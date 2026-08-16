"""Turns processed packet records into a persistent device/service inventory.

Devices are keyed primarily by IP address. This is accurate for hosts on
the same flat L2 segment as the capture point (the typical OT/ICS SPAN-port
deployment TridentyOT targets); for routed traffic the captured MAC only
identifies the last-hop router, not the true origin host, which is an
inherent limitation of any purely passive single-point capture.
"""

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.capture.packet_processor import PacketRecord
from app.fingerprint.device_classifier import NETWORK_DEVICE, ROUTER_NAT, classify_device_type
from app.fingerprint.dhcp_fingerprint import fingerprint_dhcp_options
from app.fingerprint.identity_detect import IdentityHint
from app.fingerprint.ip_scope import is_lan_ip, is_real_unicast_ip
from app.fingerprint.os_fingerprint import (
    OsGuess,
    TcpSignature,
    fingerprint_tcp_syn,
    parse_tcp_options,
)
from app.fingerprint.protocol_detect import OT, PROFINET_OTHER, ProtocolInfo, classify
from app.fingerprint.vendor_lookup import lookup_vendor
from app.i18n import bilingual, encode_i18n
from app.models import (
    CANDIDATE_PENDING,
    ArpObservation,
    CaptureSession,
    Device,
    DeviceProtocol,
    Flow,
    FlowLinkCandidate,
    NetworkLink,
    VulnerabilityFinding,
    utcnow,
)

_PRINTABLE_BANNER_MIN_RATIO = 0.85


def _looks_like_text_banner(payload: bytes) -> str | None:
    if not payload:
        return None
    try:
        text = payload.decode("utf-8", errors="ignore").strip()
    except Exception:
        return None
    if not text:
        return None
    # The printable ratio must be judged on the candidate we actually
    # return (the first line), not on the whole decoded payload: a binary
    # protocol header followed by a line break and a long, genuinely
    # printable tail can make the *whole* text mostly printable while its
    # first line -- what gets stored -- is still mostly control bytes.
    first_line = text.splitlines()[0][:256]
    if not first_line:
        return None
    # Postgres rejects NUL bytes in text columns outright, independent of
    # column width -- reject explicitly rather than relying on the
    # printable-ratio check alone to always catch it.
    if "\x00" in first_line:
        return None
    printable = sum(1 for c in first_line if c.isprintable() or c in "\r\n\t")
    if printable / max(len(first_line), 1) < _PRINTABLE_BANNER_MIN_RATIO:
        return None
    return first_line


class IngestCache:
    """Per-run in-memory lookup cache for get_or_create_device/upsert_protocol/
    upsert_flow, keyed by the same tuple each is uniquely constrained on.

    A real capture re-touches the same handful of devices/protocols/flows
    on nearly every packet (a PLC polling loop, a client's repeated
    requests to the same server, ...) -- without this, ingest_packet_record
    re-queries the database for that same row on every single packet. That
    round trip is cheap against SQLite's in-process access, but at
    Postgres's per-round-trip network/protocol latency it dominates: a 97MB
    pcap upload that took 2-4 minutes on SQLite took 40+ minutes after the
    move to Postgres, with nothing else about the workload having changed.

    Scoped to one caller-owned run (the whole file for a pcap upload, one
    batch for live capture -- see pcap_loader.py/live_capture.py) rather
    than being global: the cached ORM objects are only valid for as long as
    the Session that loaded them stays open, and a cache entry for one
    organization must never leak into another's lookup.
    """

    def __init__(self) -> None:
        self.devices_by_ip: dict[tuple[int, str], Device] = {}
        self.devices_by_mac: dict[tuple[int, str], Device] = {}
        self.protocols: dict[tuple[int, str, int | None, str], DeviceProtocol] = {}
        self.flows: dict[tuple[int, int, str, int | None], Flow] = {}
        self.arp_observations: dict[tuple[int, int | None, str], ArpObservation] = {}


def _is_real_unicast_mac(mac: str | None) -> bool:
    """Broadcast/multicast addresses (ff:ff:ff:ff:ff:ff, 01:00:5e:.., etc.)
    identify a link-layer destination class, never a specific host's own
    hardware address -- e.g. an ARP/DHCP broadcast frame's destination, or
    a multicast group like mDNS's 224.0.0.251. Recording one of those as a
    device's mac would both be meaningless and (since a device's mac is
    only ever set once) permanently block learning its real address."""
    if not mac or mac.lower() == "00:00:00:00:00:00":
        return False
    try:
        first_octet = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return first_octet & 0x01 == 0  # multicast bit unset => unicast


def get_or_create_device(
    session: Session,
    ip: str | None,
    mac: str | None,
    organization_id: int,
    capture_session_id: int | None = None,
    cache: IngestCache | None = None,
    vlan: int | None = None,
    ttl: int | None = None,
) -> Device | None:
    if mac is not None and not _is_real_unicast_mac(mac):
        mac = None
    if ip is not None and not is_real_unicast_ip(ip):
        ip = None
    if not ip and not mac:
        return None

    device = None
    if ip:
        if cache is not None:
            device = cache.devices_by_ip.get((organization_id, ip))
        if device is None:
            # ip alone isn't actually unique (the DB constraint is on the
            # (organization_id, mac, ip) triple, and two NULL macs don't
            # collide under it either) -- a large/long capture can genuinely
            # produce two rows for the same ip (e.g. an address briefly
            # reused/conflicting on the LAN, or two uploads racing each
            # other). Picking the oldest deterministically instead of
            # one_or_none() means that anomaly gets tolerated and converged
            # on rather than crashing every ingest that touches this ip
            # afterwards.
            device = (
                session.query(Device)
                .filter(Device.organization_id == organization_id, Device.ip == ip)
                .order_by(Device.id.asc())
                .first()
            )
    if device is None and mac:
        if cache is not None:
            device = cache.devices_by_mac.get((organization_id, mac))
        if device is None:
            device = (
                session.query(Device)
                .filter(Device.organization_id == organization_id, Device.mac == mac, Device.ip.is_(None))
                .order_by(Device.id.asc())
                .first()
            )

    now = utcnow()
    if device is None:
        device = Device(
            organization_id=organization_id,
            ip=ip,
            mac=mac,
            vendor=lookup_vendor(mac),
            vlan=vlan,
            last_ttl=ttl,
            capture_session_id=capture_session_id,
            first_seen=now,
            last_seen=now,
        )
        session.add(device)
        session.flush()
    else:
        if mac and not device.mac:
            device.mac = mac
        if ip and not device.ip:
            device.ip = ip
        if device.vendor is None:
            device.vendor = lookup_vendor(device.mac)
        # Last-seen-wins, unlike mac/ip above: a device rarely changes VLAN
        # or its stack's initial TTL, but when it does the newest
        # observation is more likely correct than the first. Only ever
        # overwritten when this call actually carries a value -- None means
        # "this packet didn't say", not "clear it".
        if vlan is not None:
            device.vlan = vlan
        if ttl is not None:
            device.last_ttl = ttl
        device.last_seen = now
        # Re-attributes to whichever capture last confirmed this device,
        # not just whichever one first discovered it -- devices are matched
        # by (organization_id, mac/ip) alone, with no notion of Zona, so the
        # *same* device re-observed by a different Sensor (a second capture
        # on a different Zona, e.g. the same pcap re-uploaded elsewhere, or
        # a device genuinely reachable from two SPAN ports) used to stay
        # permanently pinned to its very first Zona -- invisible in every
        # Inventario/Flujos/Topología view scoped to any other Zona/Sitio
        # (see _filter_by_zone_or_site), even though Reportes' org-wide,
        # unfiltered view showed it fine. Keeping the most recent capture
        # is the only one-FK approximation of "where does this show up
        # right now" the schema supports; a device truly live in two Zonas
        # at once will only ever show in whichever was captured last.
        if capture_session_id is not None:
            device.capture_session_id = capture_session_id

    if cache is not None:
        # Mirrors the two lookup queries above exactly: a device with an ip
        # is only ever found (or matched) via the ip branch, regardless of
        # whether it also has a mac, so any stale mac-only cache entry for
        # it (from before it had an ip) must be dropped -- otherwise a later
        # mac-only lookup would resolve to a device the real "mac == mac AND
        # ip IS NULL" query could no longer match.
        if device.ip:
            cache.devices_by_ip[(organization_id, device.ip)] = device
            if device.mac:
                cache.devices_by_mac.pop((organization_id, device.mac), None)
        elif device.mac:
            cache.devices_by_mac[(organization_id, device.mac)] = device

    return device


def upsert_arp_observation(
    session: Session,
    ip: str,
    mac: str,
    organization_id: int,
    sensor_id: int | None = None,
    cache: IngestCache | None = None,
) -> ArpObservation:
    """Live IP<->MAC binding straight off the wire -- see ArpObservation's
    docstring for why this is a separate table from Device rather than
    just reading device.ip/device.mac (a switch/router can sit between the
    sensor and a device, so a Device's own ip/mac don't necessarily reflect
    what's on this particular segment's ARP cache right now). Upserted by
    (organization_id, sensor_id, ip) -- see the model docstring for why
    sensor, not just organization: both mac and last_seen are overwritten
    on every call, since an IP that now resolves to a different mac (NIC
    swap, DHCP lease turnover) should reflect what the segment says *now*,
    not whichever binding this sensor happened to see first."""
    key = (organization_id, sensor_id, ip)
    existing = cache.arp_observations.get(key) if cache is not None else None
    if existing is None:
        existing = (
            session.query(ArpObservation)
            .filter(
                ArpObservation.organization_id == organization_id,
                ArpObservation.sensor_id == sensor_id,
                ArpObservation.ip == ip,
            )
            .one_or_none()
        )
    now = utcnow()
    if existing is None:
        existing = ArpObservation(
            organization_id=organization_id, sensor_id=sensor_id, ip=ip, mac=mac, last_seen=now
        )
        session.add(existing)
        # Autoflush is off (see db.py's SessionLocal) -- without an explicit
        # flush here, a second ARP packet for this same (org, sensor, ip)
        # later in the same uncommitted batch would find nothing via the
        # query above (this row isn't visible yet) and attempt a second
        # INSERT, hitting the unique constraint at commit time. Mirrors
        # get_or_create_device's own self-flush on creation, just above.
        session.flush()
    else:
        existing.mac = mac
        existing.last_seen = now

    if cache is not None:
        cache.arp_observations[key] = existing

    return existing


def apply_os_guess(device: Device, guess: OsGuess) -> None:
    if guess.confidence <= device.os_confidence:
        return
    device.os_guess = guess.label
    device.os_confidence = guess.confidence
    device.os_signature = guess.signature_name


def apply_device_type_guess(session: Session, device: Device) -> None:
    """Recomputes device.device_type from whatever evidence is on hand
    right now (protocols served, OS fingerprint, vendor, hostname) --
    called whenever one of those inputs just changed. Same
    never-downgrade rule as apply_os_guess: a new guess only replaces the
    stored one if it's *more* confident, so one signal disappearing later
    (e.g. a hostname getting cleared) doesn't erase a better guess an
    earlier signal already established.

    Queries DeviceProtocol directly rather than reading device.protocols:
    that relationship, once lazily loaded, stays cached on the object for
    the rest of the session even after a later flush adds a new row (e.g.
    upsert_protocol adding this device's first server protocol earlier in
    the very same packet) -- a plain query always reflects what's actually
    been flushed, a cached relationship collection does not.
    """
    server_protocols = (
        session.query(DeviceProtocol).filter(DeviceProtocol.device_id == device.id, DeviceProtocol.role == "server").all()
    )
    guess = classify_device_type(
        vendor=device.display_vendor,
        hostname=device.display_name,
        model=device.model,
        os_signature=device.os_signature,
        has_ot_server_protocol=any(p.category == OT for p in server_protocols),
        server_protocol_count=len({p.protocol for p in server_protocols}),
    )
    if guess.confidence <= device.device_type_confidence:
        return
    device.device_type = guess.device_type
    device.device_type_confidence = guess.confidence
    device.device_type_evidence = encode_i18n(*guess.evidence) if guess.evidence else None
    if guess.device_type_secondary:
        device.device_type_secondary = guess.device_type_secondary


def apply_identity_hints(session: Session, device: Device, hints: list[IdentityHint]) -> None:
    """Applies protocol-level identity hints (EtherNet/IP CIP, Modbus
    device identification, ...) to *this packet's sender* -- these are
    facts a device states about itself, not inferred evidence:

    - vendor/model/firmware_version only fill in when still unknown, same
      as the MAC-OUI lookup in get_or_create_device -- never overwrites a
      real OUI vendor (or an earlier hint's model/firmware) with a
      lower-priority guess (a DHCP vendor class string, an HTTP Server
      banner, ...).
    - device_type is a direct, maximal-confidence override, same
      "bypass the generic scorer" pattern as apply_gateway_detection --
      only the handful of protocols/values unambiguous enough to earn that
      (see identity_detect.py) ever set it.
    - a hint with no vendor/hostname/device_type at all (e.g. BACnet's raw
      vendor-id number, which this app can't translate to a name) only
      fills in device_type_evidence when nothing else has spoken yet, never
      overwriting a real classification's evidence text.
    """
    for hint in hints:
        if hint.vendor and not device.vendor:
            device.vendor = hint.vendor
        if hint.model and not device.model:
            device.model = hint.model
        if hint.firmware_version and not device.firmware_version:
            device.firmware_version = hint.firmware_version
        if hint.device_type:
            if device.device_type != hint.device_type or device.device_type_confidence < 1.0:
                device.device_type = hint.device_type
                device.device_type_confidence = 1.0
                device.device_type_evidence = hint.evidence or None
            if hint.device_type_secondary:
                device.device_type_secondary = hint.device_type_secondary
        elif hint.evidence and not device.device_type_evidence:
            device.device_type_evidence = hint.evidence


def apply_hostname_hints(session: Session, hints: list[tuple[str, str]], organization_id: int) -> None:
    """Enriches already-known devices with an auto-detected hostname.

    Only updates existing inventory entries -- never creates a device from
    a DNS/mDNS/DHCP hint alone, so e.g. a client resolving some unrelated
    public hostname doesn't pollute the inventory with a phantom "device"
    for that public IP.

    A hostname string already claimed by a *different* device is never a
    real per-host identity -- it's a shared/group name (a NetBIOS
    workgroup/domain announced with the group bit unset, e.g.) that some
    upstream extractor let through. Once a second IP tries to claim it,
    that's proof it's shared: both are cleared rather than showing a name
    that's misleading either way.
    """
    for ip, hostname in hints:
        if not hostname:
            continue
        # ip alone isn't a unique key (see get_or_create_device) -- pick the
        # oldest of any duplicates deterministically rather than crashing.
        device = (
            session.query(Device)
            .filter(Device.organization_id == organization_id, Device.ip == ip)
            .order_by(Device.id.asc())
            .first()
        )
        if device is None or hostname == device.hostname:
            continue

        others = (
            session.query(Device)
            .filter(Device.organization_id == organization_id, Device.hostname == hostname, Device.ip != ip)
            .all()
        )
        if others:
            for other in others:
                other.hostname = None
                apply_device_type_guess(session, other)
            continue

        device.hostname = hostname
        apply_device_type_guess(session, device)


# How many distinct public IPs sharing one MAC it takes before that MAC is
# treated as a router/NAT gateway rather than coincidence -- one shared
# public IP alone doesn't prove a pattern.
_GATEWAY_MIN_PUBLIC_IPS = 2

# First-Hop Redundancy Protocol virtual MAC prefixes: a group of routers
# sharing one gateway identity announces itself with a MAC out of one of
# these reserved ranges, never a real host's own burned-in address --
# recognizing one needs no accumulated evidence at all, unlike the
# multi-public-IP pattern below. HSRPv2 uses a different virtual-MAC scheme
# than HSRPv1's and isn't covered here (no verified real-world sample to
# calibrate against yet -- same "seed now, extend later" convention as the
# Cisco/Scalance switch-CLI parsers).
_HSRP_V1_MAC_PREFIX = "00:00:0c:07:ac:"
_VRRP_V4_MAC_PREFIX = "00:00:5e:00:01:"
_VRRP_V6_MAC_PREFIX = "00:00:5e:00:02:"


def _fhrp_protocol_label(mac: str) -> str | None:
    lowered = mac.lower()
    if lowered.startswith(_HSRP_V1_MAC_PREFIX):
        return "HSRP"
    if lowered.startswith(_VRRP_V4_MAC_PREFIX) or lowered.startswith(_VRRP_V6_MAC_PREFIX):
        return "VRRP"
    return None


def apply_gateway_detection(session: Session, organization_id: int) -> None:
    """Detects a router/NAT gateway from a pattern purely-passive capture
    produces: when the gateway forwards a reply from some public-internet
    host onto the LAN, it is transmitting that frame -- so by this app's
    own "MAC only ever learned from the sender" rule (see
    get_or_create_device), that MAC gets attached to the device row for
    *that public IP*. Every distinct public IP the gateway ever forwarded
    ends up as its own inventory row, all sharing the gateway's one real
    MAC, even though none of those IPs are actual local assets (see
    Device.is_external and the module docstring's routed-traffic caveat).
    The exact same thing happens for a *private* IP on another VLAN/subnet
    reached through this same gateway (inter-VLAN routing) -- its rows
    share the gateway's MAC too, just as falsely.

    Two or more distinct IPs sharing a MAC is that exact pattern -- a MAC
    belongs to exactly one real NIC, so at most one member of a shared-MAC
    group can genuinely own it. Picking *which* one, when possible:

    - An ArpObservation for one of the group's private IPs, on its own
      sensor, resolving to this exact MAC is direct self-identification --
      an ARP reply is the device itself stating "I am this MAC", not just
      "a frame from this MAC happened to carry this source IP" the way a
      forwarded TCP reply is. When this exists, that IP is confirmed as the
      gateway's own real (usually LAN-management) address, full stop.
    - Failing that, 2+ distinct *public* IPs sharing the MAC is still a
      reliable (if less specific) tell that whichever device owns it is
      routing/NATing traffic -- the oldest of those public-IP rows is
      picked to represent it instead, same heuristic as before ARP
      confirmation existed. A private-IP-only group with no ArpObservation
      match gets no primary at all: guessing wrong would mislabel a real,
      unrelated asset on another subnet as the gateway itself, which is
      worse than the gateway's own row just not being identified.

    Either way, once a primary is picked it's classified as a network
    device (subcategory "router_nat"); routes_inventory.list_devices
    collapses the rest of the *public*-IP duplicates into it when
    hide_external is requested, without deleting them (Flows/
    Vulnerabilidades still reference them normally). Every OTHER member of
    the group -- public or private, whether or not a primary was found --
    gets Device.is_mac_shared set: its mac field is left in place (clearing
    it would just have get_or_create_device silently reattach it from the
    very next packet on that same IP) but is now known to be borrowed, not
    its own NIC.

    Runs as a whole-table pass after ingesting a batch/file rather than
    per-packet: the pattern is only visible once several distinct IPs for
    the same MAC actually exist, which no single packet can tell on its own.

    Separately, ANY device whose MAC falls in a known First-Hop Redundancy
    Protocol (HSRP/VRRP) virtual range is recognized immediately, from a
    single row -- no need to wait for several public IPs to accumulate,
    since that MAC pattern is by construction never a real host's own NIC.
    Only asserted as a hard device_type override when the row's own IP is
    public; for a private IP the same inter-VLAN-routing ambiguity as
    above applies (this row could genuinely be a different real host on
    another subnet whose return traffic this same redundancy pair forwarded,
    not the gateway's own address), so only device_type_evidence fills in
    there -- and only if nothing else has spoken yet -- never a device_type
    override, mirroring apply_identity_hints' BACnet handling.
    """
    devices = (
        session.query(Device)
        .filter(Device.organization_id == organization_id, Device.mac.is_not(None))
        .all()
    )
    by_mac: dict[str, list[Device]] = {}
    for d in devices:
        by_mac.setdefault(d.mac, []).append(d)

    # Same (capture_session -> sensor) resolution apply_segment_classification
    # uses to check "is there an ArpObservation for this exact (sensor, ip)"
    # -- built once here rather than per-group/per-member.
    capture_session_ids = {d.capture_session_id for d in devices if d.capture_session_id is not None}
    sensor_by_capture_session: dict[int, int | None] = {}
    if capture_session_ids:
        sensor_by_capture_session = dict(
            session.query(CaptureSession.id, CaptureSession.sensor_id)
            .filter(CaptureSession.id.in_(capture_session_ids))
            .all()
        )
    arp_mac_by_sensor_ip: dict[tuple[int | None, str], str] = {
        (sensor_id, ip): observed_mac
        for sensor_id, ip, observed_mac in session.query(
            ArpObservation.sensor_id, ArpObservation.ip, ArpObservation.mac
        ).filter(ArpObservation.organization_id == organization_id)
    }

    for mac, group in by_mac.items():
        fhrp_protocol = _fhrp_protocol_label(mac)
        if fhrp_protocol is not None:
            for member in group:
                if not is_lan_ip(member.ip):
                    if member.device_type != NETWORK_DEVICE or member.device_type_confidence < 1.0:
                        member.device_type = NETWORK_DEVICE
                        member.device_type_confidence = 1.0
                        member.device_type_evidence = encode_i18n(
                            bilingual(
                                es=f"La MAC {mac} es una identidad virtual de {fhrp_protocol} compartida por "
                                "un grupo de routers, nunca la de un host real",
                                en=f"MAC {mac} is a {fhrp_protocol} virtual identity shared by a router "
                                "redundancy group, never a real host's own NIC",
                            )
                        )
                    if not member.device_type_secondary:
                        member.device_type_secondary = ROUTER_NAT
                elif not member.device_type_evidence:
                    member.device_type_evidence = encode_i18n(
                        bilingual(
                            es=f"La MAC {mac} es una identidad virtual de {fhrp_protocol} -- podría ser la "
                            "propia IP del gateway o un host en otra subred enrutado a través de él",
                            en=f"MAC {mac} is a {fhrp_protocol} virtual identity -- could be the gateway's "
                            "own IP, or a different host on another subnet routed through it",
                        )
                    )
            # Already handled above on its own, unconditional terms (an FHRP
            # virtual MAC is never a real host's NIC, full stop) -- skip the
            # generic shared-MAC correction below so it doesn't second-guess
            # that with a weaker, vendor-based re-derivation.
            continue

        if len(group) < 2:
            continue  # a MAC used by only one device row is never this pattern

        # First choice: a private member directly self-identified via ARP
        # (see this function's docstring) -- the oldest such match if
        # somehow more than one private IP in the group has one (shouldn't
        # normally happen; a MAC really does belong to one NIC). Falling
        # back to the 2+-public-IP heuristic only when no ARP confirmation
        # exists at all.
        public_members = [d for d in group if not is_lan_ip(d.ip)]
        arp_confirmed = sorted(
            (
                d
                for d in group
                if is_lan_ip(d.ip)
                and arp_mac_by_sensor_ip.get((sensor_by_capture_session.get(d.capture_session_id), d.ip)) == mac
            ),
            key=lambda d: d.id,
        )
        primary = arp_confirmed[0] if arp_confirmed else (
            min(public_members, key=lambda d: d.id) if len(public_members) >= _GATEWAY_MIN_PUBLIC_IPS else None
        )

        if primary is not None:
            if primary.device_type != NETWORK_DEVICE or primary.device_type_confidence < 1.0:
                primary.device_type = NETWORK_DEVICE
                primary.device_type_confidence = 1.0
                if primary in arp_confirmed:
                    primary.device_type_evidence = encode_i18n(
                        bilingual(
                            es=f"Confirmado por ARP: esta IP responde por la MAC {mac}, compartida con "
                            f"{len(group) - 1} otra(s) IP -- es la dirección real del equipo que enruta/NATea "
                            "ese tráfico, no solo un destino alcanzado a través de él",
                            en=f"ARP-confirmed: this IP itself answers for MAC {mac}, shared with "
                            f"{len(group) - 1} other IP(s) -- this is the real address of the device "
                            "routing/NAT-ing that traffic, not just a destination reached through it",
                        )
                    )
                else:
                    primary.device_type_evidence = encode_i18n(
                        bilingual(
                            es=f"Una misma MAC ({mac}) aparece en {len(public_members)} IPs públicas distintas -- "
                            "consistente con un equipo que enruta/NATea tráfico hacia internet",
                            en=f"The same MAC ({mac}) appears on {len(public_members)} distinct public IPs -- "
                            "consistent with a device routing/NAT-ing traffic to the internet",
                        )
                    )
            if not primary.device_type_secondary:
                primary.device_type_secondary = ROUTER_NAT
            primary.is_mac_shared = False

        # Every other member of the group -- regardless of device_type --
        # only has this MAC because it's whatever forwarded/routed its
        # traffic, never its own NIC (a MAC belongs to exactly one real
        # device, and we just established at most `primary` is it).
        for member in group:
            if member is not primary:
                member.is_mac_shared = True

        # Most non-primary members also read as NETWORK_DEVICE, but only
        # because they inherited the *gateway's* NIC vendor (e.g.
        # "Fortinet, Inc.") along with its MAC -- vendor_category has no way
        # to know that vendor describes whoever forwarded the frame, not
        # this row's own (nonexistent, for this purpose) NIC. Re-derive
        # without that misleading vendor signal; any other independent
        # evidence this row has (hostname, model, protocols served) is
        # unaffected and still counted normally.
        for member in group:
            if member is primary or member.device_type != NETWORK_DEVICE:
                continue
            server_protocols = (
                session.query(DeviceProtocol)
                .filter(DeviceProtocol.device_id == member.id, DeviceProtocol.role == "server")
                .all()
            )
            guess = classify_device_type(
                vendor=None,
                hostname=member.display_name,
                model=member.model,
                os_signature=member.os_signature,
                has_ot_server_protocol=any(p.category == OT for p in server_protocols),
                server_protocol_count=len({p.protocol for p in server_protocols}),
            )
            member.device_type = guess.device_type
            member.device_type_confidence = guess.confidence
            member.device_type_evidence = encode_i18n(*guess.evidence) if guess.evidence else None
            member.device_type_secondary = guess.device_type_secondary


# Device.segment_relation values -- see apply_segment_classification.
SEGMENT_SAME = "same_segment"
SEGMENT_ROUTED_LOCAL = "routed_local"
SEGMENT_INTERNET = "internet"


def apply_segment_classification(session: Session, organization_id: int) -> None:
    """Fase 2 of the topology-accuracy roadmap: for every device with an IP,
    classifies its relation to whichever sensor most recently confirmed it
    (Device.capture_session_id -> CaptureSession.sensor_id, same
    attribution already used for Zona/Sitio scoping elsewhere) into one of
    three states:

    - SEGMENT_INTERNET: a public IP (see is_lan_ip) -- never a local asset,
      by definition never directly cabled to anything this deployment
      monitors.
    - SEGMENT_SAME: a private/LAN IP with a live ArpObservation for that
      exact (sensor, ip) pair -- ARP never crosses a router, so this is
      proof the device shares this sensor's own L2 broadcast domain. This
      is the ONLY state a later phase should ever treat as "these two
      devices might be a real cable apart" (still requiring further
      corroboration -- CDP/LLDP, a MAC table -- before promoting anything
      to an actual NetworkLink; see the module docstring's routed-traffic
      caveat and the switch-topology docs).
    - SEGMENT_ROUTED_LOCAL: a private/LAN IP with no such ArpObservation --
      reached through a router (a different Zona/Sensor, another VLAN, a
      different Sitio entirely), still a legitimate internal asset, just
      never a candidate for a direct link with anything seen only on this
      sensor's own segment.

    A device with no IP at all (MAC-only, e.g. a CDP/LLDP-only switch) is
    left with segment_relation unset -- the question doesn't apply to
    something with no IP layer to reason about.

    Deliberately NOT confidence-gated like os_guess/device_type: this is a
    deterministic snapshot of currently-known data (does a matching
    ArpObservation exist right now), recomputed fresh on every pass rather
    than accumulated evidence that only ever strengthens. Runs as a
    whole-table pass after ingesting a batch/file, same as
    apply_gateway_detection and for the same reason: ArpObservation rows
    accumulate independently of any one device's own packets, so a device
    ingested early in a capture can only be reclassified once a later
    packet (from a different flow entirely) adds the ARP evidence that
    confirms it.
    """
    devices = (
        session.query(Device)
        .filter(Device.organization_id == organization_id, Device.ip.is_not(None))
        .all()
    )
    if not devices:
        return

    capture_session_ids = {d.capture_session_id for d in devices if d.capture_session_id is not None}
    sensor_by_capture_session: dict[int, int | None] = {}
    if capture_session_ids:
        sensor_by_capture_session = dict(
            session.query(CaptureSession.id, CaptureSession.sensor_id)
            .filter(CaptureSession.id.in_(capture_session_ids))
            .all()
        )

    arp_keys = set(
        session.query(ArpObservation.sensor_id, ArpObservation.ip)
        .filter(ArpObservation.organization_id == organization_id)
        .all()
    )

    for device in devices:
        if not is_lan_ip(device.ip):
            device.segment_relation = SEGMENT_INTERNET
            continue
        sensor_id = sensor_by_capture_session.get(device.capture_session_id)
        if (sensor_id, device.ip) in arp_keys:
            device.segment_relation = SEGMENT_SAME
        else:
            device.segment_relation = SEGMENT_ROUTED_LOCAL


# FlowLinkCandidate.confidence -- deliberately capped well below 1.0 (see
# the model's own docstring): a Flow between two ARP-confirmed-same-segment
# devices is real, but weak, evidence of a direct cable, never proof.
_FLOW_CANDIDATE_BASE_CONFIDENCE = 0.4
# Sharing a VLAN reinforces "same logical L2 domain" but still doesn't
# prove adjacency -- an unmanaged switch on that same VLAN is still
# invisible to this signal.
_FLOW_CANDIDATE_VLAN_MATCH_BONUS = 0.2


def apply_flow_link_candidates(session: Session, organization_id: int) -> None:
    """Fase 3 of the topology-accuracy roadmap: for every Flow between two
    devices that were BOTH ARP-confirmed on the exact same Sensor (see
    Device.segment_relation/apply_segment_classification), upserts a
    FlowLinkCandidate scored by how much (still circumstantial) evidence
    backs it -- never a NetworkLink, never auto-promoted. A pair already
    covered by a real NetworkLink (whatever its source) is skipped
    entirely: that's already resolved, by a human or a switch, and always
    outranks this weaker signal.

    Sharing a sensor (not just each independently being SEGMENT_SAME) is
    the actual precondition: a device confirmed same-segment on Sensor A
    and one confirmed same-segment on unrelated Sensor B could easily be
    two completely different physical locations that just happen to both
    have *a* directly-attached ARP-confirmed neighbor -- nothing here says
    those two neighbors are anywhere near each other.

    A row already decided by a human (status confirmed/dismissed) is never
    touched again by this pass -- confirmed candidates are moot anyway
    (their pair now has a real NetworkLink, caught by the skip above);
    dismissed ones stay dismissed until a human says otherwise.
    """
    same_segment_devices = (
        session.query(Device)
        .filter(Device.organization_id == organization_id, Device.segment_relation == SEGMENT_SAME)
        .all()
    )
    if len(same_segment_devices) < 2:
        return

    device_by_id = {d.id: d for d in same_segment_devices}
    device_ids = list(device_by_id)

    capture_session_ids = {d.capture_session_id for d in same_segment_devices if d.capture_session_id is not None}
    sensor_by_capture_session: dict[int, int | None] = {}
    if capture_session_ids:
        sensor_by_capture_session = dict(
            session.query(CaptureSession.id, CaptureSession.sensor_id)
            .filter(CaptureSession.id.in_(capture_session_ids))
            .all()
        )
    sensor_by_device = {d.id: sensor_by_capture_session.get(d.capture_session_id) for d in same_segment_devices}

    existing_link_pairs = set(
        session.query(NetworkLink.device_a_id, NetworkLink.device_b_id)
        .filter(NetworkLink.organization_id == organization_id)
        .all()
    )

    flows = (
        session.query(Flow)
        .filter(Flow.device_a_id.in_(device_ids), Flow.device_b_id.in_(device_ids))
        .all()
    )

    now = utcnow()
    seen_pairs: set[tuple[int, int]] = set()
    for flow in flows:
        pair = (flow.device_a_id, flow.device_b_id)  # already normalized a < b, same as Flow itself
        if pair in seen_pairs or pair in existing_link_pairs:
            continue
        seen_pairs.add(pair)

        sensor_a = sensor_by_device.get(pair[0])
        sensor_b = sensor_by_device.get(pair[1])
        if sensor_a != sensor_b:
            continue

        device_a, device_b = device_by_id[pair[0]], device_by_id[pair[1]]
        confidence = _FLOW_CANDIDATE_BASE_CONFIDENCE
        vlan_match = device_a.vlan is not None and device_a.vlan == device_b.vlan
        if vlan_match:
            confidence += _FLOW_CANDIDATE_VLAN_MATCH_BONUS

        existing = (
            session.query(FlowLinkCandidate)
            .filter(FlowLinkCandidate.device_a_id == pair[0], FlowLinkCandidate.device_b_id == pair[1])
            .one_or_none()
        )
        if existing is not None and existing.status != CANDIDATE_PENDING:
            continue

        evidence = encode_i18n(
            bilingual(
                es="Ambos equipos fueron confirmados por ARP en el mismo Sensor"
                + (f" y comparten la VLAN {device_a.vlan}" if vlan_match else "")
                + " -- no es prueba de un cable directo, solo de que comparten el mismo segmento L2; "
                "puede haber un switch no administrado de por medio",
                en="Both devices were ARP-confirmed on the same Sensor"
                + (f" and share VLAN {device_a.vlan}" if vlan_match else "")
                + " -- not proof of a direct cable, only that they share the same L2 segment; "
                "an unmanaged switch could still sit between them",
            )
        )

        if existing is None:
            session.add(
                FlowLinkCandidate(
                    organization_id=organization_id,
                    device_a_id=pair[0],
                    device_b_id=pair[1],
                    sensor_id=sensor_a,
                    confidence=confidence,
                    evidence=evidence,
                    created_at=now,
                    updated_at=now,
                )
            )
        else:
            existing.sensor_id = sensor_a
            existing.confidence = confidence
            existing.evidence = evidence
            existing.updated_at = now


def upsert_protocol(
    session: Session,
    device: Device,
    proto_info: ProtocolInfo,
    port: int | None,
    transport: str,
    role: str,
    banner: str | None = None,
    capture_session_id: int | None = None,
    cache: IngestCache | None = None,
) -> DeviceProtocol:
    key = (device.id, proto_info.protocol, port, role)
    existing = cache.protocols.get(key) if cache is not None else None
    if existing is None:
        existing = (
            session.query(DeviceProtocol)
            .filter(
                DeviceProtocol.device_id == device.id,
                DeviceProtocol.protocol == proto_info.protocol,
                DeviceProtocol.port == port,
                DeviceProtocol.role == role,
            )
            .one_or_none()
        )
    now = utcnow()
    if existing is None:
        existing = DeviceProtocol(
            device_id=device.id,
            protocol=proto_info.protocol,
            port=port,
            transport=transport,
            role=role,
            category=proto_info.category,
            banner=banner,
            packet_count=1,
            capture_session_id=capture_session_id,
            first_seen=now,
            last_seen=now,
        )
        session.add(existing)
    else:
        existing.packet_count += 1
        existing.last_seen = now
        if banner and not existing.banner:
            existing.banner = banner
        # See get_or_create_device's matching comment: re-attribute to the
        # capture that most recently confirmed this, not just whichever one
        # first saw it, so it doesn't stay invisible in every other Zona/Sitio.
        if capture_session_id is not None:
            existing.capture_session_id = capture_session_id

    if proto_info.category == "OT":
        device.is_ot_suspected = True

    if cache is not None:
        cache.protocols[key] = existing

    return existing


def upsert_flow(
    session: Session,
    device_x: Device,
    device_y: Device,
    server_device: Device,
    transport: str,
    port: int | None,
    proto_info: ProtocolInfo,
    capture_session_id: int | None = None,
    cache: IngestCache | None = None,
) -> Flow:
    """Aggregates both directions of a TCP/UDP conversation between two
    devices into a single row, normalized by device id so the reverse
    direction doesn't create a duplicate."""
    device_a, device_b = sorted((device_x, device_y), key=lambda d: d.id)

    key = (device_a.id, device_b.id, transport, port)
    existing = cache.flows.get(key) if cache is not None else None
    if existing is None:
        existing = (
            session.query(Flow)
            .filter(
                Flow.device_a_id == device_a.id,
                Flow.device_b_id == device_b.id,
                Flow.transport == transport,
                Flow.port == port,
            )
            .one_or_none()
        )
    now = utcnow()
    if existing is None:
        existing = Flow(
            device_a_id=device_a.id,
            device_b_id=device_b.id,
            server_device_id=server_device.id,
            transport=transport,
            port=port,
            protocol=proto_info.protocol,
            category=proto_info.category,
            packet_count=1,
            capture_session_id=capture_session_id,
            first_seen=now,
            last_seen=now,
        )
        session.add(existing)
    else:
        existing.packet_count += 1
        existing.last_seen = now
        # See get_or_create_device's matching comment: re-attribute to the
        # capture that most recently confirmed this, not just whichever one
        # first saw it, so it doesn't stay invisible in every other Zona/Sitio.
        if capture_session_id is not None:
            existing.capture_session_id = capture_session_id

    if cache is not None:
        cache.flows[key] = existing

    return existing


def _pick_server_side(record: PacketRecord) -> str:
    """Returns 'src' or 'dst' -- which endpoint is acting as the service."""
    if record.transport == "tcp":
        if record.is_syn:
            return "dst"
        if record.is_syn_ack:
            return "src"

    src_known = record.src_port is not None and classify(record.src_port).protocol != "unknown"
    dst_known = record.dst_port is not None and classify(record.dst_port).protocol != "unknown"
    if src_known and not dst_known:
        return "src"
    if dst_known and not src_known:
        return "dst"

    # fall back to "lower port number is the service" heuristic
    if record.src_port is not None and record.dst_port is not None:
        return "src" if record.src_port < record.dst_port else "dst"
    return "dst"


_CDP_LLDP_GUESS = OsGuess(
    os_family="Network device",
    label="Network appliance (router/switch/firewall)",
    confidence=1.0,
    signature_name="cdp_lldp_announcement",
    initial_ttl_guess=255,
    hop_estimate=0,
)


def ingest_packet_record(
    session: Session,
    record: PacketRecord,
    organization_id: int,
    capture_session_id: int | None = None,
    cache: IngestCache | None = None,
    sensor_id: int | None = None,
) -> None:
    if record.transport == "arp":
        device = get_or_create_device(
            session, ip=record.src_ip, mac=record.src_mac, organization_id=organization_id,
            capture_session_id=capture_session_id, cache=cache, vlan=record.vlan,
        )
        if device is not None:
            # A device only ever seen via ARP has no protocol/OS evidence at
            # all, but its vendor OUI is still real, weak-but-real evidence
            # (e.g. a Siemens NIC is still a hint towards "plc") -- worth a
            # classification attempt rather than leaving it unclassified
            # purely because it never happened to send TCP/UDP traffic.
            apply_device_type_guess(session, device)
        if (
            record.src_ip
            and record.src_mac
            and is_real_unicast_ip(record.src_ip)
            and _is_real_unicast_mac(record.src_mac)
        ):
            upsert_arp_observation(
                session, record.src_ip, record.src_mac, organization_id, sensor_id=sensor_id, cache=cache
            )
        return

    if record.transport in ("cdp", "lldp"):
        # CDP/LLDP are self-announcements switches/routers send about
        # themselves -- no IP layer involved, so the device is keyed by MAC
        # alone (it'll be merged with an IP-keyed row later if the same MAC
        # is ever seen sending ordinary IP traffic; see get_or_create_device).
        device = get_or_create_device(
            session, ip=None, mac=record.src_mac, organization_id=organization_id,
            capture_session_id=capture_session_id, cache=cache, vlan=record.vlan,
        )
        if device is not None:
            if record.l2_hostname:
                device.hostname = record.l2_hostname
            if record.l2_device_reference:
                device.model = record.l2_device_reference
            if record.l2_firmware:
                device.firmware_version = record.l2_firmware
            # An explicit CDP/LLDP announcement is a stronger signal than the
            # passive TCP-SYN heuristic, so it always outranks it.
            apply_os_guess(device, _CDP_LLDP_GUESS)
            apply_device_type_guess(session, device)
        return

    if record.transport == "profinet":
        # PROFINET runs raw over Ethernet (no IP layer), so like CDP/LLDP
        # the device is keyed by MAC alone. Unlike CDP/LLDP, this is not a
        # "this MAC is a switch" signal -- it's OT/industrial fieldbus
        # traffic, so it's registered as a normal server protocol (category
        # OT) and left to classify_device_type's existing has_ot_server_
        # protocol rule: no os_signature contradicting it (no TCP/IP stack
        # involved) reads as PLC, exactly right for a PROFINET IO device.
        device = get_or_create_device(
            session, ip=None, mac=record.src_mac, organization_id=organization_id,
            capture_session_id=capture_session_id, cache=cache, vlan=record.vlan,
        )
        if device is not None:
            if record.l2_hostname:
                device.hostname = record.l2_hostname
            if record.l2_device_reference:
                device.model = record.l2_device_reference
            proto_info = ProtocolInfo(record.l2_protocol or PROFINET_OTHER, OT, True)
            device_protocol = upsert_protocol(
                session, device, proto_info, None, "profinet", "server",
                capture_session_id=capture_session_id, cache=cache,
            )
            # A brand-new row's add() isn't visible to apply_device_type_
            # guess's query below without a flush first (autoflush is off)
            # -- always true without a cache. With one, an already-existing
            # row never needs it (see upsert_flow's comment above for why),
            # so this only actually flushes for a device/protocol pair
            # that's genuinely new this run.
            if cache is None or device_protocol in session.new:
                session.flush()
            apply_device_type_guess(session, device)
        return

    if record.transport not in ("tcp", "udp", "icmp"):
        return

    # Only ever learn a device's MAC from a packet where it is the *sender*.
    # A frame's destination MAC is merely what the sender believes/resolved
    # via its own ARP cache -- not an authoritative statement from that
    # device about its own hardware address -- so it's never used here.
    # A destination that isn't a real host -- a multicast group (mDNS,
    # SSDP), the limited broadcast address, etc. -- never becomes a
    # dst_device (see get_or_create_device/is_real_unicast_ip). That's not a
    # reason to throw away everything this packet says about its *source*:
    # only the two-device-dependent bookkeeping below (protocol-as-server,
    # flow) actually needs a real device on both ends.
    src_device = get_or_create_device(
        session, ip=record.src_ip, mac=record.src_mac, organization_id=organization_id,
        capture_session_id=capture_session_id, cache=cache, vlan=record.vlan, ttl=record.ttl,
    )
    dst_device = get_or_create_device(
        session, ip=record.dst_ip, mac=None, organization_id=organization_id,
        capture_session_id=capture_session_id, cache=cache,
    )
    # get_or_create_device() already flushes internally the moment it adds a
    # brand-new device (its caller-visible .id has to be usable as a
    # foreign key right away), so this isn't needed for the two devices
    # themselves. But without a cache, upsert_protocol/upsert_flow below
    # find-or-create purely via a plain SELECT (autoflush is off) -- so an
    # earlier packet's still-unflushed Flow/DeviceProtocol INSERT would be
    # invisible to this packet's query, and a second attempt to insert the
    # exact same key 500 microseconds later fails the unique constraint.
    # A cache sidesteps that entirely (a repeat key is found in the dict,
    # never re-queried via SQL at all), so this flush -- and the extra
    # round trip it costs on literally every packet -- is only needed when
    # the caller isn't using one.
    if cache is None:
        session.flush()

    # Applied unconditionally on src_device, independent of dst_device --
    # unlike the protocol/flow bookkeeping below, this doesn't need a real
    # device on both ends (e.g. a BACnet I-Am broadcast to 255.255.255.255
    # never gets a dst_device at all, but its sender's identity is still
    # worth recording).
    if src_device is not None and record.identity_hints:
        apply_identity_hints(session, src_device, record.identity_hints)

    # Applied before the protocol/device-type block below: has_ot_server_
    # protocol's PLC-vs-HMI split reads os_signature, and a SYN-ACK can
    # carry both the OT protocol *and* this OS fingerprint in the very same
    # packet -- classifying first would see last packet's stale (or
    # nonexistent) os_signature instead of this one's.
    if (
        src_device is not None
        and record.transport == "tcp"
        and (record.is_syn or record.is_syn_ack)
        and record.ttl is not None
    ):
        opts = parse_tcp_options(record.tcp_options)
        tcp_sig = TcpSignature(
            ttl=record.ttl,
            window=record.window or 0,
            mss=opts["mss"],
            has_sack=opts["has_sack"],
            has_timestamp=opts["has_timestamp"],
            has_wscale=opts["has_wscale"],
            df=False,
            option_order=opts["option_order"],
        )
        guess = fingerprint_tcp_syn(tcp_sig)
        # ttl/window always describe the packet's sender, i.e. src_device
        apply_os_guess(src_device, guess)
        apply_device_type_guess(session, src_device)

    # DHCP option 55 is a client-implementation fingerprint independent of
    # the TCP/IP stack signature above (see fingerprint/dhcp_fingerprint.py)
    # -- both feed the same never-downgrade apply_os_guess merge, so
    # whichever signal is more confident (not necessarily whichever ran
    # first) is the one that sticks.
    if src_device is not None and record.dhcp_param_request_list:
        dhcp_guess = fingerprint_dhcp_options(record.dhcp_param_request_list)
        if dhcp_guess is not None:
            apply_os_guess(src_device, dhcp_guess)
            apply_device_type_guess(session, src_device)

    if src_device is not None and dst_device is not None and record.transport in ("tcp", "udp"):
        server_side = _pick_server_side(record)
        server_device = src_device if server_side == "src" else dst_device
        server_port = record.src_port if server_side == "src" else record.dst_port

        banner = _looks_like_text_banner(record.payload)
        proto_info = classify(server_port, payload=record.payload)
        server_device_protocol = upsert_protocol(
            session,
            server_device,
            proto_info,
            server_port,
            record.transport,
            "server",
            banner,
            capture_session_id=capture_session_id,
            cache=cache,
        )
        # upsert_protocol's own add() of a brand-new row isn't visible to
        # apply_device_type_guess's query without a flush first (autoflush
        # is off) -- without this, a device would need a *second* packet on
        # the same protocol before ever being classified from it
        # (benchmarked: the extra flush costs ~2% on a real capture, not
        # worth trading for a device that never gets classified because a
        # capture only ever saw one packet from it). Always true without a
        # cache; with one, an already-existing row never needs it (see
        # upsert_flow's comment above), so this only actually flushes for a
        # device/protocol pair that's genuinely new this run.
        if cache is None or server_device_protocol in session.new:
            session.flush()
        apply_device_type_guess(session, server_device)
        upsert_flow(
            session,
            src_device,
            dst_device,
            server_device,
            record.transport,
            server_port,
            proto_info,
            capture_session_id=capture_session_id,
            cache=cache,
        )

    if record.hostname_hints:
        apply_hostname_hints(session, record.hostname_hints, organization_id)


def purge_capture_session(session: Session, capture_session_id: int) -> None:
    """Removes everything a capture session contributed to the shared
    inventory when it's deleted: its own DeviceProtocol/Flow rows, and any
    Device it most recently confirmed that -- after removing those rows --
    no other session's protocols/flows still reference, so a device seen by
    more than one capture survives deleting just one of them. A removed
    device's vulnerability findings go with it.

    A device/protocol/flow is attributed to whichever session *most
    recently* re-observed it (see get_or_create_device/upsert_protocol/
    upsert_flow); deleting an older session that a later one has since
    reconfirmed leaves that evidence alone, but deleting the current
    (most recent) owner still removes it outright even if an older session
    also saw the exact same thing -- there's no many-to-many audit trail
    keeping every session that ever touched a row, only the latest one.
    This is a deliberate simplification -- full multi-session provenance
    would need that audit trail, which this app doesn't keep.
    """
    session.query(DeviceProtocol).filter(DeviceProtocol.capture_session_id == capture_session_id).delete(
        synchronize_session=False
    )
    session.query(Flow).filter(Flow.capture_session_id == capture_session_id).delete(synchronize_session=False)

    candidate_ids = [
        row[0] for row in session.query(Device.id).filter(Device.capture_session_id == capture_session_id).all()
    ]
    for device_id in candidate_ids:
        remaining_protocols = session.query(DeviceProtocol).filter(DeviceProtocol.device_id == device_id).count()
        remaining_flows = (
            session.query(Flow)
            .filter(
                or_(
                    Flow.device_a_id == device_id,
                    Flow.device_b_id == device_id,
                    Flow.server_device_id == device_id,
                )
            )
            .count()
        )
        if remaining_protocols or remaining_flows:
            # Survives, but its capture_session_id FK still points at the
            # session about to be deleted -- SQLite silently tolerates that
            # dangling reference (no FK enforcement without a pragma this
            # app doesn't set), but Postgres rejects the DELETE outright.
            # Null it out: the device is now known to span more than one
            # session, so "which session first discovered it" no longer has
            # a single correct answer anyway (see docstring).
            session.query(Device).filter(Device.id == device_id, Device.capture_session_id == capture_session_id).update(
                {"capture_session_id": None}, synchronize_session=False
            )
            continue
        session.query(VulnerabilityFinding).filter(VulnerabilityFinding.device_id == device_id).delete(
            synchronize_session=False
        )
        session.query(Device).filter(Device.id == device_id).delete(synchronize_session=False)


def wipe_all_capture_data(session: Session, organization_id: int) -> dict[str, int]:
    """Clears every capture session, device, protocol, flow, and
    vulnerability finding belonging to one organization -- for starting a
    completely blank capture. User accounts are never touched here: this
    only ever clears what capturing produced, never who's allowed to use
    the app. In a central console serving several organizations, this must
    never reach beyond the calling organization's own data.

    Deletes in FK-safe order (children before the parents they reference)
    rather than looping purge_capture_session per session -- there's no
    "does something else still reference this" case to check when
    everything for this org is going away at once. Child tables
    (DeviceProtocol/Flow/VulnerabilityFinding) have no organization_id of
    their own, so they're scoped via a subquery of this org's device ids.
    """
    device_ids = session.query(Device.id).filter(Device.organization_id == organization_id).scalar_subquery()
    counts = {
        "findings": session.query(VulnerabilityFinding)
        .filter(VulnerabilityFinding.device_id.in_(device_ids))
        .delete(synchronize_session=False),
        "protocols": session.query(DeviceProtocol)
        .filter(DeviceProtocol.device_id.in_(device_ids))
        .delete(synchronize_session=False),
        "flows": session.query(Flow)
        .filter(or_(Flow.device_a_id.in_(device_ids), Flow.device_b_id.in_(device_ids)))
        .delete(synchronize_session=False),
        "devices": session.query(Device).filter(Device.organization_id == organization_id).delete(
            synchronize_session=False
        ),
        "sessions": session.query(CaptureSession)
        .filter(CaptureSession.organization_id == organization_id)
        .delete(synchronize_session=False),
    }
    return counts
