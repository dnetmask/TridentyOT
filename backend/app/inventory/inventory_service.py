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
from app.fingerprint.ip_scope import is_lan_ip, is_real_unicast_ip
from app.fingerprint.os_fingerprint import (
    OsGuess,
    TcpSignature,
    fingerprint_tcp_syn,
    parse_tcp_options,
)
from app.fingerprint.protocol_detect import OT, PROFINET_OTHER, ProtocolInfo, classify
from app.fingerprint.vendor_lookup import lookup_vendor
from app.models import CaptureSession, Device, DeviceProtocol, Flow, VulnerabilityFinding, utcnow

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
    printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    if printable / max(len(text), 1) < _PRINTABLE_BANNER_MIN_RATIO:
        return None
    return text.splitlines()[0][:256]


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
    session: Session, ip: str | None, mac: str | None, capture_session_id: int | None = None
) -> Device | None:
    if mac is not None and not _is_real_unicast_mac(mac):
        mac = None
    if ip is not None and not is_real_unicast_ip(ip):
        ip = None
    if not ip and not mac:
        return None

    device = None
    if ip:
        # ip alone isn't actually unique (the DB constraint is on the
        # (mac, ip) pair, and two NULL macs don't collide under it either)
        # -- a large/long capture can genuinely produce two rows for the
        # same ip (e.g. an address briefly reused/conflicting on the LAN,
        # or two uploads racing each other). Picking the oldest
        # deterministically instead of one_or_none() means that anomaly
        # gets tolerated and converged on rather than crashing every
        # ingest that touches this ip afterwards.
        device = session.query(Device).filter(Device.ip == ip).order_by(Device.id.asc()).first()
    if device is None and mac:
        device = (
            session.query(Device)
            .filter(Device.mac == mac, Device.ip.is_(None))
            .order_by(Device.id.asc())
            .first()
        )

    now = utcnow()
    if device is None:
        device = Device(
            ip=ip,
            mac=mac,
            vendor=lookup_vendor(mac),
            capture_session_id=capture_session_id,
            first_seen=now,
            last_seen=now,
        )
        session.add(device)
        session.flush()
        return device

    if mac and not device.mac:
        device.mac = mac
    if ip and not device.ip:
        device.ip = ip
    if device.vendor is None:
        device.vendor = lookup_vendor(device.mac)
    device.last_seen = now
    return device


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
        os_signature=device.os_signature,
        has_ot_server_protocol=any(p.category == OT for p in server_protocols),
        server_protocol_count=len({p.protocol for p in server_protocols}),
    )
    if guess.confidence <= device.device_type_confidence:
        return
    device.device_type = guess.device_type
    device.device_type_confidence = guess.confidence
    device.device_type_evidence = "; ".join(guess.evidence) if guess.evidence else None


def apply_hostname_hints(session: Session, hints: list[tuple[str, str]]) -> None:
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
        device = session.query(Device).filter(Device.ip == ip).order_by(Device.id.asc()).first()
        if device is None or hostname == device.hostname:
            continue

        others = session.query(Device).filter(Device.hostname == hostname, Device.ip != ip).all()
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


def apply_gateway_detection(session: Session) -> None:
    """Detects a router/NAT gateway from a pattern purely-passive capture
    produces: when the gateway forwards a reply from some public-internet
    host onto the LAN, it is transmitting that frame -- so by this app's
    own "MAC only ever learned from the sender" rule (see
    get_or_create_device), that MAC gets attached to the device row for
    *that public IP*. Every distinct public IP the gateway ever forwarded
    ends up as its own inventory row, all sharing the gateway's one real
    MAC, even though none of those IPs are actual local assets (see
    Device.is_external and the module docstring's routed-traffic caveat).

    Two or more distinct public IPs sharing a MAC is that exact pattern.
    Once found, the oldest of those public-IP rows is picked to represent
    the gateway in Inventory and classified as a network device (subcategory
    "router_nat"); routes_inventory.list_devices collapses the rest of the
    *public*-IP duplicates into it when hide_external is requested, without
    deleting them (Flows/Vulnerabilidades still reference them normally).

    Deliberately never promotes a *private*-IP row sharing that MAC to be
    the gateway, even though the gateway's own LAN-side identity (if this
    capture ever saw it speak from one, e.g. via ARP) would be a nicer,
    more recognizable row to label -- there is no reliable way to tell
    that apart from a real, distinct host on a different subnet whose
    traffic was also routed through this same gateway (inter-VLAN routing
    produces the exact same "sender MAC == the gateway" pattern for that
    host's returning packets). Guessing wrong there would mislabel a real
    asset as the gateway itself, which is worse than the gateway's own row
    just not being the one every reader would expect; a private IP is
    always left as a genuine, separate device, classified independently.

    Runs as a whole-table pass after ingesting a batch/file rather than
    per-packet: the pattern is only visible once several distinct public
    IPs for the same MAC actually exist, which no single packet can tell
    on its own.
    """
    devices = session.query(Device).filter(Device.mac.is_not(None)).all()
    by_mac: dict[str, list[Device]] = {}
    for d in devices:
        by_mac.setdefault(d.mac, []).append(d)

    for mac, group in by_mac.items():
        if len(group) < _GATEWAY_MIN_PUBLIC_IPS:
            continue
        public_members = [d for d in group if not is_lan_ip(d.ip)]
        if len(public_members) < _GATEWAY_MIN_PUBLIC_IPS:
            continue

        primary = min(public_members, key=lambda d: d.id)

        if primary.device_type != NETWORK_DEVICE or primary.device_type_confidence < 1.0:
            primary.device_type = NETWORK_DEVICE
            primary.device_type_confidence = 1.0
            primary.device_type_evidence = (
                f"Una misma MAC ({mac}) aparece en {len(public_members)} IPs públicas distintas -- "
                "consistente con un equipo que enruta/NATea tráfico hacia internet"
            )
        if not primary.device_type_secondary:
            primary.device_type_secondary = ROUTER_NAT


def upsert_protocol(
    session: Session,
    device: Device,
    proto_info: ProtocolInfo,
    port: int | None,
    transport: str,
    role: str,
    banner: str | None = None,
    capture_session_id: int | None = None,
) -> DeviceProtocol:
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

    if proto_info.category == "OT":
        device.is_ot_suspected = True

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
) -> Flow:
    """Aggregates both directions of a TCP/UDP conversation between two
    devices into a single row, normalized by device id so the reverse
    direction doesn't create a duplicate."""
    device_a, device_b = sorted((device_x, device_y), key=lambda d: d.id)

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
    session: Session, record: PacketRecord, capture_session_id: int | None = None
) -> None:
    if record.transport == "arp":
        device = get_or_create_device(
            session, ip=record.src_ip, mac=record.src_mac, capture_session_id=capture_session_id
        )
        if device is not None:
            # A device only ever seen via ARP has no protocol/OS evidence at
            # all, but its vendor OUI is still real, weak-but-real evidence
            # (e.g. a Siemens NIC is still a hint towards "plc") -- worth a
            # classification attempt rather than leaving it unclassified
            # purely because it never happened to send TCP/UDP traffic.
            apply_device_type_guess(session, device)
        return

    if record.transport in ("cdp", "lldp"):
        # CDP/LLDP are self-announcements switches/routers send about
        # themselves -- no IP layer involved, so the device is keyed by MAC
        # alone (it'll be merged with an IP-keyed row later if the same MAC
        # is ever seen sending ordinary IP traffic; see get_or_create_device).
        device = get_or_create_device(session, ip=None, mac=record.src_mac, capture_session_id=capture_session_id)
        if device is not None:
            if record.l2_hostname:
                device.hostname = record.l2_hostname
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
        device = get_or_create_device(session, ip=None, mac=record.src_mac, capture_session_id=capture_session_id)
        if device is not None:
            if record.l2_hostname:
                device.hostname = record.l2_hostname
            proto_info = ProtocolInfo(record.l2_protocol or PROFINET_OTHER, OT, True)
            upsert_protocol(session, device, proto_info, None, "profinet", "server", capture_session_id=capture_session_id)
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
        session, ip=record.src_ip, mac=record.src_mac, capture_session_id=capture_session_id
    )
    dst_device = get_or_create_device(session, ip=record.dst_ip, mac=None, capture_session_id=capture_session_id)
    session.flush()

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

    if src_device is not None and dst_device is not None and record.transport in ("tcp", "udp"):
        server_side = _pick_server_side(record)
        server_device = src_device if server_side == "src" else dst_device
        server_port = record.src_port if server_side == "src" else record.dst_port

        banner = _looks_like_text_banner(record.payload)
        proto_info = classify(server_port, payload=record.payload)
        upsert_protocol(
            session,
            server_device,
            proto_info,
            server_port,
            record.transport,
            "server",
            banner,
            capture_session_id=capture_session_id,
        )
        # upsert_protocol's own add() of a brand-new row isn't visible to
        # apply_device_type_guess's query without a flush first (autoflush
        # is off) -- without this, a device would need a *second* packet on
        # the same protocol before ever being classified from it
        # (benchmarked: the extra flush costs ~2% on a real capture, not
        # worth trading for a device that never gets classified because a
        # capture only ever saw one packet from it).
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
        )

    if record.hostname_hints:
        apply_hostname_hints(session, record.hostname_hints)


def purge_capture_session(session: Session, capture_session_id: int) -> None:
    """Removes everything a capture session contributed to the shared
    inventory when it's deleted: its own DeviceProtocol/Flow rows, and any
    Device it first discovered that -- after removing those rows -- no
    other session's protocols/flows still reference, so a device seen by
    more than one capture survives deleting just one of them. A removed
    device's vulnerability findings go with it.

    A device/protocol/flow is attributed to whichever session *first*
    observed it; a later session re-observing the exact same protocol/flow
    only bumps its packet count rather than re-attributing it, so deleting
    that first session also removes evidence a later session merely
    corroborated. This is a deliberate simplification -- full multi-session
    provenance would need a many-to-many audit trail this app doesn't keep.
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
            continue
        session.query(VulnerabilityFinding).filter(VulnerabilityFinding.device_id == device_id).delete(
            synchronize_session=False
        )
        session.query(Device).filter(Device.id == device_id).delete(synchronize_session=False)


def wipe_all_capture_data(session: Session) -> dict[str, int]:
    """Clears every capture session, device, protocol, flow, and
    vulnerability finding -- for starting a completely blank capture.
    User accounts are never touched here: this only ever clears what
    capturing produced, never who's allowed to use the app.

    Deletes in FK-safe order (children before the parents they reference)
    rather than looping purge_capture_session per session -- there's no
    "does something else still reference this" case to check when
    everything is going away at once.
    """
    counts = {
        "findings": session.query(VulnerabilityFinding).delete(synchronize_session=False),
        "protocols": session.query(DeviceProtocol).delete(synchronize_session=False),
        "flows": session.query(Flow).delete(synchronize_session=False),
        "devices": session.query(Device).delete(synchronize_session=False),
        "sessions": session.query(CaptureSession).delete(synchronize_session=False),
    }
    return counts
