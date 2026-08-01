"""Turns processed packet records into a persistent device/service inventory.

Devices are keyed primarily by IP address. This is accurate for hosts on
the same flat L2 segment as the capture point (the typical OT/ICS SPAN-port
deployment TridentyOT targets); for routed traffic the captured MAC only
identifies the last-hop router, not the true origin host, which is an
inherent limitation of any purely passive single-point capture.
"""

from sqlalchemy.orm import Session

from app.capture.packet_processor import PacketRecord
from app.fingerprint.os_fingerprint import (
    OsGuess,
    TcpSignature,
    fingerprint_tcp_syn,
    parse_tcp_options,
)
from app.fingerprint.protocol_detect import ProtocolInfo, classify
from app.fingerprint.vendor_lookup import lookup_vendor
from app.models import Device, DeviceProtocol, Flow, utcnow

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


def get_or_create_device(session: Session, ip: str | None, mac: str | None) -> Device | None:
    if mac is not None and not _is_real_unicast_mac(mac):
        mac = None
    if not ip and not mac:
        return None

    device = None
    if ip:
        device = session.query(Device).filter(Device.ip == ip).one_or_none()
    if device is None and mac:
        device = session.query(Device).filter(Device.mac == mac, Device.ip.is_(None)).one_or_none()

    now = utcnow()
    if device is None:
        device = Device(ip=ip, mac=mac, vendor=lookup_vendor(mac), first_seen=now, last_seen=now)
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


def apply_hostname_hints(session: Session, hints: list[tuple[str, str]]) -> None:
    """Enriches already-known devices with an auto-detected hostname.

    Only updates existing inventory entries -- never creates a device from
    a DNS/mDNS/DHCP hint alone, so e.g. a client resolving some unrelated
    public hostname doesn't pollute the inventory with a phantom "device"
    for that public IP.
    """
    for ip, hostname in hints:
        device = session.query(Device).filter(Device.ip == ip).one_or_none()
        if device is not None and hostname:
            device.hostname = hostname


def upsert_protocol(
    session: Session,
    device: Device,
    proto_info: ProtocolInfo,
    port: int | None,
    transport: str,
    role: str,
    banner: str | None = None,
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


def ingest_packet_record(session: Session, record: PacketRecord) -> None:
    if record.transport == "arp":
        get_or_create_device(session, ip=record.src_ip, mac=record.src_mac)
        return

    if record.transport in ("cdp", "lldp"):
        # CDP/LLDP are self-announcements switches/routers send about
        # themselves -- no IP layer involved, so the device is keyed by MAC
        # alone (it'll be merged with an IP-keyed row later if the same MAC
        # is ever seen sending ordinary IP traffic; see get_or_create_device).
        device = get_or_create_device(session, ip=None, mac=record.src_mac)
        if device is not None:
            if record.l2_hostname:
                device.hostname = record.l2_hostname
            # An explicit CDP/LLDP announcement is a stronger signal than the
            # passive TCP-SYN heuristic, so it always outranks it.
            apply_os_guess(device, _CDP_LLDP_GUESS)
        return

    if record.transport not in ("tcp", "udp", "icmp"):
        return

    # Only ever learn a device's MAC from a packet where it is the *sender*.
    # A frame's destination MAC is merely what the sender believes/resolved
    # via its own ARP cache -- not an authoritative statement from that
    # device about its own hardware address -- so it's never used here.
    src_device = get_or_create_device(session, ip=record.src_ip, mac=record.src_mac)
    dst_device = get_or_create_device(session, ip=record.dst_ip, mac=None)
    if src_device is None or dst_device is None:
        return
    session.flush()

    if record.transport in ("tcp", "udp"):
        server_side = _pick_server_side(record)
        server_device = src_device if server_side == "src" else dst_device
        server_port = record.src_port if server_side == "src" else record.dst_port

        banner = _looks_like_text_banner(record.payload)
        proto_info = classify(server_port, payload=record.payload)
        upsert_protocol(session, server_device, proto_info, server_port, record.transport, "server", banner)
        upsert_flow(session, src_device, dst_device, server_device, record.transport, server_port, proto_info)

    if record.hostname_hints:
        apply_hostname_hints(session, record.hostname_hints)

    if record.transport == "tcp" and (record.is_syn or record.is_syn_ack) and record.ttl is not None:
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
