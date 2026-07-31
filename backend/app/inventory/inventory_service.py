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
from app.models import Device, DeviceProtocol, utcnow

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


def get_or_create_device(session: Session, ip: str | None, mac: str | None) -> Device | None:
    if not ip and not mac:
        return None

    device = None
    if ip:
        device = session.query(Device).filter(Device.ip == ip).one_or_none()
    if device is None and mac:
        device = session.query(Device).filter(Device.mac == mac, Device.ip.is_(None)).one_or_none()

    now = utcnow()
    if device is None:
        device = Device(ip=ip, mac=mac, first_seen=now, last_seen=now)
        session.add(device)
        session.flush()
        return device

    if mac and not device.mac:
        device.mac = mac
    if ip and not device.ip:
        device.ip = ip
    device.last_seen = now
    return device


def apply_os_guess(device: Device, guess: OsGuess) -> None:
    if guess.confidence <= device.os_confidence:
        return
    device.os_guess = guess.label
    device.os_confidence = guess.confidence
    device.os_signature = guess.signature_name


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


def ingest_packet_record(session: Session, record: PacketRecord) -> None:
    if record.transport == "arp":
        get_or_create_device(session, ip=record.src_ip, mac=record.src_mac)
        return

    if record.transport not in ("tcp", "udp", "icmp"):
        return

    src_device = get_or_create_device(session, ip=record.src_ip, mac=record.src_mac)
    dst_device = get_or_create_device(session, ip=record.dst_ip, mac=record.dst_mac)
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
