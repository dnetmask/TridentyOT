"""Extracts the fields the inventory/fingerprinting pipeline cares about
from a single scapy packet, regardless of whether it came from a live
sniff() callback or from iterating over a loaded .pcap file.
"""

from dataclasses import dataclass, field

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

from app.fingerprint.hostname_detect import extract_hostname_hints

try:
    from scapy.contrib.cdp import CDPMsgDeviceID, CDPv2_HDR
except ImportError:  # pragma: no cover - scapy always ships this contrib layer
    CDPv2_HDR = CDPMsgDeviceID = None

try:
    from scapy.contrib.lldp import LLDPDUSystemName
except ImportError:  # pragma: no cover - scapy always ships this contrib layer
    LLDPDUSystemName = None

MAX_PAYLOAD_BYTES = 256


@dataclass
class PacketRecord:
    timestamp: float | None = None
    src_mac: str | None = None
    dst_mac: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    transport: str | None = None  # "tcp" | "udp" | "icmp" | "arp" | "cdp" | "lldp"
    src_port: int | None = None
    dst_port: int | None = None
    ttl: int | None = None
    tcp_flags: str | None = None
    window: int | None = None
    tcp_options: list = field(default_factory=list)
    is_syn: bool = False
    is_syn_ack: bool = False
    payload: bytes = b""
    hostname_hints: list = field(default_factory=list)  # [(ip, hostname), ...]
    # Self-reported device name from a CDP/LLDP announcement -- these are L2-only
    # frames (no IP layer), so unlike hostname_hints this identifies src_mac,
    # not an IP.
    l2_hostname: str | None = None


def _mac(pkt: Packet, field_name: str) -> str | None:
    if pkt.haslayer(Ether):
        return getattr(pkt[Ether], field_name, None)
    return None


def _decode(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value)


def _cdp_device_id(pkt: Packet) -> str | None:
    """The switch/router's own name, from a CDP Device ID TLV."""
    for msg in pkt[CDPv2_HDR].msg:
        if isinstance(msg, CDPMsgDeviceID):
            name = _decode(msg.val).strip().rstrip("\x00")
            return name or None
    return None


def process_packet(pkt: Packet) -> PacketRecord | None:
    timestamp = float(pkt.time) if hasattr(pkt, "time") else None
    record = PacketRecord(
        timestamp=timestamp,
        src_mac=_mac(pkt, "src"),
        dst_mac=_mac(pkt, "dst"),
    )

    # CDP/LLDP are pure L2 discovery frames (no IP layer) that switches and
    # routers send about themselves -- the only passive way to identify
    # network infrastructure that never originates ordinary IP traffic on
    # the monitored segment.
    if CDPv2_HDR is not None and pkt.haslayer(CDPv2_HDR):
        record.transport = "cdp"
        record.l2_hostname = _cdp_device_id(pkt)
        return record

    if LLDPDUSystemName is not None and pkt.haslayer(LLDPDUSystemName):
        record.transport = "lldp"
        name = _decode(pkt[LLDPDUSystemName].system_name).strip()
        record.l2_hostname = name or None
        return record

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        record.transport = "arp"
        # op 1 = who-has (request, src is asking about dst); op 2 = is-at (reply)
        # hwsrc/hwdst are the semantically correct MACs for the claimed IPs,
        # which can differ from the enclosing Ethernet frame's src/dst.
        record.src_ip = arp.psrc
        record.dst_ip = arp.pdst
        record.src_mac = arp.hwsrc
        record.dst_mac = arp.hwdst
        return record

    if pkt.haslayer(IP):
        ip = pkt[IP]
        record.src_ip = ip.src
        record.dst_ip = ip.dst
        record.ttl = ip.ttl

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            record.transport = "tcp"
            record.src_port = int(tcp.sport)
            record.dst_port = int(tcp.dport)
            record.window = int(tcp.window)
            record.tcp_options = list(tcp.options)
            flags = str(tcp.flags)
            record.tcp_flags = flags
            record.is_syn = "S" in flags and "A" not in flags
            record.is_syn_ack = "S" in flags and "A" in flags
            # bytes(tcp.payload) rather than pkt[Raw].load: some well-known
            # ports (e.g. 139, once scapy.layers.netbios/smb are imported
            # for hostname_detect) get their own scapy sub-dissector bound
            # onto TCP, splitting what's really one contiguous payload into
            # typed sub-layers (NBTSession/_SMBGeneric/Raw). pkt[Raw].load
            # would then only be whatever tail scapy couldn't parse into
            # those -- bytes(tcp.payload) always reassembles the full,
            # original wire bytes regardless of how deep that dissection went.
            record.payload = bytes(tcp.payload)[:MAX_PAYLOAD_BYTES]
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            record.transport = "udp"
            record.src_port = int(udp.sport)
            record.dst_port = int(udp.dport)
            record.payload = bytes(udp.payload)[:MAX_PAYLOAD_BYTES]
        elif pkt.haslayer(ICMP):
            record.transport = "icmp"
        else:
            return None

        # Hostname extraction needs the *full* payload (e.g. a NetBIOS
        # Session Request on TCP/139), so it runs against the original pkt
        # here rather than the possibly-truncated record.payload above --
        # and for both transports, not just UDP, since SMB/NetBIOS session
        # hostnames ride over TCP.
        if record.transport in ("tcp", "udp"):
            record.hostname_hints = extract_hostname_hints(pkt)

        return record

    return None
