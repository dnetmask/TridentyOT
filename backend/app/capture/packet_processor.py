"""Extracts the fields the inventory/fingerprinting pipeline cares about
from a single scapy packet, regardless of whether it came from a live
sniff() callback or from iterating over a loaded .pcap file.
"""

from dataclasses import dataclass, field

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

from app.fingerprint.hostname_detect import extract_hostname_hints
from app.fingerprint.protocol_detect import PN_ALARM, PN_DCP, PNIO_PS, PROFINET_OTHER

try:
    from scapy.contrib.cdp import CDPMsgDeviceID, CDPv2_HDR
except ImportError:  # pragma: no cover - scapy always ships this contrib layer
    CDPv2_HDR = CDPMsgDeviceID = None

try:
    from scapy.contrib.lldp import LLDPDUSystemName
except ImportError:  # pragma: no cover - scapy always ships this contrib layer
    LLDPDUSystemName = None

try:
    from scapy.contrib.pnio import ProfinetIO
    from scapy.contrib.pnio_dcp import ProfinetDCP
except ImportError:  # pragma: no cover - scapy always ships this contrib layer
    ProfinetIO = ProfinetDCP = None

# PROFINET frame IDs that identify which sub-protocol a given ProfinetIO
# frame carries -- mirrors ProfinetIO.guess_payload_class's own dispatch in
# scapy.contrib.pnio, kept here as plain ranges rather than introspecting
# the dissected payload type, since the frameID is always present and
# unambiguous regardless of how deep scapy's own dissection went.
_PNIO_DCP_FRAME_IDS = (0xFEFC, 0xFEFD, 0xFEFE, 0xFEFF)
_PNIO_ALARM_FRAME_IDS = (0xFC01, 0xFE01)


def _pnio_protocol_name(frame_id: int) -> str:
    """The protocol name to record for a PROFINET frame, matching
    Wireshark's own Protocol column labels as closely as practical so a
    site's existing PROFINET knowledge (Wireshark captures, docs) transfers
    directly. PNIO_PS -- the cyclic real-time I/O data exchange between an
    IO-controller (PLC) and its IO-devices -- is by far the most common in
    a running line, which is why it's the frameID range check, not an
    afterthought fallback."""
    if frame_id in _PNIO_DCP_FRAME_IDS:
        return PN_DCP
    if frame_id in _PNIO_ALARM_FRAME_IDS:
        return PN_ALARM
    if (0x0100 <= frame_id < 0x1000) or (0x8000 <= frame_id < 0xFC00):
        return PNIO_PS
    return PROFINET_OTHER


def _pnio_station_name(pkt: Packet) -> str | None:
    """A DCP Identify/Hello response carries the device's own configured
    name in a Name-of-Station block -- the PROFINET equivalent of CDP/LLDP's
    system name, self-reported by the device rather than inferred."""
    dcp = pkt[ProfinetDCP]
    for block in getattr(dcp, "dcp_blocks", None) or []:
        name = getattr(block, "name_of_station", None)
        if name:
            return _decode(name).strip() or None
    return None


MAX_PAYLOAD_BYTES = 256


@dataclass
class PacketRecord:
    timestamp: float | None = None
    src_mac: str | None = None
    dst_mac: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    transport: str | None = None  # "tcp" | "udp" | "icmp" | "arp" | "cdp" | "lldp" | "profinet"
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
    # Self-reported device name from a CDP/LLDP/PROFINET-DCP announcement --
    # these are L2-only frames (no IP layer), so unlike hostname_hints this
    # identifies src_mac, not an IP.
    l2_hostname: str | None = None
    # Which PROFINET sub-protocol this frame carries (see _pnio_protocol_name)
    # -- only set when transport == "profinet".
    l2_protocol: str | None = None


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

    # PROFINET (IEC 61158) runs its real-time I/O traffic raw over Ethernet
    # (EtherType 0x8892, no IP layer at all) rather than over IP/UDP -- a
    # PLC and its IO-devices are identified by MAC alone the same way a
    # CDP/LLDP-only switch is. PNIO_PS (cyclic real-time I/O data) is the
    # overwhelming majority of traffic on a running line; PN-DCP
    # (discovery/configuration) additionally self-reports the device's
    # configured name, same role as CDP/LLDP's system name.
    if ProfinetIO is not None and pkt.haslayer(ProfinetIO):
        record.transport = "profinet"
        record.l2_protocol = _pnio_protocol_name(pkt[ProfinetIO].frameID)
        if ProfinetDCP is not None and pkt.haslayer(ProfinetDCP):
            record.l2_hostname = _pnio_station_name(pkt)
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
