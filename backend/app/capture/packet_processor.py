"""Extracts the fields the inventory/fingerprinting pipeline cares about
from a single scapy packet, regardless of whether it came from a live
sniff() callback or from iterating over a loaded .pcap file.
"""

from dataclasses import dataclass, field

from scapy.layers.dhcp import DHCP
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Dot1Q, Ether
from scapy.packet import Packet

from app.fingerprint.hostname_detect import extract_hostname_hints
from app.fingerprint.identity_detect import extract_identity_hints
from app.fingerprint.protocol_detect import PN_ALARM, PN_DCP, PNIO_PS, PROFINET_OTHER

try:
    from scapy.contrib.cdp import CDPMsgDeviceID, CDPMsgPlatform, CDPMsgSoftwareVersion, CDPv2_HDR
except ImportError:  # pragma: no cover - scapy always ships this contrib layer
    CDPv2_HDR = CDPMsgDeviceID = CDPMsgPlatform = CDPMsgSoftwareVersion = None

try:
    from scapy.contrib.lldp import LLDPDUSystemDescription, LLDPDUSystemName
except ImportError:  # pragma: no cover - scapy always ships this contrib layer
    LLDPDUSystemName = LLDPDUSystemDescription = None

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


def _pnio_device_reference(pkt: Packet) -> str | None:
    """A DCP Identify/Hello response's Manufacturer Specific block ("Type of
    Station" sub-option) is normally set by the vendor to the product's own
    model/type designation, e.g. Siemens firmware reporting "S7-1200" --
    this app's best-effort passive source for a PROFINET device's
    manufacturer reference. Unlike the Name-of-Station block above, there is
    no firmware/software-revision block in DCP's Identify response to read.
    """
    dcp = pkt[ProfinetDCP]
    for block in getattr(dcp, "dcp_blocks", None) or []:
        value = getattr(block, "device_vendor_value", None)
        if value:
            return _decode(value).strip() or None
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
    # 802.1Q VLAN ID this frame was tagged with, or None if untagged --
    # tagging happens at the outer Ethernet framing level, so this is
    # populated once in process_packet() regardless of which branch
    # (ARP/CDP/LLDP/PROFINET/IP) the frame dispatches to below.
    vlan: int | None = None
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
    # Manufacturer's model/reference for this device -- CDP Platform TLV or
    # a PROFINET DCP "Type of Station" block. Never set for plain LLDP
    # (base LLDP has no separate model TLV, only System Description below).
    l2_device_reference: str | None = None
    # Self-reported firmware/software version -- CDP Software Version TLV,
    # or (best-effort, since base LLDP has no dedicated field for it)
    # LLDP's System Description. Never set for PROFINET DCP, whose Identify
    # response has no firmware/software-revision block to read.
    l2_firmware: str | None = None
    # Which PROFINET sub-protocol this frame carries (see _pnio_protocol_name)
    # -- only set when transport == "profinet".
    l2_protocol: str | None = None
    # Protocol-level device identity (EtherNet/IP CIP, Modbus device ID,
    # ...) self-reported by this packet's sender -- see identity_detect.py.
    identity_hints: list = field(default_factory=list)
    # DHCP option 55 (Parameter Request List), in the order the client sent
    # it -- a client-implementation fingerprint (see fingerprint/
    # dhcp_fingerprint.py), only ever set on a DHCP client packet's sender.
    dhcp_param_request_list: list[int] | None = None


def _dhcp_param_request_list(pkt: Packet) -> list[int] | None:
    """The client's option 55 (Parameter Request List) from a DHCP packet,
    in wire order. Only ever meaningful on a client message (DISCOVER/
    REQUEST/INFORM); a server's OFFER/ACK never carries this option, so
    this naturally returns None for those without needing to check the
    DHCP message type separately."""
    if not pkt.haslayer(DHCP):
        return None
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == "param_req_list":
            value = opt[1]
            if isinstance(value, (list, tuple)) and value:
                return [int(v) for v in value]
    return None


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


def _cdp_platform(pkt: Packet) -> str | None:
    """The device's manufacturer model/reference (e.g. "cisco WS-C2960X-24TS-L"),
    from a CDP Platform TLV."""
    for msg in pkt[CDPv2_HDR].msg:
        if isinstance(msg, CDPMsgPlatform):
            value = _decode(msg.val).strip().rstrip("\x00")
            return value or None
    return None


def _cdp_software_version(pkt: Packet) -> str | None:
    """The device's self-reported firmware/software version, from a CDP
    Software Version TLV (typically a full banner string, e.g. "Cisco IOS
    Software, C2960X Software ..., Version 15.2(4)E7")."""
    for msg in pkt[CDPv2_HDR].msg:
        if isinstance(msg, CDPMsgSoftwareVersion):
            value = _decode(msg.val).strip().rstrip("\x00")
            return value or None
    return None


def process_packet(pkt: Packet) -> PacketRecord | None:
    timestamp = float(pkt.time) if hasattr(pkt, "time") else None
    record = PacketRecord(
        timestamp=timestamp,
        src_mac=_mac(pkt, "src"),
        dst_mac=_mac(pkt, "dst"),
    )
    # 802.1Q tagging happens at the outer Ethernet framing level, independent
    # of whatever the frame carries above it -- checked once here rather
    # than in each branch below.
    if pkt.haslayer(Dot1Q):
        record.vlan = int(pkt[Dot1Q].vlan)

    # CDP/LLDP are pure L2 discovery frames (no IP layer) that switches and
    # routers send about themselves -- the only passive way to identify
    # network infrastructure that never originates ordinary IP traffic on
    # the monitored segment.
    if CDPv2_HDR is not None and pkt.haslayer(CDPv2_HDR):
        record.transport = "cdp"
        record.l2_hostname = _cdp_device_id(pkt)
        record.l2_device_reference = _cdp_platform(pkt)
        record.l2_firmware = _cdp_software_version(pkt)
        return record

    if LLDPDUSystemName is not None and pkt.haslayer(LLDPDUSystemName):
        record.transport = "lldp"
        name = _decode(pkt[LLDPDUSystemName].system_name).strip()
        record.l2_hostname = name or None
        if LLDPDUSystemDescription is not None and pkt.haslayer(LLDPDUSystemDescription):
            description = _decode(pkt[LLDPDUSystemDescription].description).strip()
            record.l2_firmware = description or None
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
            record.l2_device_reference = _pnio_device_reference(pkt)
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
            record.dhcp_param_request_list = _dhcp_param_request_list(pkt)
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
            record.identity_hints = extract_identity_hints(pkt)
            for hint in record.identity_hints:
                if hint.hostname and record.src_ip:
                    record.hostname_hints.append((record.src_ip, hint.hostname))

        return record

    return None
