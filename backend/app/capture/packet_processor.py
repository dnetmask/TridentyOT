"""Extracts the fields the inventory/fingerprinting pipeline cares about
from a single scapy packet, regardless of whether it came from a live
sniff() callback or from iterating over a loaded .pcap file.
"""

from dataclasses import dataclass, field

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw

from app.fingerprint.hostname_detect import extract_hostname_hints

MAX_PAYLOAD_BYTES = 256


@dataclass
class PacketRecord:
    timestamp: float | None = None
    src_mac: str | None = None
    dst_mac: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    transport: str | None = None  # "tcp" | "udp" | "icmp" | "arp"
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


def _mac(pkt: Packet, field_name: str) -> str | None:
    if pkt.haslayer(Ether):
        return getattr(pkt[Ether], field_name, None)
    return None


def process_packet(pkt: Packet) -> PacketRecord | None:
    timestamp = float(pkt.time) if hasattr(pkt, "time") else None
    record = PacketRecord(
        timestamp=timestamp,
        src_mac=_mac(pkt, "src"),
        dst_mac=_mac(pkt, "dst"),
    )

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
            if pkt.haslayer(Raw):
                record.payload = bytes(pkt[Raw].load)[:MAX_PAYLOAD_BYTES]
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            record.transport = "udp"
            record.src_port = int(udp.sport)
            record.dst_port = int(udp.dport)
            if pkt.haslayer(Raw):
                record.payload = bytes(pkt[Raw].load)[:MAX_PAYLOAD_BYTES]
            record.hostname_hints = extract_hostname_hints(pkt)
        elif pkt.haslayer(ICMP):
            record.transport = "icmp"
        else:
            return None

        return record

    return None
