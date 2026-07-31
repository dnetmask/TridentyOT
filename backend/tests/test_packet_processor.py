from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from app.capture.packet_processor import process_packet


def test_process_tcp_syn_extracts_fields():
    pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.10", ttl=64) / TCP(
        sport=51000, dport=502, flags="S", window=1024, options=[("MSS", 536)]
    )
    record = process_packet(pkt)
    assert record.transport == "tcp"
    assert record.is_syn is True
    assert record.is_syn_ack is False
    assert record.src_ip == "10.0.0.5"
    assert record.dst_ip == "10.0.0.10"
    assert record.dst_port == 502
    assert record.ttl == 64
    assert record.window == 1024
    assert ("MSS", 536) in record.tcp_options


def test_process_tcp_synack():
    pkt = Ether() / IP(src="10.0.0.10", dst="10.0.0.5", ttl=64) / TCP(sport=502, dport=51000, flags="SA")
    record = process_packet(pkt)
    assert record.is_syn_ack is True
    assert record.is_syn is False


def test_process_arp():
    pkt = Ether() / ARP(psrc="10.0.0.5", pdst="10.0.0.1", hwsrc="aa:bb:cc:dd:ee:ff")
    record = process_packet(pkt)
    assert record.transport == "arp"
    assert record.src_ip == "10.0.0.5"
    assert record.dst_ip == "10.0.0.1"


def test_process_udp_with_payload():
    pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.20") / UDP(sport=123, dport=161) / Raw(load=b"snmp-ish-payload")
    record = process_packet(pkt)
    assert record.transport == "udp"
    assert record.dst_port == 161
    assert record.payload.startswith(b"snmp")


def test_process_non_ip_ethernet_returns_none():
    pkt = Ether(type=0x88CC)  # LLDP, not handled
    assert process_packet(pkt) is None
