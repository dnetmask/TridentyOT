from scapy.contrib.cdp import CDPMsgDeviceID, CDPMsgPlatform, CDPv2_HDR
from scapy.contrib.lldp import (
    LLDPDUChassisID,
    LLDPDUEndOfLLDPDU,
    LLDPDUPortID,
    LLDPDUSystemName,
    LLDPDUTimeToLive,
)
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, LLC, SNAP, Ether
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
    pkt = Ether(type=0x88CC)  # bare LLDP ethertype, no LLDPDU layers -- unrecognized
    assert process_packet(pkt) is None


def test_process_cdp_extracts_device_id_and_mac():
    pkt = (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="01:00:0c:cc:cc:cc")
        / LLC()
        / SNAP(OUI=0xC, code=0x2000)
        / CDPv2_HDR(msg=[CDPMsgDeviceID(val=b"switch1.corp.local"), CDPMsgPlatform(val=b"cisco WS-C2960X-24TS-L")])
    )
    record = process_packet(Ether(bytes(pkt)))
    assert record.transport == "cdp"
    assert record.src_mac == "aa:bb:cc:dd:ee:ff"
    assert record.l2_hostname == "switch1.corp.local"


def test_process_lldp_extracts_system_name_and_mac():
    pkt = (
        Ether(src="11:22:33:44:55:66", dst="01:80:c2:00:00:0e", type=0x88CC)
        / LLDPDUChassisID(subtype=4, id=b"\x11\x22\x33\x44\x55\x66")
        / LLDPDUPortID(subtype=1, id=b"Gi0/1")
        / LLDPDUTimeToLive(ttl=120)
        / LLDPDUSystemName(system_name=b"switch2-access")
        / LLDPDUEndOfLLDPDU()
    )
    record = process_packet(Ether(bytes(pkt)))
    assert record.transport == "lldp"
    assert record.src_mac == "11:22:33:44:55:66"
    assert record.l2_hostname == "switch2-access"
