from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import rdpcap, wrpcap

from app.fingerprint.hostname_detect import (
    extract_dhcp_hostname,
    extract_dns_hostnames,
    extract_hostname_hints,
)


def _roundtrip(pkt, tmp_path, name="pkt.pcap"):
    """Round-trips through real pcap bytes, since some scapy fields (e.g.
    DNS rrname) decode differently in-memory vs. from captured bytes."""
    path = str(tmp_path / name)
    wrpcap(path, [pkt])
    return rdpcap(path)[0]


def test_extract_dns_hostname_from_mdns_response(tmp_path):
    pkt = Ether() / IP(src="10.10.1.21", dst="224.0.0.251") / UDP(sport=5353, dport=5353) / DNS(
        qr=1, aa=1, an=DNSRR(rrname="myhost.local.", type="A", rdata="10.10.1.21")
    )
    pkt = _roundtrip(pkt, tmp_path)
    assert extract_dns_hostnames(pkt) == [("10.10.1.21", "myhost.local")]


def test_extract_dns_hostname_ignores_queries():
    query = Ether() / IP(src="10.10.1.5", dst="10.10.1.1") / UDP(sport=53000, dport=53) / DNS(qr=0)
    assert extract_dns_hostnames(query) == []


def test_extract_dhcp_hostname_requires_assigned_ip():
    with_ip = Ether() / IP(src="10.10.1.30", dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(
        chaddr=b"\xaa\xbb\xcc\xdd\xee\xff"
    ) / DHCP(options=[("message-type", "request"), ("hostname", "plc-eng-01"), "end"])
    assert extract_dhcp_hostname(with_ip) == ("10.10.1.30", "plc-eng-01")

    pre_lease = Ether() / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(
        chaddr=b"\xaa\xbb\xcc\xdd\xee\xff"
    ) / DHCP(options=[("message-type", "discover"), ("hostname", "plc-eng-01"), "end"])
    assert extract_dhcp_hostname(pre_lease) is None


def test_extract_dhcp_hostname_absent_option_returns_none():
    pkt = Ether() / IP(src="10.10.1.30", dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(
        chaddr=b"\xaa\xbb\xcc\xdd\xee\xff"
    ) / DHCP(options=[("message-type", "request"), "end"])
    assert extract_dhcp_hostname(pkt) is None


def test_extract_hostname_hints_combines_both_sources(tmp_path):
    dns_pkt = _roundtrip(
        Ether() / IP(src="10.10.1.21", dst="224.0.0.251") / UDP(sport=5353, dport=5353) / DNS(
            qr=1, aa=1, an=DNSRR(rrname="myhost.local.", type="A", rdata="10.10.1.21")
        ),
        tmp_path,
        "dns.pcap",
    )
    assert extract_hostname_hints(dns_pkt) == [("10.10.1.21", "myhost.local")]

    dhcp_pkt = Ether() / IP(src="10.10.1.30", dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(
        chaddr=b"\xaa\xbb\xcc\xdd\xee\xff"
    ) / DHCP(options=[("message-type", "request"), ("hostname", "plc-eng-01"), "end"])
    assert extract_hostname_hints(dhcp_pkt) == [("10.10.1.30", "plc-eng-01")]

    tcp_only = Ether() / IP(src="10.10.1.5", dst="10.10.1.6")
    assert extract_hostname_hints(tcp_only) == []
