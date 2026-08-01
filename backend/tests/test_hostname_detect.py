from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.netbios import NBNSHeader, NBNSRegistrationRequest
from scapy.layers.smb import BRWS_HostAnnouncement, BRWS_LocalMasterAnnouncement, NBTDatagram, SMB_Header, SMBTransaction_Request
from scapy.utils import rdpcap, wrpcap

from app.fingerprint.hostname_detect import (
    extract_dhcp_hostname,
    extract_dns_hostnames,
    extract_hostname_hints,
    extract_nbns_hostname,
    extract_smb_browser_hostname,
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


def test_extract_nbns_hostname_from_registration_request(tmp_path):
    pkt = (
        Ether()
        / IP(src="10.10.1.40", dst="10.10.1.255")
        / UDP(sport=137, dport=137)
        / NBNSHeader(OPCODE=0x5, NM_FLAGS=0x11)
        / NBNSRegistrationRequest(QUESTION_NAME="ENGWORKSTATION", SUFFIX="workstation", NB_ADDRESS="10.10.1.40")
    )
    pkt = _roundtrip(pkt, tmp_path, "nbns.pcap")
    assert extract_nbns_hostname(pkt) == ("10.10.1.40", "ENGWORKSTATION")


def test_extract_nbns_hostname_ignores_non_registration_packets():
    query = Ether() / IP(src="10.10.1.5", dst="10.10.1.1") / UDP(sport=53000, dport=53) / DNS(qr=0)
    assert extract_nbns_hostname(query) is None


def test_extract_smb_browser_hostname_from_host_announcement(tmp_path):
    brws = BRWS_HostAnnouncement(ServerName=b"FILESERVER01", Comment=b"Engineering share")
    txn = SMBTransaction_Request(Name="\\MAILSLOT\\BROWSE", Data=bytes(brws))
    pkt = (
        Ether()
        / IP(src="10.10.1.50", dst="10.10.1.255")
        / UDP(sport=138, dport=138)
        / NBTDatagram()
        / SMB_Header(Command=0x25)
        / txn
    )
    pkt = _roundtrip(pkt, tmp_path, "browser.pcap")
    assert extract_smb_browser_hostname(pkt) == ("10.10.1.50", "FILESERVER01")


def test_extract_smb_browser_hostname_from_local_master_announcement(tmp_path):
    brws = BRWS_LocalMasterAnnouncement(ServerName=b"DC01", Comment=b"Domain Controller")
    txn = SMBTransaction_Request(Name="\\MAILSLOT\\BROWSE", Data=bytes(brws))
    pkt = (
        Ether()
        / IP(src="10.10.1.51", dst="10.10.1.255")
        / UDP(sport=138, dport=138)
        / NBTDatagram()
        / SMB_Header(Command=0x25)
        / txn
    )
    pkt = _roundtrip(pkt, tmp_path, "browser2.pcap")
    assert extract_smb_browser_hostname(pkt) == ("10.10.1.51", "DC01")


def test_extract_smb_browser_hostname_ignores_unrelated_udp():
    pkt = Ether() / IP(src="10.10.1.5", dst="10.10.1.1") / UDP(sport=53000, dport=53) / DNS(qr=0)
    assert extract_smb_browser_hostname(pkt) is None


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
