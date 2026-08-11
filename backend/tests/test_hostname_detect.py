from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.netbios import NBNSHeader, NBNSRegistrationRequest
from scapy.layers.smb import NBTDatagram
from scapy.packet import Raw
from scapy.utils import rdpcap, wrpcap

from app.fingerprint.hostname_detect import (
    extract_dhcp_hostname,
    extract_dns_hostnames,
    extract_hostname_hints,
    extract_netbios_session_hostname,
    extract_nbns_hostname,
    extract_nbt_datagram_hostname,
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


def test_extract_nbt_datagram_hostname_from_source_name(tmp_path):
    """Matches Wireshark's "NetBIOS Datagram Service" tree exactly: Source
    IP, Source name (with its <suffix>), Destination name."""
    pkt = (
        Ether()
        / IP(src="192.168.0.105", dst="192.168.0.255")
        / UDP(sport=138, dport=138)
        / NBTDatagram(
            SourceName="DESKTOP-JGVDMBA",
            SUFFIX1="file server service",
            DestinationName="WORKGROUP",
            SUFFIX2="workstation",
        )
    )
    pkt = _roundtrip(pkt, tmp_path, "nbt_datagram.pcap")
    assert extract_nbt_datagram_hostname(pkt) == ("192.168.0.105", "DESKTOP-JGVDMBA")


def test_extract_nbt_datagram_hostname_ignores_unrelated_udp():
    pkt = Ether() / IP(src="10.10.1.5", dst="10.10.1.1") / UDP(sport=53000, dport=53) / DNS(qr=0)
    assert extract_nbt_datagram_hostname(pkt) is None


def test_extract_nbns_hostname_rejects_group_registration(tmp_path):
    """A workgroup/domain name registered with the RR_NAME group bit set is
    shared by every member of the group -- never a specific device's own
    identity (this is how "WORKGROUP" used to leak into the inventory as a
    device's hostname)."""
    pkt = (
        Ether()
        / IP(src="10.10.1.40", dst="10.10.1.255")
        / UDP(sport=137, dport=137)
        / NBNSHeader(OPCODE=0x5, NM_FLAGS=0x11)
        / NBNSRegistrationRequest(QUESTION_NAME="WORKGROUP", SUFFIX="workstation", NB_ADDRESS="10.10.1.40", G=1)
    )
    pkt = _roundtrip(pkt, tmp_path, "nbns_group.pcap")
    assert extract_nbns_hostname(pkt) is None


def test_extract_nbns_hostname_rejects_msbrowse_token_even_without_group_bit(tmp_path):
    """The reserved browser-election name is rejected outright, regardless
    of whether this particular registration set the group bit -- some
    stacks don't set it consistently."""
    pkt = (
        Ether()
        / IP(src="10.10.1.40", dst="10.10.1.255")
        / UDP(sport=137, dport=137)
        / NBNSHeader(OPCODE=0x5, NM_FLAGS=0x11)
        / NBNSRegistrationRequest(
            QUESTION_NAME="\x01\x02__MSBROWSE__\x02", SUFFIX="workstation", NB_ADDRESS="10.10.1.40", G=0
        )
    )
    pkt = _roundtrip(pkt, tmp_path, "nbns_msbrowse.pcap")
    assert extract_nbns_hostname(pkt) is None


def _encode_netbios_session_name(name: str, suffix: int = 0x00) -> bytes:
    """RFC 1001 S14.1 first-level ("half-ASCII") encoding, the inverse of
    _decode_netbios_session_name -- used here to build a synthetic Session
    Request payload, since scapy has no dedicated layer for one."""
    padded = name.encode("ascii")[:15].ljust(15, b" ") + bytes([suffix])
    encoded = bytearray()
    for b in padded:
        encoded.append(0x41 + (b >> 4))
        encoded.append(0x41 + (b & 0x0F))
    return bytes(encoded)


def _nbss_session_request(called: str, calling: str) -> bytes:
    body = (
        b"\x20"
        + _encode_netbios_session_name(called)
        + b"\x00"
        + b"\x20"
        + _encode_netbios_session_name(calling)
        + b"\x00"
    )
    return bytes([0x81, 0x00]) + len(body).to_bytes(2, "big") + body


def test_extract_netbios_session_hostname_from_calling_name(tmp_path):
    """The one hostname source that needs deep TCP payload inspection: the
    NetBIOS Session Request (TCP/139) handshake's self-reported "Calling
    Name", present on every SMB-over-NetBIOS session even when the host
    never sends any NBNS/NBT-Datagram broadcast of its own."""
    payload = _nbss_session_request(called="FILESERVER", calling="K787395-HMI01")
    pkt = (
        Ether()
        / IP(src="10.17.124.16", dst="10.17.124.124")
        / TCP(sport=51000, dport=139, flags="PA")
        / Raw(load=payload)
    )
    pkt = _roundtrip(pkt, tmp_path, "nbss.pcap")
    assert extract_netbios_session_hostname(pkt) == ("10.17.124.16", "K787395-HMI01")


def test_extract_netbios_session_hostname_ignores_other_ports(tmp_path):
    payload = _nbss_session_request(called="A", calling="B")
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=51000, dport=445, flags="PA") / Raw(load=payload)
    pkt = _roundtrip(pkt, tmp_path, "not_139.pcap")
    assert extract_netbios_session_hostname(pkt) is None


def test_extract_netbios_session_hostname_ignores_non_session_request(tmp_path):
    """An ordinary SMB data packet over the NetBIOS session (type 0x00,
    "Session Message") isn't the handshake -- no Calling Name to read."""
    pkt = (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=51000, dport=139, flags="PA")
        / Raw(load=b"\x00\x00\x00\x04ABCD")
    )
    pkt = _roundtrip(pkt, tmp_path, "session_message.pcap")
    assert extract_netbios_session_hostname(pkt) is None


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
