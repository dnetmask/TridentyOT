"""Best-effort hostname discovery from traffic already being processed for
inventory purposes -- no active queries are ever sent.

Four independent sources, all cheap to check on every packet:

- DNS/mDNS A-record answers (regular DNS on port 53, or mDNS on 5353 --
  scapy parses both with the same DNS layer): whenever a name is resolved
  to an IPv4 address, that's a strong (ip -> hostname) hint, regardless of
  which host asked. Only used to *enrich* devices already in the
  inventory (see inventory_service), never to create new ones, so a
  client resolving some unrelated public hostname doesn't pollute the
  device list.
- DHCP option 12 (Host Name): a client stating its own hostname while
  requesting/renewing a lease. Only usable once the client already has a
  real IP (DHCPDISCOVER frames are sent from 0.0.0.0 and can't be
  attributed to a device we track by IP).
- NBNS Name Registration Request (UDP/137): the NetBIOS/SMB equivalent of
  DHCP option 12 -- a Windows/Samba host broadcasting its own short
  ("partial", 15-byte-max) NetBIOS computer name while claiming/refreshing
  it on the network.
- NetBIOS Datagram Service header (UDP/138): every single NBT datagram --
  Computer Browser announcements, NETLOGON broadcasts, anything sent over
  this service -- carries the sender's own NetBIOS name in its "Source
  name" field (what Wireshark's "NetBIOS Datagram Service" tree shows,
  e.g. "DESKTOP-JGVDMBA<20> (Server service)"), regardless of what's in
  the payload above it.
"""

from scapy.layers.inet import IP
from scapy.packet import Packet

try:
    from scapy.layers.dns import DNS, DNSRR
except ImportError:  # pragma: no cover - scapy always ships this layer
    DNS = DNSRR = None

try:
    from scapy.layers.dhcp import DHCP
except ImportError:  # pragma: no cover - scapy always ships this layer
    DHCP = None

try:
    from scapy.layers.netbios import NBNSRegistrationRequest
except ImportError:  # pragma: no cover - scapy always ships this layer
    NBNSRegistrationRequest = None

try:
    from scapy.layers.smb import NBTDatagram
except ImportError:  # pragma: no cover - scapy always ships this layer
    NBTDatagram = None

_A_RECORD = 1


def _decode(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value)


def extract_dns_hostnames(pkt: Packet) -> list[tuple[str, str]]:
    """Returns [(ip, hostname), ...] from A-record answers in a DNS/mDNS response."""
    if DNS is None or not pkt.haslayer(DNS):
        return []
    dns = pkt[DNS]
    if dns.qr != 1 or not dns.an:
        return []

    results = []
    for rr in dns.an:
        if not isinstance(rr, DNSRR) or rr.type != _A_RECORD:
            continue
        name = _decode(rr.rrname).rstrip(".")
        ip = _decode(rr.rdata)
        if name and ip:
            results.append((ip, name))
    return results


def extract_dhcp_hostname(pkt: Packet) -> tuple[str, str] | None:
    """Returns (ip, hostname) from DHCP option 12, when the packet's
    source IP is already assigned (not the 0.0.0.0 used pre-lease)."""
    if DHCP is None or not pkt.haslayer(DHCP) or not pkt.haslayer(IP):
        return None

    hostname = None
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == "hostname":
            hostname = _decode(opt[1])
            break

    src_ip = pkt[IP].src
    if hostname and src_ip and src_ip != "0.0.0.0":
        return (src_ip, hostname)
    return None


def extract_nbns_hostname(pkt: Packet) -> tuple[str, str] | None:
    """Returns (ip, hostname) from an NBNS Name Registration Request --
    a host claiming/refreshing its own NetBIOS computer name."""
    if NBNSRegistrationRequest is None or not pkt.haslayer(NBNSRegistrationRequest) or not pkt.haslayer(IP):
        return None

    name = _decode(pkt[NBNSRegistrationRequest].QUESTION_NAME).strip()
    src_ip = pkt[IP].src
    if name and src_ip and src_ip != "0.0.0.0":
        return (src_ip, name)
    return None


def extract_nbt_datagram_hostname(pkt: Packet) -> tuple[str, str] | None:
    """Returns (ip, hostname) from the "Source name" of a NetBIOS Datagram
    Service header (UDP/138) -- present on every such packet, not just
    Computer Browser announcements."""
    if NBTDatagram is None or not pkt.haslayer(NBTDatagram) or not pkt.haslayer(IP):
        return None

    name = _decode(pkt[NBTDatagram].SourceName).strip()
    src_ip = pkt[IP].src
    if name and src_ip and src_ip != "0.0.0.0":
        return (src_ip, name)
    return None


def extract_hostname_hints(pkt: Packet) -> list[tuple[str, str]]:
    """All (ip, hostname) hints found in this single packet."""
    hints = extract_dns_hostnames(pkt)
    for extractor in (extract_dhcp_hostname, extract_nbns_hostname, extract_nbt_datagram_hostname):
        hint = extractor(pkt)
        if hint:
            hints.append(hint)
    return hints
