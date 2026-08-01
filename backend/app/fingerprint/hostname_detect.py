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
- SMB "Computer Browser" service Host/Local Master Announcements (legacy
  NetBIOS Datagram Service, UDP/138): periodic broadcasts every
  Windows/Samba file-sharing host sends, carrying its own NetBIOS computer
  name in the clear alongside OS version info.
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
    from scapy.layers.smb import BRWS_HostAnnouncement, BRWS_LocalMasterAnnouncement, SMBTransaction_Request
except ImportError:  # pragma: no cover - scapy always ships this layer
    BRWS_HostAnnouncement = BRWS_LocalMasterAnnouncement = SMBTransaction_Request = None

_A_RECORD = 1
_BROWSER_MAILSLOTS = (b"\\MAILSLOT\\BROWSE", b"\\MAILSLOT\\LANMAN")


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


def extract_smb_browser_hostname(pkt: Packet) -> tuple[str, str] | None:
    """Returns (ip, hostname) from an SMB Computer Browser service Host or
    Local Master Announcement (NetBIOS Datagram Service, UDP/138).

    BRWS_HostAnnouncement/BRWS_LocalMasterAnnouncement are dissected out as
    the *value* of SMBTransaction_Request.Data (based on the mailslot name),
    not as a normal encapsulated sub-layer -- so they must be reached via
    that field directly rather than pkt.haslayer()/pkt[...]."""
    if SMBTransaction_Request is None or not pkt.haslayer(SMBTransaction_Request) or not pkt.haslayer(IP):
        return None

    txn = pkt[SMBTransaction_Request]
    if txn.Name not in _BROWSER_MAILSLOTS:
        return None

    data = txn.Data
    if not isinstance(data, (BRWS_HostAnnouncement, BRWS_LocalMasterAnnouncement)):
        return None

    name = _decode(data.ServerName).rstrip("\x00").strip()
    src_ip = pkt[IP].src
    if name and src_ip and src_ip != "0.0.0.0":
        return (src_ip, name)
    return None


def extract_hostname_hints(pkt: Packet) -> list[tuple[str, str]]:
    """All (ip, hostname) hints found in this single packet."""
    hints = extract_dns_hostnames(pkt)
    for extractor in (extract_dhcp_hostname, extract_nbns_hostname, extract_smb_browser_hostname):
        hint = extractor(pkt)
        if hint:
            hints.append(hint)
    return hints
