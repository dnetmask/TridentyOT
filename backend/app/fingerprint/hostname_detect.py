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
- NetBIOS Session Service Session Request (TCP/139): the SMB-over-NetBIOS
  handshake's "Calling Name" -- the source host's own computer name,
  first-level-encoded (RFC 1001 S14.1) in the TCP payload itself, so this
  is the one source here that needs the raw payload rather than a scapy
  layer (scapy has no dedicated Session Request sub-packet). This is what
  actually carries a name for hosts only ever seen doing plain SMB/CIFS
  traffic, with no DHCP/NBNS/mDNS broadcast of their own.

A NetBIOS *group* name (a workgroup/domain name like "WORKGROUP", or the
reserved "__MSBROWSE__" browser-election token) is never a specific
device's own identity -- registering/announcing one is something every
member of that group does, so it must never be trusted as *that* device's
hostname. NBNS registrations expose this via the RR_NAME G (group) bit;
extract_nbns_hostname rejects those directly. Group names that don't set
the bit (some stacks register the domain name as G=0) are instead caught
downstream, in inventory_service.apply_hostname_hints, by the fact that a
real per-host name is never claimed by more than one IP.
"""

from scapy.layers.inet import IP, TCP
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
_NBSS_SESSION_REQUEST = 0x81
_NBSS_ENCODED_NAME_LEN = 32
_MSBROWSE_TOKEN = "\x01\x02__MSBROWSE__\x02"


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
    a host claiming/refreshing its own NetBIOS computer name. Registrations
    of a *group* name (RR_NAME G bit set -- a workgroup/domain name, or the
    reserved browser-election token) are rejected: those are shared by
    every member of the group, never a specific device's own identity."""
    if NBNSRegistrationRequest is None or not pkt.haslayer(NBNSRegistrationRequest) or not pkt.haslayer(IP):
        return None

    reg = pkt[NBNSRegistrationRequest]
    if getattr(reg, "G", 0):
        return None

    name = _decode(reg.QUESTION_NAME).strip()
    if name == _MSBROWSE_TOKEN:
        return None

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


def _decode_netbios_session_name(encoded: bytes) -> str | None:
    """Reverses the RFC 1001 S14.1 first-level ("half-ASCII") encoding used
    in a NetBIOS Session Request's Called/Calling name fields: each of the
    16 original name bytes is split into two nibbles, each written out as
    a letter 'A'..'P' (nibble 0 -> 'A', ... nibble 15 -> 'P')."""
    if len(encoded) != _NBSS_ENCODED_NAME_LEN:
        return None
    try:
        raw = bytes(
            ((encoded[i] - 0x41) << 4) | (encoded[i + 1] - 0x41) for i in range(0, _NBSS_ENCODED_NAME_LEN, 2)
        )
    except (ValueError, IndexError):
        return None
    if any(b > 0xFF or b < 0 for b in raw):
        return None
    name = raw.decode("ascii", errors="ignore").strip(" \x00")
    return name or None


def extract_netbios_session_hostname(pkt: Packet) -> tuple[str, str] | None:
    """Returns (ip, hostname) from the "Calling Name" of a NetBIOS Session
    Request (TCP/139) -- the one hostname source that lives in the raw TCP
    payload of the SMB-over-NetBIOS handshake, not a parsed scapy layer.

    Reads bytes(tcp.payload) rather than pkt[Raw].load: once
    scapy.layers.netbios is imported (it is, above, for
    NBNSRegistrationRequest), scapy auto-binds TCP/139 to its own
    NBTSession/_SMBGeneric dissector, so pkt[Raw] -- if even present --
    would only be whatever tail scapy's own parser didn't recognize, not
    the full original payload this function needs to decode from byte 0.
    """
    if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
        return None
    tcp = pkt[TCP]
    if int(tcp.dport) != 139:
        return None

    data = bytes(tcp.payload)
    if len(data) < 4 or data[0] != _NBSS_SESSION_REQUEST:
        return None

    # 4-byte NBSS header, then [1-byte len=0x20][32-byte encoded called name]
    # [0x00][1-byte len=0x20][32-byte encoded calling name] -- we only need
    # the second (calling/source) name.
    pos = 4
    if len(data) < pos + 1 or data[pos] != _NBSS_ENCODED_NAME_LEN:
        return None
    pos += 1 + _NBSS_ENCODED_NAME_LEN + 1
    if len(data) < pos + 1 or data[pos] != _NBSS_ENCODED_NAME_LEN:
        return None
    pos += 1

    calling = _decode_netbios_session_name(data[pos : pos + _NBSS_ENCODED_NAME_LEN])
    if not calling or calling == _MSBROWSE_TOKEN:
        return None

    src_ip = pkt[IP].src
    if src_ip and src_ip != "0.0.0.0":
        return (src_ip, calling)
    return None


def extract_hostname_hints(pkt: Packet) -> list[tuple[str, str]]:
    """All (ip, hostname) hints found in this single packet."""
    hints = extract_dns_hostnames(pkt)
    for extractor in (
        extract_dhcp_hostname,
        extract_nbns_hostname,
        extract_nbt_datagram_hostname,
        extract_netbios_session_hostname,
    ):
        hint = extractor(pkt)
        if hint:
            hints.append(hint)
    return hints
