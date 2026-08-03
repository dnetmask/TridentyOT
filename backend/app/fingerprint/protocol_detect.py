"""Port- and banner-based protocol/service detection.

Covers common IT protocols as well as OT/ICS fieldbus and SCADA protocols,
since TridentyOT's primary use case is asset inventory on mixed IT/OT
networks. Detection is intentionally conservative: it is based on
well-known port numbers (fast, works on every packet) with an optional
payload-based override for a handful of protocols that are easy to
recognize from their first bytes (HTTP, TLS, SSH, FTP).
"""

from dataclasses import dataclass

IT = "IT"
OT = "OT"


@dataclass(frozen=True)
class ProtocolInfo:
    protocol: str
    category: str
    insecure: bool  # no built-in encryption and/or no authentication by default


# port -> ProtocolInfo. When both TCP and UDP use the same port for the
# same protocol we register it once and match regardless of transport.
_PORT_MAP: dict[int, ProtocolInfo] = {
    20: ProtocolInfo("ftp-data", IT, True),
    21: ProtocolInfo("ftp", IT, True),
    22: ProtocolInfo("ssh", IT, False),
    23: ProtocolInfo("telnet", IT, True),
    25: ProtocolInfo("smtp", IT, True),
    53: ProtocolInfo("dns", IT, False),
    67: ProtocolInfo("dhcp", IT, False),
    68: ProtocolInfo("dhcp", IT, False),
    69: ProtocolInfo("tftp", IT, True),
    80: ProtocolInfo("http", IT, True),
    102: ProtocolInfo("s7comm", OT, True),
    110: ProtocolInfo("pop3", IT, True),
    111: ProtocolInfo("rpcbind", IT, True),
    123: ProtocolInfo("ntp", IT, False),
    135: ProtocolInfo("msrpc", IT, True),
    137: ProtocolInfo("netbios-ns", IT, True),
    138: ProtocolInfo("netbios-dgm", IT, True),
    139: ProtocolInfo("netbios-ssn", IT, True),
    143: ProtocolInfo("imap", IT, True),
    161: ProtocolInfo("snmp", IT, True),
    162: ProtocolInfo("snmp-trap", IT, True),
    389: ProtocolInfo("ldap", IT, True),
    443: ProtocolInfo("https", IT, False),
    445: ProtocolInfo("smb", IT, True),
    502: ProtocolInfo("modbus", OT, True),
    512: ProtocolInfo("rexec", IT, True),
    513: ProtocolInfo("rlogin", IT, True),
    514: ProtocolInfo("rsh-syslog", IT, True),
    993: ProtocolInfo("imaps", IT, False),
    995: ProtocolInfo("pop3s", IT, False),
    1433: ProtocolInfo("mssql", IT, False),
    1521: ProtocolInfo("oracle-db", IT, False),
    1883: ProtocolInfo("mqtt", IT, True),
    1911: ProtocolInfo("niagara-fox", OT, True),
    1962: ProtocolInfo("pcworx", OT, True),
    2222: ProtocolInfo("ethernet-ip-io", OT, True),
    2404: ProtocolInfo("iec-104", OT, True),
    2049: ProtocolInfo("nfs", IT, True),
    3306: ProtocolInfo("mysql", IT, False),
    3389: ProtocolInfo("rdp", IT, False),
    4840: ProtocolInfo("opcua", OT, False),
    4911: ProtocolInfo("niagara-fox", OT, True),
    5006: ProtocolInfo("niagara-web", OT, True),
    5094: ProtocolInfo("hart-ip", OT, True),
    5432: ProtocolInfo("postgresql", IT, False),
    5900: ProtocolInfo("vnc", IT, True),
    8080: ProtocolInfo("http-alt", IT, True),
    9600: ProtocolInfo("omron-fins", OT, True),
    20000: ProtocolInfo("dnp3", OT, True),
    44818: ProtocolInfo("ethernet-ip", OT, True),
    47808: ProtocolInfo("bacnet", OT, True),
}

# PROFINET runs its real-time I/O traffic raw over Ethernet (EtherType
# 0x8892 -- see app.capture.packet_processor), so there's no port to key
# it by like everything in _PORT_MAP above. Named here (not just inline
# strings in packet_processor.py) so both that module and the OT_PROTOCOLS/
# INSECURE_PROTOCOL_NAMES membership below share one source of truth.
PNIO_PS = "pnio_ps"  # cyclic real-time I/O data -- the bulk of traffic on a running line
PN_DCP = "pn-dcp"  # discovery/configuration (device identify, name, IP assignment)
PN_ALARM = "pn-alarm"
PROFINET_OTHER = "profinet"
_PROFINET_PROTOCOL_NAMES = frozenset((PNIO_PS, PN_DCP, PN_ALARM, PROFINET_OTHER))

OT_PROTOCOLS = (
    frozenset(info.protocol for info in _PORT_MAP.values() if info.category == OT) | _PROFINET_PROTOCOL_NAMES
)
INSECURE_PROTOCOL_NAMES = (
    frozenset(info.protocol for info in _PORT_MAP.values() if info.insecure) | _PROFINET_PROTOCOL_NAMES
)


def detect_by_port(port: int) -> ProtocolInfo | None:
    return _PORT_MAP.get(port)


def detect_by_payload(payload: bytes) -> ProtocolInfo | None:
    if not payload:
        return None

    head = payload[:16]

    if head[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ") or head[:8] == b"HTTP/1.1" or head[:8] == b"HTTP/1.0":
        return ProtocolInfo("http", IT, True)

    if head.startswith(b"SSH-"):
        return ProtocolInfo("ssh", IT, False)

    if head.startswith(b"220 ") or head.startswith(b"220-"):
        return ProtocolInfo("ftp", IT, True)

    if len(head) >= 3 and head[0] == 0x16 and head[1] == 0x03:
        return ProtocolInfo("tls", IT, False)

    return None


def classify(port: int | None, payload: bytes | None = None) -> ProtocolInfo:
    """Best-effort protocol classification for a single flow endpoint."""
    if payload:
        by_payload = detect_by_payload(payload)
        if by_payload is not None:
            return by_payload

    if port is not None:
        by_port = detect_by_port(port)
        if by_port is not None:
            return by_port

    return ProtocolInfo("unknown", IT, False)
