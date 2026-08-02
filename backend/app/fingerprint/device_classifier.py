"""Device-type classification (PC / servidor / PLC / equipo de red / otro)
from evidence the rest of the passive pipeline already collects --
protocols served, OS fingerprint, vendor, and hostname. Rule-based and
explainable, same spirit as os_fingerprint.py's signature scoring: each
rule casts a weighted vote for one type, the highest-scoring type wins,
and the evidence that produced it is kept for display.

This is inherently probabilistic from purely passive data alone -- a
Windows Server and a Windows workstation have an identical TCP/IP
fingerprint, so telling them apart with certainty needs an active query
(SNMP sysDescr, WMI), a separate, later piece of work. What this does get
right with high confidence today is the OT side (a device serving
Modbus/S7comm/EtherNet-IP *is* a PLC/RTU) and network infrastructure
(already confirmed via CDP/LLDP) -- the IT split (server vs. workstation)
is a best-effort evidence-based guess, not a certainty.
"""

from dataclasses import dataclass, field

PLC = "plc"
SERVER = "server"
WORKSTATION = "workstation"
NETWORK_DEVICE = "network_device"
OTHER = "other"

LABELS = {
    PLC: "PLC",
    SERVER: "Servidor",
    WORKSTATION: "PC",
    NETWORK_DEVICE: "Equipo de red",
    OTHER: "Otro",
}

# Substring match against the OUI vendor string (already resolved by
# vendor_lookup.py) -- lowercased. Deliberately conservative: these are
# vendors that are overwhelmingly one category, not general electronics
# manufacturers who also happen to sell industrial gear.
_INDUSTRIAL_VENDOR_KEYWORDS = (
    "siemens", "rockwell", "allen-bradley", "allen bradley", "schneider",
    "phoenix contact", "abb ", "omron", "mitsubishi electric", "wago",
    "beckhoff", "festo", "honeywell", "yokogawa", "emerson", "ge fanuc",
    "pepperl", "turck", "endress",
)
_NETWORK_VENDOR_KEYWORDS = (
    "cisco", "juniper", "aruba", "ubiquiti", "mikrotik", "hirschmann",
    "netgear", "d-link", "tp-link", "fortinet", "extreme networks", "moxa", "advantech",
)
_IT_VENDOR_KEYWORDS = (
    "dell", "vmware", "microsoft", "lenovo", "hewlett-packard", "hewlett packard",
    "intel corporate", "apple", "supermicro",
)

# Substring match against the device's own (lowercased) hostname. A site's
# naming convention is a strong hint when it exists (e.g. this product's
# own test capture: "K787395-HMI01") but never authoritative alone --
# someone can name a PC "server-old" -- so these votes are moderate, not
# maximal, and always combined with other evidence.
_PLC_HOSTNAME_KEYWORDS = ("plc", "rtu", "scada", "hmi", "-ied", "controller")
_SERVER_HOSTNAME_KEYWORDS = ("srv", "server", "-dc", "sql", "svc", "vcenter", "esxi", "-dc0")
_WORKSTATION_HOSTNAME_KEYWORDS = ("wks", "workstation", "desktop", "laptop", "-pc")
_NETWORK_HOSTNAME_KEYWORDS = ("switch", "sw-", "-sw", "router", "rtr-", "firewall", "fw-", "core-")

# A device serving this many *distinct* protocols as a server is doing
# more than a single-purpose workstation or field device would.
_MANY_SERVER_PROTOCOLS_THRESHOLD = 4

# Score needed to fully saturate confidence to 1.0 -- roughly "one strong
# signal (3.0) plus one supporting one (1.0)", matching how the rules
# below are weighted.
_CONFIDENCE_SATURATION = 4.0


@dataclass
class DeviceTypeGuess:
    device_type: str
    confidence: float  # 0.0 - 1.0
    evidence: list[str] = field(default_factory=list)


def _vendor_category(vendor: str | None) -> str | None:
    if not vendor:
        return None
    v = vendor.lower()
    if any(k in v for k in _INDUSTRIAL_VENDOR_KEYWORDS):
        return PLC
    if any(k in v for k in _NETWORK_VENDOR_KEYWORDS):
        return NETWORK_DEVICE
    if any(k in v for k in _IT_VENDOR_KEYWORDS):
        return "it"  # ambiguous between server/workstation on its own
    return None


def _hostname_category(hostname: str | None) -> str | None:
    if not hostname:
        return None
    h = hostname.lower()
    if any(k in h for k in _PLC_HOSTNAME_KEYWORDS):
        return PLC
    if any(k in h for k in _NETWORK_HOSTNAME_KEYWORDS):
        return NETWORK_DEVICE
    if any(k in h for k in _SERVER_HOSTNAME_KEYWORDS):
        return SERVER
    if any(k in h for k in _WORKSTATION_HOSTNAME_KEYWORDS):
        return WORKSTATION
    return None


def classify_device_type(
    *,
    vendor: str | None,
    hostname: str | None,
    os_signature: str | None,
    has_ot_server_protocol: bool,
    server_protocol_count: int,
) -> DeviceTypeGuess:
    scores = {PLC: 0.0, SERVER: 0.0, WORKSTATION: 0.0, NETWORK_DEVICE: 0.0}
    evidence: list[str] = []

    if os_signature == "cdp_lldp_announcement":
        scores[NETWORK_DEVICE] += 3.0
        evidence.append("Se anuncia activamente como switch/router (CDP/LLDP)")

    if has_ot_server_protocol:
        scores[PLC] += 3.0
        evidence.append("Sirve un protocolo industrial (Modbus/S7comm/EtherNet-IP/DNP3/...)")

    vendor_cat = _vendor_category(vendor)
    if vendor_cat == PLC:
        scores[PLC] += 2.0
        evidence.append(f'Fabricante industrial ("{vendor}")')
    elif vendor_cat == NETWORK_DEVICE:
        scores[NETWORK_DEVICE] += 2.0
        evidence.append(f'Fabricante de redes ("{vendor}")')
    elif vendor_cat == "it":
        scores[SERVER] += 0.5
        scores[WORKSTATION] += 0.5
        evidence.append(f'Fabricante IT genérico ("{vendor}")')

    host_cat = _hostname_category(hostname)
    # Weighted slightly above a vendor-only match: a site's own naming
    # convention is a more specific, intentional statement about a
    # device's *role* than "who made its NIC" is -- e.g. a Siemens-made
    # industrial PC named "...-PC" is still better called a workstation
    # than a PLC, so a hostname match should win a tie against vendor alone.
    if host_cat == PLC:
        scores[PLC] += 2.5
        evidence.append(f'Nombre sugiere HMI/PLC/RTU ("{hostname}")')
    elif host_cat == SERVER:
        scores[SERVER] += 2.5
        evidence.append(f'Nombre sugiere servidor ("{hostname}")')
    elif host_cat == WORKSTATION:
        scores[WORKSTATION] += 2.5
        evidence.append(f'Nombre sugiere estación de trabajo ("{hostname}")')
    elif host_cat == NETWORK_DEVICE:
        scores[NETWORK_DEVICE] += 2.5
        evidence.append(f'Nombre sugiere equipo de red ("{hostname}")')

    if os_signature == "embedded_ot":
        scores[PLC] += 1.0
        evidence.append("Pila TCP/IP embebida, sin extensiones modernas (SACK/timestamps/wscale)")
    elif os_signature in ("windows", "linux", "bsd_macos"):
        if server_protocol_count >= _MANY_SERVER_PROTOCOLS_THRESHOLD:
            scores[SERVER] += 1.5
            evidence.append(f"Sirve {server_protocol_count} protocolos distintos (típico de servidor)")
        elif server_protocol_count == 0:
            scores[WORKSTATION] += 1.0
            evidence.append("Solo actúa como cliente, no expone servicios")

    best_type = max(scores, key=scores.get)
    best_score = scores[best_type]
    if best_score <= 0:
        return DeviceTypeGuess(device_type=OTHER, confidence=0.0, evidence=[])

    confidence = round(min(best_score / _CONFIDENCE_SATURATION, 1.0), 2)
    return DeviceTypeGuess(device_type=best_type, confidence=confidence, evidence=evidence)
