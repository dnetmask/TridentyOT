"""Device-type classification (PC / servidor / PLC / HMI / equipo de red /
otro) from evidence the rest of the passive pipeline already collects --
protocols served, OS fingerprint, vendor, and hostname. Rule-based and
explainable, same spirit as os_fingerprint.py's signature scoring: each
rule casts a weighted vote for one type, the highest-scoring type wins,
and the evidence that produced it is kept for display.

This is inherently probabilistic from purely passive data alone -- a
Windows Server and a Windows workstation have an identical TCP/IP
fingerprint, so telling them apart with certainty needs an active query
(SNMP sysDescr, WMI), a separate, later piece of work. What this does get
right with high confidence today is the OT side: a device serving
Modbus/S7comm/EtherNet-IP from an embedded stack *is* a PLC/RTU, while
the same protocol served from a real Windows/Linux TCP/IP stack is
software (HMI/SCADA/engineering tooling), not the embedded controller
itself. Network infrastructure is confirmed via CDP/LLDP -- the IT split
(server vs. workstation) is a best-effort evidence-based guess, not a
certainty.
"""

from dataclasses import dataclass, field

PLC = "plc"
HMI = "hmi"
SERVER = "server"
WORKSTATION = "workstation"
NETWORK_DEVICE = "network_device"
OTHER = "other"

LABELS = {
    PLC: "PLC",
    HMI: "HMI",
    SERVER: "Servidor/VM",
    WORKSTATION: "PC",
    NETWORK_DEVICE: "Equipo de red",
    OTHER: "Otro",
}

# Subcategory for NETWORK_DEVICE rows only -- a second, independent
# classification field (see Device.device_type_secondary/custom_device_type_secondary).
# ROUTER_NAT is the only one ever auto-detected today (see
# inventory_service.apply_gateway_detection); the rest are manual-only
# until there's a reliable passive signal for them.
SWITCH_L2 = "switch_l2"
SWITCH_L3 = "switch_l3"
FIREWALL = "firewall"
ACCESS_POINT = "access_point"
ROUTER_NAT = "router_nat"

NETWORK_DEVICE_SUBTYPES = (SWITCH_L2, SWITCH_L3, FIREWALL, ACCESS_POINT, ROUTER_NAT)

# Subcategory for OTHER rows -- same idea as NETWORK_DEVICE_SUBTYPES above,
# just for the OTHER bucket. TRANSPORT_CONTROLLER is auto-detected from
# vendor (see _vendor_category / "Industrial Software Co").
TRANSPORT_CONTROLLER = "transport_controller"

OTHER_SUBTYPES = (TRANSPORT_CONTROLLER,)

SUBTYPE_LABELS = {
    SWITCH_L2: "Switch L2",
    SWITCH_L3: "Switch L3",
    FIREWALL: "Firewall",
    ACCESS_POINT: "Access Point",
    ROUTER_NAT: "Router/NAT",
    TRANSPORT_CONTROLLER: "Controlador de transporte",
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
    "dell", "microsoft", "lenovo", "hewlett-packard", "hewlett packard",
    "intel corporate", "apple", "supermicro",
)
# A VMware-registered MAC prefix is a virtual NIC -- VMware doesn't make
# workstations, so unlike the ambiguous IT keywords above this is a
# confident, direct vote for SERVER (a VM), not a 50/50 split.
_VIRTUALIZATION_VENDOR_KEYWORDS = ("vmware",)
# Weintek only makes HMI touch panels -- an unambiguous, direct vendor vote,
# same spirit as the VMware rule above.
_HMI_VENDOR_KEYWORDS = ("weintek",)
# "Industrial Software Co" is the OUI registrant string used by transport/
# logistics controller boards seen in this product's own test captures --
# not a PLC/HMI vendor, so it votes OTHER with a specific subtype rather
# than falling through to the zero-score OTHER fallback.
_TRANSPORT_CONTROLLER_VENDOR_KEYWORDS = ("industrial software co",)

# Substring match against the device's own (lowercased) hostname. A site's
# naming convention is a strong hint when it exists (e.g. this product's
# own test capture: "K787395-HMI01") but never authoritative alone --
# someone can name a PC "server-old" -- so these votes are moderate, not
# maximal, and always combined with other evidence.
_HMI_HOSTNAME_KEYWORDS = ("hmi",)
_PLC_HOSTNAME_KEYWORDS = ("plc", "rtu", "scada", "-ied", "controller")
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
    device_type_secondary: str | None = None


def _vendor_category(vendor: str | None) -> str | None:
    if not vendor:
        return None
    v = vendor.lower()
    if any(k in v for k in _INDUSTRIAL_VENDOR_KEYWORDS):
        return PLC
    if any(k in v for k in _HMI_VENDOR_KEYWORDS):
        return HMI
    if any(k in v for k in _NETWORK_VENDOR_KEYWORDS):
        return NETWORK_DEVICE
    if any(k in v for k in _VIRTUALIZATION_VENDOR_KEYWORDS):
        return SERVER
    if any(k in v for k in _TRANSPORT_CONTROLLER_VENDOR_KEYWORDS):
        return OTHER
    if any(k in v for k in _IT_VENDOR_KEYWORDS):
        return "it"  # ambiguous between server/workstation on its own
    return None


def _hostname_category(hostname: str | None) -> str | None:
    if not hostname:
        return None
    h = hostname.lower()
    if any(k in h for k in _HMI_HOSTNAME_KEYWORDS):
        return HMI
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
    scores = {PLC: 0.0, HMI: 0.0, SERVER: 0.0, WORKSTATION: 0.0, NETWORK_DEVICE: 0.0, OTHER: 0.0}
    evidence: list[str] = []
    subtype_hint: str | None = None

    if os_signature == "cdp_lldp_announcement":
        scores[NETWORK_DEVICE] += 3.0
        evidence.append("Se anuncia activamente como switch/router (CDP/LLDP)")

    if has_ot_server_protocol:
        # A device serving Modbus/S7comm/... from a general-purpose OS is
        # software (SCADA/HMI, or engineering tooling) using that OS's real
        # TCP/IP stack -- not an embedded PLC, which wouldn't fingerprint
        # as Windows/Linux in the first place.
        if os_signature in ("windows", "linux"):
            scores[HMI] += 3.0
            evidence.append(
                "Sirve un protocolo industrial pero corre en un SO de propósito general "
                "(Windows/Linux) -- HMI/estación SCADA, no un PLC embebido"
            )
        else:
            scores[PLC] += 3.0
            evidence.append("Sirve un protocolo industrial (Modbus/S7comm/EtherNet-IP/DNP3/...)")

    vendor_cat = _vendor_category(vendor)
    if vendor_cat == PLC:
        scores[PLC] += 2.0
        evidence.append(f'Fabricante industrial ("{vendor}")')
    elif vendor_cat == NETWORK_DEVICE:
        scores[NETWORK_DEVICE] += 2.0
        evidence.append(f'Fabricante de redes ("{vendor}")')
    elif vendor_cat == HMI:
        scores[HMI] += 2.0
        evidence.append(f'Fabricante de HMI ("{vendor}")')
    elif vendor_cat == SERVER:
        scores[SERVER] += 2.0
        evidence.append(f'Fabricante de virtualización ("{vendor}") -- interfaz de máquina virtual')
    elif vendor_cat == OTHER:
        scores[OTHER] += 2.0
        subtype_hint = TRANSPORT_CONTROLLER
        evidence.append(f'Fabricante de controladores de transporte ("{vendor}")')
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
    if host_cat == HMI:
        scores[HMI] += 2.5
        evidence.append(f'Nombre sugiere HMI ("{hostname}")')
    elif host_cat == PLC:
        scores[PLC] += 2.5
        evidence.append(f'Nombre sugiere PLC/RTU ("{hostname}")')
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
    secondary = subtype_hint if best_type == OTHER else None
    return DeviceTypeGuess(
        device_type=best_type, confidence=confidence, evidence=evidence, device_type_secondary=secondary
    )
