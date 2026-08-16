"""Device-type classification (PC / servidor / PLC / HMI / equipo de red /
otro) from evidence the rest of the passive pipeline already collects --
protocols served, OS fingerprint, vendor, self-reported model, and
hostname. Rule-based and explainable, same spirit as os_fingerprint.py's
signature scoring: each rule casts a weighted vote for one type, the
highest-scoring type wins, and the evidence that produced it is kept for
display.

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

from app.i18n import bilingual

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
    TRANSPORT_CONTROLLER: "Transportador",
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

# Substring match against the device's own self-reported product/platform
# string (Device.model -- CDP's Platform TLV, PROFINET DCP's "Type of
# Station" block, EtherNet/IP's product name, ...). More specific than a
# vendor-name match: "Siemens" alone can't tell a SCALANCE switch from a
# SIMATIC-PC engineering workstation from a real S7 PLC, but the product
# family name always can. This is what actually caught the bug that added
# this rule: a SIMATIC-PC (a Windows PC running TIA Portal, discovered via
# PROFINET DCP/a CDP neighbor announcement) was being classified as
# NETWORK_DEVICE on manufacturer alone -- see apply_neighbor_table's own
# fallback in topology_from_switch.py, which used to hardcode
# NETWORK_DEVICE for *any* unresolved CDP/LLDP neighbor regardless of what
# it actually was.
_WORKSTATION_MODEL_KEYWORDS = (
    "simatic-pc", "simatic ipc", "simatic industrial pc", "simatic field pg",
    "simatic rack pc", "simatic panel pc", "simatic microbox",
)
_PLC_MODEL_KEYWORDS = ("simatic s7-", "s7-1200", "s7-1500", "s7-300", "s7-400", "et 200", "et200", "logo!")
_NETWORK_MODEL_KEYWORDS = ("scalance", "ruggedcom")

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
    # Each item is a bilingual() dict -- see app.i18n -- ready to be passed
    # straight to encode_i18n() for storage in Device.device_type_evidence.
    evidence: list[dict] = field(default_factory=list)
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


def _model_category(model: str | None) -> str | None:
    if not model:
        return None
    m = model.lower()
    if any(k in m for k in _WORKSTATION_MODEL_KEYWORDS):
        return WORKSTATION
    if any(k in m for k in _PLC_MODEL_KEYWORDS):
        return PLC
    if any(k in m for k in _NETWORK_MODEL_KEYWORDS):
        return NETWORK_DEVICE
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
    model: str | None = None,
    os_signature: str | None,
    has_ot_server_protocol: bool,
    server_protocol_count: int,
) -> DeviceTypeGuess:
    scores = {PLC: 0.0, HMI: 0.0, SERVER: 0.0, WORKSTATION: 0.0, NETWORK_DEVICE: 0.0, OTHER: 0.0}
    evidence: list[dict] = []
    subtype_hint: str | None = None

    if os_signature == "cdp_lldp_announcement":
        scores[NETWORK_DEVICE] += 3.0
        evidence.append(
            bilingual(
                es="Se anuncia activamente como switch/router (CDP/LLDP)",
                en="Actively announces itself as a switch/router (CDP/LLDP)",
            )
        )

    if has_ot_server_protocol:
        # A device serving Modbus/S7comm/... from a general-purpose OS is
        # software (SCADA/HMI, or engineering tooling) using that OS's real
        # TCP/IP stack -- not an embedded PLC, which wouldn't fingerprint
        # as Windows/Linux in the first place.
        if os_signature in ("windows", "linux"):
            scores[HMI] += 3.0
            evidence.append(
                bilingual(
                    es="Sirve un protocolo industrial pero corre en un SO de propósito general "
                    "(Windows/Linux) -- HMI/estación SCADA, no un PLC embebido",
                    en="Serves an industrial protocol but runs on a general-purpose OS "
                    "(Windows/Linux) -- HMI/SCADA workstation, not an embedded PLC",
                )
            )
        else:
            scores[PLC] += 3.0
            evidence.append(
                bilingual(
                    es="Sirve un protocolo industrial (Modbus/S7comm/EtherNet-IP/DNP3/...)",
                    en="Serves an industrial protocol (Modbus/S7comm/EtherNet-IP/DNP3/...)",
                )
            )

    vendor_cat = _vendor_category(vendor)
    if vendor_cat == PLC:
        scores[PLC] += 2.0
        evidence.append(bilingual(es=f'Fabricante industrial ("{vendor}")', en=f'Industrial vendor ("{vendor}")'))
    elif vendor_cat == NETWORK_DEVICE:
        scores[NETWORK_DEVICE] += 2.0
        evidence.append(bilingual(es=f'Fabricante de redes ("{vendor}")', en=f'Networking vendor ("{vendor}")'))
    elif vendor_cat == HMI:
        scores[HMI] += 2.0
        evidence.append(bilingual(es=f'Fabricante de HMI ("{vendor}")', en=f'HMI vendor ("{vendor}")'))
    elif vendor_cat == SERVER:
        scores[SERVER] += 2.0
        evidence.append(
            bilingual(
                es=f'Fabricante de virtualización ("{vendor}") -- interfaz de máquina virtual',
                en=f'Virtualization vendor ("{vendor}") -- virtual machine NIC',
            )
        )
    elif vendor_cat == OTHER:
        scores[OTHER] += 2.0
        subtype_hint = TRANSPORT_CONTROLLER
        evidence.append(
            bilingual(es=f'Fabricante de transportadores ("{vendor}")', en=f'Conveyor/transport vendor ("{vendor}")')
        )
    elif vendor_cat == "it":
        scores[SERVER] += 0.5
        scores[WORKSTATION] += 0.5
        evidence.append(bilingual(es=f'Fabricante IT genérico ("{vendor}")', en=f'Generic IT vendor ("{vendor}")'))

    # Weighted slightly *above* the strongest direct signals above
    # (cdp_lldp_announcement/has_ot_server_protocol, both 3.0): a
    # self-reported product/platform string is a specific, direct
    # statement about *what this device is*, not just who made it or what
    # protocol it happened to be seen on -- e.g. it's what tells a
    # SIMATIC-PC (a PC that runs TIA Portal, so it *will* speak PROFINET
    # DCP) apart from a SCALANCE switch or an S7 PLC, three very different
    # device types neither a "Siemens" vendor match nor "serves an OT
    # protocol from a Windows/Linux host" (which alone would read as an
    # HMI/engineering-tooling guess) can tell apart on their own.
    model_cat = _model_category(model)
    if model_cat == WORKSTATION:
        scores[WORKSTATION] += 3.5
        evidence.append(
            bilingual(
                es=f'El modelo autoreportado ("{model}") es una PC industrial, no un PLC ni un equipo de red',
                en=f'The self-reported model ("{model}") is an industrial PC, not a PLC or network device',
            )
        )
    elif model_cat == PLC:
        scores[PLC] += 3.5
        evidence.append(
            bilingual(es=f'El modelo autoreportado ("{model}") es un PLC', en=f'The self-reported model ("{model}") is a PLC')
        )
    elif model_cat == NETWORK_DEVICE:
        scores[NETWORK_DEVICE] += 3.5
        evidence.append(
            bilingual(
                es=f'El modelo autoreportado ("{model}") es un equipo de red',
                en=f'The self-reported model ("{model}") is networking gear',
            )
        )

    host_cat = _hostname_category(hostname)
    # Weighted slightly above a vendor-only match: a site's own naming
    # convention is a more specific, intentional statement about a
    # device's *role* than "who made its NIC" is -- e.g. a Siemens-made
    # industrial PC named "...-PC" is still better called a workstation
    # than a PLC, so a hostname match should win a tie against vendor alone.
    if host_cat == HMI:
        scores[HMI] += 2.5
        evidence.append(bilingual(es=f'Nombre sugiere HMI ("{hostname}")', en=f'Hostname suggests HMI ("{hostname}")'))
    elif host_cat == PLC:
        scores[PLC] += 2.5
        evidence.append(
            bilingual(es=f'Nombre sugiere PLC/RTU ("{hostname}")', en=f'Hostname suggests PLC/RTU ("{hostname}")')
        )
    elif host_cat == SERVER:
        scores[SERVER] += 2.5
        evidence.append(
            bilingual(es=f'Nombre sugiere servidor ("{hostname}")', en=f'Hostname suggests server ("{hostname}")')
        )
    elif host_cat == WORKSTATION:
        scores[WORKSTATION] += 2.5
        evidence.append(
            bilingual(
                es=f'Nombre sugiere estación de trabajo ("{hostname}")',
                en=f'Hostname suggests workstation ("{hostname}")',
            )
        )
    elif host_cat == NETWORK_DEVICE:
        scores[NETWORK_DEVICE] += 2.5
        evidence.append(
            bilingual(
                es=f'Nombre sugiere equipo de red ("{hostname}")', en=f'Hostname suggests network device ("{hostname}")'
            )
        )

    if os_signature == "embedded_ot":
        scores[PLC] += 1.0
        evidence.append(
            bilingual(
                es="Pila TCP/IP embebida, sin extensiones modernas (SACK/timestamps/wscale)",
                en="Embedded TCP/IP stack, missing modern extensions (SACK/timestamps/wscale)",
            )
        )
    elif os_signature in ("windows", "linux", "bsd_macos"):
        if server_protocol_count >= _MANY_SERVER_PROTOCOLS_THRESHOLD:
            scores[SERVER] += 1.5
            evidence.append(
                bilingual(
                    es=f"Sirve {server_protocol_count} protocolos distintos (típico de servidor)",
                    en=f"Serves {server_protocol_count} distinct protocols (typical of a server)",
                )
            )
        elif server_protocol_count == 0:
            scores[WORKSTATION] += 1.0
            evidence.append(
                bilingual(es="Solo actúa como cliente, no expone servicios", en="Only acts as a client, exposes no services")
            )

    best_type = max(scores, key=scores.get)
    best_score = scores[best_type]
    if best_score <= 0:
        return DeviceTypeGuess(device_type=OTHER, confidence=0.0, evidence=[])

    confidence = round(min(best_score / _CONFIDENCE_SATURATION, 1.0), 2)
    secondary = subtype_hint if best_type == OTHER else None
    return DeviceTypeGuess(
        device_type=best_type, confidence=confidence, evidence=evidence, device_type_secondary=secondary
    )
