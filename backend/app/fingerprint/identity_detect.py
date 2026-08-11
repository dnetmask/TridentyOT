"""Best-effort device *identity* discovery from protocol traffic already
being processed for inventory purposes -- no active probes are ever sent.
Every extractor here reads a field a device already puts on the wire as
part of normal operation (or, for EtherNet/IP List Identity, a reply to a
discovery broadcast some other tool on the network already issued): this
module only ever reads bytes already present in the capture.

Two protocols self-report an explicit device *type*, authoritative enough
to override device_classifier.py's generic vendor/hostname/protocol-count
scoring outright -- same "direct-set, bypass the scorer" pattern already
used for gateway/NAT detection (see apply_identity_hints in
inventory_service.py):

- EtherNet/IP (CIP) List Identity reply: every EtherNet/IP device carries
  an ODVA-standardized Identity object whose deviceType is one of a fixed,
  public enum (scapy.contrib.enipTCP._deviceTypeList). Only the
  unambiguous entries ("Human-Machine Interface", "Programmable Logic
  Controller", "Managed Ethernet Switch") are mapped onto this app's own
  type list -- the rest (drives, sensors, safety I/O, ...) don't have a
  good 1:1 mapping here, so they're left unclassified; their self-reported
  productName is still captured as a hostname hint.
- Modbus Read Device Identification (function 0x2B/MEI 0x0E): a plain-text
  VendorName/ProductName/ModelName, no enum to translate.
- S7comm Read SZL: unlike the two above, there's no scapy contrib layer
  for S7comm, and getting the exact byte layout of every SZL record type
  right from memory is a real risk -- so rather than modeling the SZL
  structure field-by-field, this only regex-scans a *confirmed* S7comm
  Read-SZL response for a Siemens MLFB-style order code ("6ES7 315-2AH14-
  0AB0"). Lower-precision than the two above, but the order-code format is
  distinctive enough, and the protocol/port framing check narrow enough,
  that a false match is very unlikely.

CIP's vendorId and BACnet's vendorId are *numeric*, registry-assigned IDs,
not strings -- there is no complete, verified ID->company table bundled
here, so neither is ever translated into a vendor name (a wrong guess
would be worse than no guess). BACnet Who-Is/I-Am parsing below only
surfaces the raw device-instance/vendor-ID numbers as evidence text for a
human to look up, and never sets Device.vendor/hostname from them.
"""

import re
from dataclasses import dataclass

from scapy.layers.inet import TCP, UDP
from scapy.packet import Packet

from app.fingerprint.device_classifier import HMI, NETWORK_DEVICE, PLC
from app.i18n import bilingual, encode_i18n

try:
    from scapy.contrib.enipTCP import ENIPTCP, ENIPListIdentityItem, _deviceTypeList
except ImportError:  # pragma: no cover - scapy always ships this contrib layer
    ENIPTCP = ENIPListIdentityItem = None
    _deviceTypeList = {}

try:
    from scapy.contrib.modbus import (
        ModbusObjectId,
        ModbusPDU2B0EReadDeviceIdentificationResponse,
        ModbusPDU11ReportSlaveIdResponse,
    )
except ImportError:  # pragma: no cover - scapy always ships this contrib layer
    ModbusObjectId = ModbusPDU2B0EReadDeviceIdentificationResponse = ModbusPDU11ReportSlaveIdResponse = None

try:
    from scapy.layers.dhcp import DHCP
except ImportError:  # pragma: no cover - scapy always ships this layer
    DHCP = None

try:
    from scapy.layers.dns import DNS, DNSRR
except ImportError:  # pragma: no cover - scapy always ships this layer
    DNS = DNSRR = None


@dataclass
class IdentityHint:
    vendor: str | None = None
    # Self-reported product/model name -- routed through the same (ip,
    # hostname) hint channel as DNS/DHCP/NBNS (see packet_processor.py),
    # so it gets the same "rejected once claimed by 2+ IPs" protection.
    hostname: str | None = None
    # Manufacturer's model/reference for this device (e.g. an EtherNet/IP
    # productName, a Modbus ModelName, a Siemens S7comm order code) --
    # unlike hostname above, this is never routed through the
    # multi-claimant collision check: the same model legitimately repeats
    # across every identical unit on the network, so two devices sharing
    # one isn't evidence of a bad read the way two devices sharing one
    # hostname is.
    model: str | None = None
    # Self-reported firmware/software revision (e.g. EtherNet/IP's
    # Major.Minor Revision, Modbus's MajorMinorRevision object). Left None
    # for protocols that don't self-report it.
    firmware_version: str | None = None
    # Direct, maximal-confidence device_type/_secondary override -- only
    # set for the handful of protocols/values unambiguous enough to bypass
    # classify_device_type's generic scoring entirely.
    device_type: str | None = None
    device_type_secondary: str | None = None
    evidence: str = ""


def _decode(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value)


# ---------------------------------------------------------------------------
# EtherNet/IP (CIP) List Identity
# ---------------------------------------------------------------------------

_ENIP_PORT = 44818
_ENIP_LIST_IDENTITY_COMMAND = 0x63

_CIP_DEVICE_TYPE_MAP = {
    "Human-Machine Interface": (HMI, None),
    "Programmable Logic Controller": (PLC, None),
    "Managed Ethernet Switch": (NETWORK_DEVICE, None),
}


def extract_enip_identity(pkt: Packet) -> IdentityHint | None:
    """A List Identity reply is the ODVA-standardized CIP Identity object
    every EtherNet/IP device carries about itself. Not bound to UDP by
    scapy's own contrib module (only to TCP/44818), but the encapsulation
    header format is identical regardless of transport -- List Identity
    discovery is, in fact, normally broadcast over UDP -- so this parses
    the raw payload bytes directly rather than relying on layer binding.
    """
    if ENIPTCP is None:
        return None
    if pkt.haslayer(TCP):
        l4 = pkt[TCP]
    elif pkt.haslayer(UDP):
        l4 = pkt[UDP]
    else:
        return None
    if _ENIP_PORT not in (int(l4.sport), int(l4.dport)):
        return None

    raw = bytes(l4.payload)
    if len(raw) < 24:
        return None
    try:
        enip = ENIPTCP(raw)
        if int(enip.commandId) != _ENIP_LIST_IDENTITY_COMMAND or int(enip.status) != 0:
            return None
        items = getattr(enip.payload, "items", None) or []
        item = next((i for i in items if isinstance(i, ENIPListIdentityItem)), None)
        if item is None:
            return None
        device_type_name = _deviceTypeList.get(int(item.deviceType))
        product_name = _decode(item.productName).strip() if item.productName else None
        firmware_version = f"{int(item.revisionMajor)}.{int(item.revisionMinor)}"
    except Exception:
        return None

    mapped_type, mapped_secondary = _CIP_DEVICE_TYPE_MAP.get(device_type_name, (None, None))
    bits = [bilingual(es="Identidad EtherNet/IP (CIP)", en="EtherNet/IP (CIP) identity")]
    if device_type_name:
        bits.append(bilingual(es=f'tipo declarado "{device_type_name}"', en=f'declared type "{device_type_name}"'))
    if product_name:
        bits.append(bilingual(es=f'producto "{product_name}"', en=f'product "{product_name}"'))
    bits.append(bilingual(es=f"revisión {firmware_version}", en=f"revision {firmware_version}"))
    return IdentityHint(
        hostname=product_name or None,
        # The CIP Identity object's productName doubles as this app's
        # "model" field for EtherNet/IP devices -- for this protocol the
        # two concepts are the same string (e.g. "1756-L83E" is both the
        # vendor's model designation and the only name the device gives
        # itself), unlike a DNS/DHCP hostname a site chose independently.
        model=product_name or None,
        firmware_version=firmware_version,
        device_type=mapped_type,
        device_type_secondary=mapped_secondary,
        evidence=encode_i18n(*bits),
    )


# ---------------------------------------------------------------------------
# Modbus Read Device Identification (function 0x2B / MEI 0x0E)
# ---------------------------------------------------------------------------

_MODBUS_VENDOR_NAME = 0x00
_MODBUS_PRODUCT_CODE = 0x01
_MODBUS_MAJOR_MINOR_REVISION = 0x02
_MODBUS_PRODUCT_NAME = 0x04
_MODBUS_MODEL_NAME = 0x05


def extract_modbus_identity(pkt: Packet) -> IdentityHint | None:
    """The response chains one ModbusObjectId packet per requested field as
    nested .payload -- not a PacketListField, so this walks the chain by
    hand. guess_payload_class always returns ModbusObjectId regardless of
    remaining bytes, but once the bytes run out scapy's own dissection
    naturally terminates the chain with a non-ModbusObjectId payload
    (Padding/NoPayload), so a plain isinstance check is enough to stop.
    """
    if ModbusPDU2B0EReadDeviceIdentificationResponse is None:
        return None
    if not pkt.haslayer(ModbusPDU2B0EReadDeviceIdentificationResponse):
        return None

    objects: dict[int, str] = {}
    node = pkt[ModbusPDU2B0EReadDeviceIdentificationResponse].payload
    seen = 0
    while isinstance(node, ModbusObjectId) and seen < 32:
        value = _decode(node.value).strip()
        if value:
            objects[int(node.id)] = value
        node = node.payload
        seen += 1

    vendor = objects.get(_MODBUS_VENDOR_NAME)
    product = objects.get(_MODBUS_PRODUCT_NAME) or objects.get(_MODBUS_MODEL_NAME)
    # ModelName (0x05) is the spec's own "model" object -- preferred over
    # ProductCode (0x01), a vendor-internal catalog number with no bundled
    # registry to make sense of on its own (same caveat as CIP's
    # productCode/BACnet's vendor-id: never guessed at, only ever surfaced
    # verbatim).
    model = objects.get(_MODBUS_MODEL_NAME) or objects.get(_MODBUS_PRODUCT_CODE)
    firmware_version = objects.get(_MODBUS_MAJOR_MINOR_REVISION)
    if not vendor and not product and not model and not firmware_version:
        return None

    bits = [
        bilingual(
            es="Identificación de dispositivo Modbus (función 0x2B/0x0E)",
            en="Modbus device identification (function 0x2B/0x0E)",
        )
    ]
    if vendor:
        bits.append(bilingual(es=f'fabricante "{vendor}"', en=f'vendor "{vendor}"'))
    if product:
        bits.append(bilingual(es=f'producto "{product}"', en=f'product "{product}"'))
    if model:
        bits.append(bilingual(es=f'modelo "{model}"', en=f'model "{model}"'))
    if firmware_version:
        bits.append(bilingual(es=f'revisión "{firmware_version}"', en=f'revision "{firmware_version}"'))
    return IdentityHint(
        vendor=vendor,
        hostname=product,
        model=model,
        firmware_version=firmware_version,
        evidence=encode_i18n(*bits),
    )


def extract_modbus_legacy_slave_id(pkt: Packet) -> IdentityHint | None:
    """Function 0x11 (Report Slave ID) predates the standardized 0x2B/0x0E
    request above and has no fixed sub-fields -- slaveId is a single,
    vendor-defined free-text string -- so it's only ever used as a
    hostname-ish label, never parsed further, and only as a fallback when
    the modern request isn't present."""
    if ModbusPDU11ReportSlaveIdResponse is None:
        return None
    if not pkt.haslayer(ModbusPDU11ReportSlaveIdResponse):
        return None
    if pkt.haslayer(ModbusPDU2B0EReadDeviceIdentificationResponse):
        return None

    raw = _decode(pkt[ModbusPDU11ReportSlaveIdResponse].slaveId).strip().strip("\x00").strip()
    if not raw:
        return None
    return IdentityHint(
        hostname=raw,
        evidence=encode_i18n(
            bilingual(
                es=f'Identificación de dispositivo Modbus (Report Slave ID): "{raw}"',
                en=f'Modbus device identification (Report Slave ID): "{raw}"',
            )
        ),
    )


# ---------------------------------------------------------------------------
# DHCP Option 60 (Vendor Class Identifier)
# ---------------------------------------------------------------------------


def extract_dhcp_vendor_class(pkt: Packet) -> IdentityHint | None:
    if DHCP is None or not pkt.haslayer(DHCP):
        return None
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == "vendor_class_id":
            vendor_class = _decode(opt[1]).strip()
            if vendor_class:
                return IdentityHint(
                    vendor=vendor_class,
                    evidence=encode_i18n(
                        bilingual(
                            es=f'DHCP Vendor Class Identifier (opción 60): "{vendor_class}"',
                            en=f'DHCP Vendor Class Identifier (option 60): "{vendor_class}"',
                        )
                    ),
                )
    return None


# ---------------------------------------------------------------------------
# HTTP Server header / page <title>
# ---------------------------------------------------------------------------

_HTTP_SERVER_RE = re.compile(rb"(?im)^Server:[ \t]*(.+?)[ \t]*\r?$")
_HTML_TITLE_RE = re.compile(rb"(?is)<title[^>]*>(.*?)</title>")
_WHITESPACE_RE = re.compile(r"\s+")


def extract_http_identity(pkt: Packet) -> IdentityHint | None:
    if not pkt.haslayer(TCP):
        return None
    data = bytes(pkt[TCP].payload)
    if not data.startswith(b"HTTP/1."):
        return None

    header_end = data.find(b"\r\n\r\n")
    headers = data[:header_end] if header_end != -1 else data
    server_match = _HTTP_SERVER_RE.search(headers)
    server = _decode(server_match.group(1)).strip() if server_match else None

    title_match = _HTML_TITLE_RE.search(data)
    title = _WHITESPACE_RE.sub(" ", _decode(title_match.group(1))).strip() if title_match else None

    if not server and not title:
        return None
    bits = []
    if server:
        bits.append(bilingual(es=f'encabezado HTTP Server: "{server}"', en=f'HTTP Server header: "{server}"'))
    if title:
        bits.append(bilingual(es=f'título de página: "{title}"', en=f'page title: "{title}"'))
    return IdentityHint(vendor=server or None, hostname=title or None, evidence=encode_i18n(*bits))


# ---------------------------------------------------------------------------
# SSDP/UPnP (M-SEARCH / NOTIFY)
# ---------------------------------------------------------------------------

_SSDP_PORT = 1900


def extract_ssdp_identity(pkt: Packet) -> IdentityHint | None:
    if not pkt.haslayer(UDP):
        return None
    udp = pkt[UDP]
    if _SSDP_PORT not in (int(udp.sport), int(udp.dport)):
        return None
    data = bytes(udp.payload)
    if not (data.startswith(b"NOTIFY") or data.startswith(b"M-SEARCH") or data.startswith(b"HTTP/1.1 200")):
        return None
    server_match = _HTTP_SERVER_RE.search(data)
    if not server_match:
        return None
    server = _decode(server_match.group(1)).strip()
    if not server:
        return None
    return IdentityHint(
        vendor=server,
        evidence=encode_i18n(
            bilingual(es=f'SSDP/UPnP encabezado Server: "{server}"', en=f'SSDP/UPnP Server header: "{server}"')
        ),
    )


# ---------------------------------------------------------------------------
# mDNS TXT records
# ---------------------------------------------------------------------------

_MDNS_PORT = 5353
_DNS_TXT_TYPE = 16


def _parse_txt_strings(raw: bytes) -> list[str]:
    strings = []
    i = 0
    while i < len(raw):
        length = raw[i]
        i += 1
        if length == 0 or i + length > len(raw):
            break
        strings.append(raw[i : i + length].decode("utf-8", errors="ignore"))
        i += length
    return strings


def extract_mdns_txt_identity(pkt: Packet) -> IdentityHint | None:
    """Best-effort: mDNS/Bonjour TXT records have no single universal key
    for "model"/"vendor" across every device class, so this only looks for
    the handful of conventional keys ("md"/"model" for a product model,
    "manufacturer"/"vendor"/"usb_mfg" for the maker) and ignores the rest."""
    if DNS is None or not pkt.haslayer(DNS) or not pkt.haslayer(UDP):
        return None
    if _MDNS_PORT not in (int(pkt[UDP].sport), int(pkt[UDP].dport)):
        return None
    dns = pkt[DNS]
    if dns.qr != 1 or not dns.an:
        return None

    for rr in dns.an:
        if not isinstance(rr, DNSRR) or rr.type != _DNS_TXT_TYPE:
            continue
        rdata = rr.rdata
        blob = b"".join(rdata) if isinstance(rdata, list) else rdata if isinstance(rdata, bytes) else None
        if not blob:
            continue
        pairs: dict[str, str] = {}
        for s in _parse_txt_strings(blob):
            if "=" in s:
                key, _, value = s.partition("=")
                pairs[key.strip().lower()] = value.strip()
        model = pairs.get("md") or pairs.get("model")
        vendor = pairs.get("manufacturer") or pairs.get("vendor") or pairs.get("usb_mfg")
        if not model and not vendor:
            continue
        bits = [bilingual(es="mDNS TXT", en="mDNS TXT")]
        if vendor:
            bits.append(bilingual(es=f'fabricante "{vendor}"', en=f'vendor "{vendor}"'))
        if model:
            bits.append(bilingual(es=f'modelo "{model}"', en=f'model "{model}"'))
        return IdentityHint(
            vendor=vendor or None, hostname=model or None, model=model or None, evidence=encode_i18n(*bits)
        )
    return None


# ---------------------------------------------------------------------------
# S7comm Read SZL (best-effort -- see module docstring)
# ---------------------------------------------------------------------------

_S7COMM_PORT = 102
# Siemens' own MLFB order-code scheme, e.g. "6ES7 315-2AH14-0AB0" or
# "6GK7 343-1EX30-0XE0" -- deliberately loose on the exact digit/letter
# counts per product family (verified case-by-case, not from one fixed
# spec table), tightened instead by requiring the two dashes that make
# this pattern distinctive in the first place.
_SIEMENS_ORDER_CODE_RE = re.compile(rb"6[A-Z]{2}\d\s?[0-9]{2,4}-[0-9][A-Z0-9]{2,4}-[0-9][A-Z0-9]{2,4}")


def extract_s7comm_identity(pkt: Packet) -> IdentityHint | None:
    """No scapy contrib layer exists for S7comm. Rather than hand-modeling
    the exact byte layout of every SZL record type (real risk of an
    off-by-one from memory), this only confirms the stable, well-documented
    outer framing (TPKT + COTP DT + S7 header, response/userdata rosctr)
    and then regex-scans the payload for a Siemens order code -- lower
    precision than a structured field parse, but the framing check plus
    the order code's distinctive format make a false match very unlikely.
    """
    if not pkt.haslayer(TCP):
        return None
    tcp = pkt[TCP]
    if _S7COMM_PORT not in (int(tcp.sport), int(tcp.dport)):
        return None
    data = bytes(tcp.payload)
    if len(data) < 11 or data[0] != 0x03 or data[1] != 0x00:
        return None  # not a TPKT header (version 3, reserved 0)

    cotp_li = data[4]
    s7_offset = 5 + cotp_li
    if len(data) <= s7_offset or data[s7_offset] != 0x32:
        return None  # not an S7comm PDU (protocol id 0x32)

    rosctr = data[s7_offset + 1]
    if rosctr not in (3, 7):  # Ack-Data or Userdata -- what an SZL reply uses
        return None

    match = _SIEMENS_ORDER_CODE_RE.search(data[s7_offset:])
    if not match:
        return None
    order_code = _decode(match.group(0)).strip()
    return IdentityHint(
        vendor="Siemens AG",
        hostname=order_code,
        # The MLFB order code is Siemens' own catalog reference for this
        # exact product (e.g. "6ES7 315-2AH14-0AB0") -- a model designation,
        # not a site-chosen name, so it also populates the model field.
        model=order_code,
        device_type=PLC,
        evidence=encode_i18n(
            bilingual(
                es=f'S7comm: código de referencia Siemens en respuesta SZL: "{order_code}"',
                en=f'S7comm: Siemens order code in SZL response: "{order_code}"',
            )
        ),
    )


# ---------------------------------------------------------------------------
# BACnet Who-Is/I-Am (best-effort -- see module docstring)
# ---------------------------------------------------------------------------

_BACNET_PORT = 47808
_BACNET_ORIGINAL_UNICAST_NPDU = 0x0A
_BACNET_ORIGINAL_BROADCAST_NPDU = 0x0B
_BACNET_UNCONFIRMED_REQUEST_PDU = 0x1
_BACNET_SERVICE_I_AM = 0x00
_BACNET_OBJECT_IDENTIFIER_TAG = 12
_BACNET_UNSIGNED_TAG = 2


def _bacnet_parse_application_tags(data: bytes) -> list[tuple[int, bytes]]:
    """Walks a BACnet application-tagged TLV sequence, yielding (tag_number,
    value_bytes). Only the short form (length 0-4, or one length-extension
    byte for 5-253) is handled -- more than enough for the small fixed-size
    fields I-Am carries; a malformed/unexpected tag just stops the walk
    rather than raising, since this is untrusted wire data."""
    tags = []
    i = 0
    while i < len(data):
        tag_byte = data[i]
        tag_number = (tag_byte >> 4) & 0x0F
        length = tag_byte & 0x07
        i += 1
        if length == 5:
            if i >= len(data):
                break
            length = data[i]
            i += 1
        if length > 4 or i + length > len(data):
            break
        tags.append((tag_number, data[i : i + length]))
        i += length
    return tags


def extract_bacnet_identity(pkt: Packet) -> IdentityHint | None:
    """Deliberately narrow: only handles a flat (non-routed) BACnet/IP
    segment, where the NPDU header is always exactly 2 bytes (version +
    control, no network-layer routing fields) -- overwhelmingly the common
    case for a single OT network segment. A control byte indicating
    routing fields are present is treated as "can't safely parse this"
    rather than guessed at.

    Never sets vendor/hostname: the vendor-id and device-instance numbers
    this decodes are only meaningful with a full BACnet vendor-ID registry
    (ASHRAE-maintained) this app doesn't bundle -- surfaced as evidence
    text only, for a human to look up.
    """
    if not pkt.haslayer(UDP):
        return None
    udp = pkt[UDP]
    if _BACNET_PORT not in (int(udp.sport), int(udp.dport)):
        return None
    data = bytes(udp.payload)
    if len(data) < 9 or data[0] != 0x81:
        return None  # not BVLC/BACnet-IP
    if data[1] not in (_BACNET_ORIGINAL_UNICAST_NPDU, _BACNET_ORIGINAL_BROADCAST_NPDU):
        return None

    npdu_control = data[5]
    if npdu_control != 0x00:
        return None  # routing fields present -- out of scope, bail out safely

    apdu = data[6:]
    if len(apdu) < 2:
        return None
    pdu_type = (apdu[0] >> 4) & 0x0F
    service_choice = apdu[1]
    if pdu_type != _BACNET_UNCONFIRMED_REQUEST_PDU or service_choice != _BACNET_SERVICE_I_AM:
        return None

    tags = _bacnet_parse_application_tags(apdu[2:])
    device_instance = None
    vendor_id = None
    for tag_number, value in tags:
        if tag_number == _BACNET_OBJECT_IDENTIFIER_TAG and len(value) == 4 and device_instance is None:
            device_instance = int.from_bytes(value, "big") & 0x3FFFFF
        elif tag_number == _BACNET_UNSIGNED_TAG and value:
            vendor_id = int.from_bytes(value, "big")

    if device_instance is None and vendor_id is None:
        return None
    bits = [bilingual(es="BACnet I-Am", en="BACnet I-Am")]
    if device_instance is not None:
        bits.append(bilingual(es=f"instancia de dispositivo {device_instance}", en=f"device instance {device_instance}"))
    if vendor_id is not None:
        bits.append(
            bilingual(
                es=f"ID de fabricante BACnet {vendor_id} (consultar el registro de fabricantes de ASHRAE)",
                en=f"BACnet vendor ID {vendor_id} (look up in ASHRAE's vendor registry)",
            )
        )
    return IdentityHint(evidence=encode_i18n(*bits))


_EXTRACTORS = (
    extract_enip_identity,
    extract_modbus_identity,
    extract_modbus_legacy_slave_id,
    extract_dhcp_vendor_class,
    extract_http_identity,
    extract_ssdp_identity,
    extract_mdns_txt_identity,
    extract_s7comm_identity,
    extract_bacnet_identity,
)


def extract_identity_hints(pkt: Packet) -> list[IdentityHint]:
    """All identity hints found in this single packet, describing *this
    packet's sender* -- never the destination. Each extractor is isolated:
    several of these hand-parse untrusted wire bytes, so one malformed
    packet tripping up a single extractor must never take the rest down
    with it."""
    hints = []
    for extractor in _EXTRACTORS:
        try:
            hint = extractor(pkt)
        except Exception:
            continue
        if hint:
            hints.append(hint)
    return hints
