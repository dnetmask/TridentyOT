from scapy.contrib.enipTCP import ENIPTCP, ENIPListIdentity, ENIPListIdentityItem
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from app.fingerprint.identity_detect import (
    extract_bacnet_identity,
    extract_dhcp_vendor_class,
    extract_enip_identity,
    extract_http_identity,
    extract_identity_hints,
    extract_mdns_txt_identity,
    extract_modbus_identity,
    extract_modbus_legacy_slave_id,
    extract_s7comm_identity,
    extract_ssdp_identity,
)


def _redissect(pkt):
    """Forces a full binary re-dissection, same pattern used throughout
    test_packet_processor.py -- otherwise a packet built from constructor
    kwargs doesn't necessarily round-trip through the same byte-level
    parsing a real captured/loaded packet would."""
    return Ether(bytes(pkt))


def _modbus_object(object_id: int, value: str) -> bytes:
    return bytes([object_id, len(value)]) + value.encode()


def test_enip_list_identity_maps_hmi_device_type():
    item = ENIPListIdentityItem(
        itemTypeCode=0x0C,
        protocolVersion=1,
        sinFamily=2,
        sinPort=44818,
        sinAddress="10.0.0.9",
        vendorId=1,
        deviceType=0x18,  # Human-Machine Interface
        productCode=100,
        revisionMajor=1,
        revisionMinor=2,
        serialNumber=0x1234ABCD,
        productNameLength=len("MyHMI-9000"),
        productName="MyHMI-9000",
        state=0,
    )
    enip = ENIPTCP(commandId=0x63, status=0) / ENIPListIdentity(itemCount=1, items=[item])
    pkt = _redissect(Ether() / IP(src="10.0.0.9", dst="10.0.0.2") / TCP(sport=44818, dport=51000) / enip)

    hint = extract_enip_identity(pkt)
    assert hint is not None
    assert hint.device_type == "hmi"
    assert hint.hostname == "MyHMI-9000"
    assert "Human-Machine Interface" in hint.evidence


def test_enip_list_identity_maps_plc_device_type():
    item = ENIPListIdentityItem(
        itemTypeCode=0x0C,
        sinFamily=2,
        sinPort=44818,
        sinAddress="10.0.0.9",
        vendorId=1,
        deviceType=0x0E,  # Programmable Logic Controller
        productNameLength=len("1756-L83E"),
        productName="1756-L83E",
    )
    enip = ENIPTCP(commandId=0x63, status=0) / ENIPListIdentity(itemCount=1, items=[item])
    pkt = _redissect(Ether() / IP(src="10.0.0.9", dst="10.0.0.2") / TCP(sport=44818, dport=51000) / enip)

    hint = extract_enip_identity(pkt)
    assert hint is not None
    assert hint.device_type == "plc"
    assert hint.hostname == "1756-L83E"


def test_enip_list_identity_unmapped_device_type_still_yields_product_hostname():
    item = ENIPListIdentityItem(
        itemTypeCode=0x0C,
        sinFamily=2,
        sinPort=44818,
        sinAddress="10.0.0.9",
        vendorId=1,
        deviceType=0x0005,  # Inductive Proximity Switch -- no 1:1 mapping
        productNameLength=len("PXN-100"),
        productName="PXN-100",
    )
    enip = ENIPTCP(commandId=0x63, status=0) / ENIPListIdentity(itemCount=1, items=[item])
    pkt = _redissect(Ether() / IP(src="10.0.0.9", dst="10.0.0.2") / TCP(sport=44818, dport=51000) / enip)

    hint = extract_enip_identity(pkt)
    assert hint is not None
    assert hint.device_type is None
    assert hint.hostname == "PXN-100"


def test_enip_ignores_non_list_identity_commands():
    enip = ENIPTCP(commandId=0x65, status=0)  # RegisterSession
    pkt = _redissect(Ether() / IP(src="10.0.0.9", dst="10.0.0.2") / TCP(sport=44818, dport=51000) / enip)
    assert extract_enip_identity(pkt) is None


def test_modbus_read_device_identification_extracts_vendor_and_product():
    payload = bytes([0x2B, 0x0E, 0x0E, 0x83, 0x00, 0x00, 2])
    payload += _modbus_object(0x00, "Acme Corp") + _modbus_object(0x04, "Widget-9000")
    adu = bytes([0, 1, 0, 0, 0, len(payload) + 1, 0xFF]) + payload
    pkt = _redissect(Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=502, dport=51000) / adu)

    hint = extract_modbus_identity(pkt)
    assert hint is not None
    assert hint.vendor == "Acme Corp"
    assert hint.hostname == "Widget-9000"
    assert hint.device_type is None


def test_modbus_read_device_identification_falls_back_to_model_name():
    payload = bytes([0x2B, 0x0E, 0x0E, 0x83, 0x00, 0x00, 1])
    payload += _modbus_object(0x05, "Model-X")  # ModelName only, no ProductName
    adu = bytes([0, 1, 0, 0, 0, len(payload) + 1, 0xFF]) + payload
    pkt = _redissect(Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=502, dport=51000) / adu)

    hint = extract_modbus_identity(pkt)
    assert hint is not None
    assert hint.hostname == "Model-X"


def test_modbus_legacy_report_slave_id_used_only_as_hostname():
    payload = bytes([0x11, 10]) + b"ACME-PLC1" + b"\x00" + bytes([0xFF])
    adu = bytes([0, 1, 0, 0, 0, len(payload) + 1, 0xFF]) + payload
    pkt = _redissect(Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=502, dport=51000) / adu)

    hint = extract_modbus_legacy_slave_id(pkt)
    assert hint is not None
    assert hint.vendor is None
    assert "ACME-PLC1" in hint.hostname


def test_dhcp_option_60_vendor_class():
    pkt = _redissect(
        Ether()
        / IP(src="10.0.0.50", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP()
        / DHCP(options=[("message-type", "request"), ("vendor_class_id", "lwip 2.0.3"), "end"])
    )
    hint = extract_dhcp_vendor_class(pkt)
    assert hint is not None
    assert hint.vendor == "lwip 2.0.3"


def test_http_server_header_and_title():
    body = (
        b"HTTP/1.1 200 OK\r\nServer: GoAhead-Webs\r\nContent-Type: text/html\r\n\r\n"
        b"<html><head><title>PLC Web Server</title></head></html>"
    )
    pkt = _redissect(Ether() / IP(src="10.0.0.7", dst="10.0.0.2") / TCP(sport=80, dport=51000) / body)
    hint = extract_http_identity(pkt)
    assert hint is not None
    assert hint.vendor == "GoAhead-Webs"
    assert hint.hostname == "PLC Web Server"


def test_http_ignores_non_http_payload():
    pkt = _redissect(Ether() / IP(src="10.0.0.7", dst="10.0.0.2") / TCP(sport=80, dport=51000) / b"not http")
    assert extract_http_identity(pkt) is None


def test_ssdp_server_header():
    notify = (
        b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
        b"SERVER: Linux/3.10 UPnP/1.0 MyDevice/1.0\r\nNT: upnp:rootdevice\r\n\r\n"
    )
    pkt = _redissect(Ether() / IP(src="10.0.0.8", dst="239.255.255.250") / UDP(sport=1900, dport=1900) / notify)
    hint = extract_ssdp_identity(pkt)
    assert hint is not None
    assert hint.vendor == "Linux/3.10 UPnP/1.0 MyDevice/1.0"


def _mdns_txt_strings(*pairs: str) -> bytes:
    out = b""
    for p in pairs:
        out += bytes([len(p)]) + p.encode()
    return out


def test_mdns_txt_model_and_manufacturer():
    rdata = _mdns_txt_strings("md=Model X9000", "manufacturer=Acme Corp")
    dns = DNS(qr=1, an=DNSRR(rrname="_http._tcp.local.", type=16, rclass=1, ttl=120, rdata=[rdata]))
    pkt = _redissect(Ether() / IP(src="10.0.0.30", dst="224.0.0.251") / UDP(sport=5353, dport=5353) / dns)

    hint = extract_mdns_txt_identity(pkt)
    assert hint is not None
    assert hint.vendor == "Acme Corp"
    assert hint.hostname == "Model X9000"


def test_mdns_txt_without_recognized_keys_yields_nothing():
    rdata = _mdns_txt_strings("path=/", "txtvers=1")
    dns = DNS(qr=1, an=DNSRR(rrname="_http._tcp.local.", type=16, rclass=1, ttl=120, rdata=[rdata]))
    pkt = _redissect(Ether() / IP(src="10.0.0.30", dst="224.0.0.251") / UDP(sport=5353, dport=5353) / dns)
    assert extract_mdns_txt_identity(pkt) is None


def _s7comm_packet(rosctr: int, payload_tail: bytes) -> object:
    s7_header = bytes([0x32, rosctr, 0, 0, 0, 1, 0, 4, 0, 50])
    userdata_param = b"\x00\x01\x12"
    s7_payload = s7_header + userdata_param + payload_tail
    cotp = bytes([2, 0xF0, 0x80])
    tpkt_len = 4 + len(cotp) + len(s7_payload)
    tpkt = bytes([3, 0]) + tpkt_len.to_bytes(2, "big")
    data = tpkt + cotp + s7_payload
    return _redissect(Ether() / IP(src="10.0.0.40", dst="10.0.0.2") / TCP(sport=102, dport=51000) / data)


def test_s7comm_szl_order_code_sets_plc_and_vendor():
    pkt = _s7comm_packet(rosctr=7, payload_tail=b"padding 6ES7 315-2AH14-0AB0 trailing")
    hint = extract_s7comm_identity(pkt)
    assert hint is not None
    assert hint.vendor == "Siemens AG"
    assert hint.device_type == "plc"
    assert hint.hostname == "6ES7 315-2AH14-0AB0"


def test_s7comm_ignores_traffic_without_an_order_code():
    pkt = _s7comm_packet(rosctr=7, payload_tail=b"no order code in here at all")
    assert extract_s7comm_identity(pkt) is None


def test_s7comm_ignores_wrong_rosctr():
    pkt = _s7comm_packet(rosctr=1, payload_tail=b"6ES7 315-2AH14-0AB0")  # Job Request, not a reply
    assert extract_s7comm_identity(pkt) is None


def _bacnet_i_am_packet(device_instance: int, vendor_id: int) -> object:
    apdu = bytes([0x10, 0x00])  # Unconfirmed-Request, I-Am
    object_id = (8 << 22) | (device_instance & 0x3FFFFF)  # object type 8 = Device
    apdu += bytes([0xC4]) + object_id.to_bytes(4, "big")
    apdu += bytes([0x22, 0x04, 0x00])  # max-apdu-length-accepted = 1024
    apdu += bytes([0x91, 0x00])  # segmentation-supported = none
    apdu += bytes([0x21, vendor_id])  # vendor-id
    npdu = bytes([0x01, 0x00])
    bvlc_len = 4 + len(npdu) + len(apdu)
    bvlc = bytes([0x81, 0x0A]) + bvlc_len.to_bytes(2, "big")
    data = bvlc + npdu + apdu
    return _redissect(Ether() / IP(src="10.0.0.60", dst="10.0.0.255") / UDP(sport=47808, dport=47808) / data)


def test_bacnet_i_am_extracts_device_instance_and_vendor_id_as_evidence_only():
    pkt = _bacnet_i_am_packet(device_instance=1234, vendor_id=42)
    hint = extract_bacnet_identity(pkt)
    assert hint is not None
    assert hint.vendor is None
    assert hint.hostname is None
    assert hint.device_type is None
    assert "1234" in hint.evidence
    assert "42" in hint.evidence


def test_extract_identity_hints_ignores_ordinary_traffic():
    pkt = _redissect(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=51000, dport=51099, flags="A"))
    assert extract_identity_hints(pkt) == []


def test_extract_identity_hints_survives_malformed_bytes_on_a_known_port():
    """A truncated/garbage payload on a recognized OT port must never raise
    -- these are hand-rolled byte parsers reading untrusted wire data."""
    pkt = _redissect(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=102, dport=51099) / b"\x00\x01\x02")
    assert extract_identity_hints(pkt) == []
