from scapy.contrib.cdp import CDPMsgDeviceID, CDPMsgPlatform, CDPMsgSoftwareVersion, CDPv2_HDR
from scapy.contrib.lldp import (
    LLDPDUChassisID,
    LLDPDUEndOfLLDPDU,
    LLDPDUPortID,
    LLDPDUSystemDescription,
    LLDPDUSystemName,
    LLDPDUTimeToLive,
)
from scapy.contrib.pnio import ProfinetIO
from scapy.contrib.pnio_dcp import (
    DCP_IDENTIFY_RESPONSE_FRAME_ID,
    DCPManufacturerSpecificBlock,
    DCPNameOfStationBlock,
    ProfinetDCP,
)
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, LLC, SNAP, Ether
from scapy.packet import Raw

from app.capture.packet_processor import process_packet


def test_process_tcp_syn_extracts_fields():
    pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.10", ttl=64) / TCP(
        sport=51000, dport=502, flags="S", window=1024, options=[("MSS", 536)]
    )
    record = process_packet(pkt)
    assert record.transport == "tcp"
    assert record.is_syn is True
    assert record.is_syn_ack is False
    assert record.src_ip == "10.0.0.5"
    assert record.dst_ip == "10.0.0.10"
    assert record.dst_port == 502
    assert record.ttl == 64
    assert record.window == 1024
    assert ("MSS", 536) in record.tcp_options


def test_process_tcp_synack():
    pkt = Ether() / IP(src="10.0.0.10", dst="10.0.0.5", ttl=64) / TCP(sport=502, dport=51000, flags="SA")
    record = process_packet(pkt)
    assert record.is_syn_ack is True
    assert record.is_syn is False


def test_process_arp():
    pkt = Ether() / ARP(psrc="10.0.0.5", pdst="10.0.0.1", hwsrc="aa:bb:cc:dd:ee:ff")
    record = process_packet(pkt)
    assert record.transport == "arp"
    assert record.src_ip == "10.0.0.5"
    assert record.dst_ip == "10.0.0.1"


def test_process_udp_with_payload():
    pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.20") / UDP(sport=123, dport=161) / Raw(load=b"snmp-ish-payload")
    record = process_packet(pkt)
    assert record.transport == "udp"
    assert record.dst_port == 161
    assert record.payload.startswith(b"snmp")


def test_process_non_ip_ethernet_returns_none():
    pkt = Ether(type=0x88CC)  # bare LLDP ethertype, no LLDPDU layers -- unrecognized
    assert process_packet(pkt) is None


def test_process_cdp_extracts_device_id_and_mac():
    pkt = (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="01:00:0c:cc:cc:cc")
        / LLC()
        / SNAP(OUI=0xC, code=0x2000)
        / CDPv2_HDR(
            msg=[
                CDPMsgDeviceID(val=b"switch1.corp.local"),
                CDPMsgPlatform(val=b"cisco WS-C2960X-24TS-L"),
                CDPMsgSoftwareVersion(val=b"Cisco IOS Software, Version 15.2(4)E7"),
            ]
        )
    )
    record = process_packet(Ether(bytes(pkt)))
    assert record.transport == "cdp"
    assert record.src_mac == "aa:bb:cc:dd:ee:ff"
    assert record.l2_hostname == "switch1.corp.local"
    assert record.l2_device_reference == "cisco WS-C2960X-24TS-L"
    assert record.l2_firmware == "Cisco IOS Software, Version 15.2(4)E7"


def test_process_lldp_extracts_system_name_and_mac():
    pkt = (
        Ether(src="11:22:33:44:55:66", dst="01:80:c2:00:00:0e", type=0x88CC)
        / LLDPDUChassisID(subtype=4, id=b"\x11\x22\x33\x44\x55\x66")
        / LLDPDUPortID(subtype=1, id=b"Gi0/1")
        / LLDPDUTimeToLive(ttl=120)
        / LLDPDUSystemName(system_name=b"switch2-access")
        / LLDPDUEndOfLLDPDU()
    )
    record = process_packet(Ether(bytes(pkt)))
    assert record.transport == "lldp"
    assert record.src_mac == "11:22:33:44:55:66"
    assert record.l2_hostname == "switch2-access"
    assert record.l2_firmware is None


def test_process_lldp_extracts_system_description_as_firmware_best_effort():
    """Base LLDP has no separate model/platform TLV -- System Description
    is the closest available field, and in practice usually carries the
    vendor's software/firmware banner (e.g. Cisco/Aruba), so it's surfaced
    as l2_firmware rather than left unused. Never set as l2_device_reference:
    there's no reliable way to split a model out of this free-text field."""
    pkt = (
        Ether(src="11:22:33:44:55:77", dst="01:80:c2:00:00:0e", type=0x88CC)
        / LLDPDUChassisID(subtype=4, id=b"\x11\x22\x33\x44\x55\x77")
        / LLDPDUPortID(subtype=1, id=b"Gi0/2")
        / LLDPDUTimeToLive(ttl=120)
        / LLDPDUSystemName(system_name=b"switch3-access")
        / LLDPDUSystemDescription(description=b"Cisco IOS Software, C2960X, Version 15.2(4)E7")
        / LLDPDUEndOfLLDPDU()
    )
    record = process_packet(Ether(bytes(pkt)))
    assert record.transport == "lldp"
    assert record.l2_hostname == "switch3-access"
    assert record.l2_firmware == "Cisco IOS Software, C2960X, Version 15.2(4)E7"
    assert record.l2_device_reference is None


def test_process_profinet_rtc_cyclic_data_is_pnio_ps():
    """PROFINET's real-time cyclic I/O exchange runs raw over Ethernet
    (EtherType 0x8892, no IP layer) -- frameID 0x8000 falls in the
    RT_CLASS_1 range, the overwhelming majority of traffic on a running
    line, and is what Wireshark's Protocol column shows as PNIO_PS."""
    pkt = Ether(src="00:1b:1b:aa:bb:cc", dst="00:1b:1b:dd:ee:ff") / ProfinetIO(frameID=0x8000)
    record = process_packet(Ether(bytes(pkt)))
    assert record.transport == "profinet"
    assert record.src_mac == "00:1b:1b:aa:bb:cc"
    assert record.l2_protocol == "pnio_ps"
    assert record.l2_hostname is None


def test_process_profinet_dcp_extracts_station_name_and_mac():
    """A DCP Identify response self-reports the device's configured name in
    a Name-of-Station block -- the PROFINET analogue of CDP/LLDP's system
    name."""
    pkt = (
        Ether(src="00:1b:1b:11:22:33", dst="01:0e:cf:00:00:00")
        / ProfinetIO(frameID=DCP_IDENTIFY_RESPONSE_FRAME_ID)
        / ProfinetDCP(service_id=5, service_type=1, dcp_data_length=20)
        / DCPNameOfStationBlock(name_of_station=b"plc-line3")
    )
    record = process_packet(Ether(bytes(pkt)))
    assert record.transport == "profinet"
    assert record.src_mac == "00:1b:1b:11:22:33"
    assert record.l2_protocol == "pn-dcp"
    assert record.l2_hostname == "plc-line3"


def test_process_profinet_dcp_extracts_manufacturer_specific_as_device_reference():
    """The Manufacturer Specific ("Type of Station") sub-option is normally
    set by the vendor's firmware to the product's own model/type
    designation -- e.g. Siemens reporting "S7-1200" -- distinct from the
    Name-of-Station block's site-chosen device name. DCP's Identify
    response has no firmware/software-revision block to read, unlike
    CDP/LLDP -- so no l2_firmware is ever set here."""
    block = DCPManufacturerSpecificBlock(device_vendor_value=b"S7-1200", dcp_block_length=len(b"S7-1200") + 2)
    pkt = (
        Ether(src="00:1b:1b:44:55:66", dst="01:0e:cf:00:00:00")
        / ProfinetIO(frameID=DCP_IDENTIFY_RESPONSE_FRAME_ID)
        / ProfinetDCP(service_id=5, service_type=1, dcp_data_length=len(bytes(block)))
        / block
    )
    record = process_packet(Ether(bytes(pkt)))
    assert record.transport == "profinet"
    assert record.l2_protocol == "pn-dcp"
    assert record.l2_hostname is None
    assert record.l2_device_reference == "S7-1200"
    assert record.l2_firmware is None


def test_process_profinet_alarm_frame():
    pkt = Ether(src="00:1b:1b:22:33:44", dst="00:1b:1b:dd:ee:ff") / ProfinetIO(frameID=0xFE01)
    record = process_packet(Ether(bytes(pkt)))
    assert record.transport == "profinet"
    assert record.l2_protocol == "pn-alarm"
