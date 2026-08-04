from scapy.contrib.cdp import CDPMsgDeviceID, CDPv2_HDR
from scapy.contrib.enipTCP import ENIPTCP, ENIPListIdentity, ENIPListIdentityItem
from scapy.contrib.lldp import (
    LLDPDUChassisID,
    LLDPDUEndOfLLDPDU,
    LLDPDUPortID,
    LLDPDUSystemName,
    LLDPDUTimeToLive,
)
from scapy.contrib.pnio import ProfinetIO
from scapy.contrib.pnio_dcp import (
    DCP_IDENTIFY_RESPONSE_FRAME_ID,
    DCPNameOfStationBlock,
    ProfinetDCP,
)
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, LLC, SNAP, Ether
from scapy.layers.netbios import NBNSHeader, NBNSRegistrationRequest

from app.capture.packet_processor import process_packet
from app.inventory.inventory_service import ingest_packet_record
from app.models import Device, DeviceProtocol, Flow


def test_ingest_modbus_syn_creates_device_and_ot_protocol(db_session, org_id):
    pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.50", ttl=64) / TCP(
        sport=51000, dport=502, flags="S", window=1024, options=[("MSS", 536)]
    )
    record = process_packet(pkt)
    ingest_packet_record(db_session, record, org_id)
    db_session.commit()

    server = db_session.query(Device).filter(Device.ip == "10.0.0.50").one()
    assert server.is_ot_suspected is True

    proto = db_session.query(DeviceProtocol).filter(DeviceProtocol.device_id == server.id).one()
    assert proto.protocol == "modbus"
    assert proto.category == "OT"
    assert proto.role == "server"

    client = db_session.query(Device).filter(Device.ip == "10.0.0.5").one()
    assert client.os_signature is not None
    assert client.os_confidence > 0


def test_ingest_repeated_packets_increments_count_not_rows(db_session, org_id):
    for _ in range(3):
        pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.50", ttl=64) / TCP(sport=51000, dport=502, flags="A", window=1024)
        ingest_packet_record(db_session, process_packet(pkt), org_id)
    db_session.commit()

    rows = db_session.query(DeviceProtocol).all()
    assert len(rows) == 1
    assert rows[0].packet_count == 3


def test_arp_only_host_is_registered(db_session, org_id):
    from scapy.layers.l2 import ARP

    pkt = Ether() / ARP(psrc="10.0.0.77", pdst="10.0.0.1", hwsrc="aa:bb:cc:dd:ee:01")
    ingest_packet_record(db_session, process_packet(pkt), org_id)
    db_session.commit()

    device = db_session.query(Device).filter(Device.ip == "10.0.0.77").one()
    assert device.mac == "aa:bb:cc:dd:ee:01"


def test_vendor_is_auto_populated_from_mac(db_session, org_id):
    pkt = Ether(src="00:1b:1b:aa:bb:cc") / IP(src="10.0.0.50", dst="10.0.0.5", ttl=64) / TCP(
        sport=502, dport=51000, flags="SA", window=1024
    )
    ingest_packet_record(db_session, process_packet(pkt), org_id)
    db_session.commit()

    device = db_session.query(Device).filter(Device.ip == "10.0.0.50").one()
    assert device.mac == "00:1b:1b:aa:bb:cc"
    assert device.vendor == "Siemens AG"
    assert device.display_vendor == "Siemens AG"


def test_destination_mac_is_never_learned_as_device_identity(db_session, org_id):
    """A SYN's destination MAC is merely what the sender resolved via its
    own ARP cache (here scapy's synthetic default, an arbitrary locally
    administered address) -- never an authoritative statement from that
    device about its own hardware address. Only a device speaking as the
    packet's *source* should have its MAC recorded."""
    syn = Ether() / IP(src="10.0.0.5", dst="10.0.0.60", ttl=64) / TCP(sport=51000, dport=502, flags="S", window=1024)
    ingest_packet_record(db_session, process_packet(syn), org_id)
    db_session.commit()

    server_before = db_session.query(Device).filter(Device.ip == "10.0.0.60").one()
    assert server_before.mac is None

    synack = Ether(src="00:1b:1b:aa:bb:cc") / IP(src="10.0.0.60", dst="10.0.0.5", ttl=64) / TCP(
        sport=502, dport=51000, flags="SA", window=1024
    )
    ingest_packet_record(db_session, process_packet(synack), org_id)
    db_session.commit()

    server_after = db_session.query(Device).filter(Device.ip == "10.0.0.60").one()
    assert server_after.mac == "00:1b:1b:aa:bb:cc"


def test_broadcast_and_multicast_macs_are_never_recorded(db_session, org_id):
    from scapy.layers.inet import UDP

    pkt = Ether(src="ff:ff:ff:ff:ff:ff") / IP(src="10.0.0.60", dst="10.0.0.1") / UDP(sport=67, dport=68)
    ingest_packet_record(db_session, process_packet(pkt), org_id)
    db_session.commit()

    device = db_session.query(Device).filter(Device.ip == "10.0.0.60").one()
    assert device.mac is None
    assert device.vendor is None


def test_broadcast_and_multicast_ips_never_become_devices(db_session, org_id):
    """255.255.255.255 (limited broadcast), an mDNS/SSDP-style multicast
    group, and the DHCP pre-lease 0.0.0.0 are never a specific device's own
    address -- inventoried them and they'd just be junk rows, never a real
    asset (see is_real_unicast_ip)."""
    for src_ip in ("255.255.255.255", "224.0.0.251", "0.0.0.0"):
        pkt = Ether() / IP(src=src_ip, dst="10.0.0.1") / UDP(sport=5353, dport=5353)
        ingest_packet_record(db_session, process_packet(pkt), org_id)
    db_session.commit()

    for src_ip in ("255.255.255.255", "224.0.0.251", "0.0.0.0"):
        assert db_session.query(Device).filter(Device.ip == src_ip).one_or_none() is None

    # the real destination is unaffected
    assert db_session.query(Device).filter(Device.ip == "10.0.0.1").one_or_none() is not None


def test_apply_hostname_hints_clears_a_name_shared_by_two_ips(db_session, org_id):
    """A NetBIOS group/domain name (e.g. "WORKGROUP" registered with the
    group bit unset by some stacks) slips past extract_nbns_hostname's own
    checks: this is the backstop. Once a *second* IP claims a name the
    first one already has, that proves it's shared, not a real per-host
    identity -- so both get cleared instead of one keeping a misleading
    name that arrived first by chance of packet ordering."""
    from app.inventory.inventory_service import apply_hostname_hints

    first = Ether() / IP(src="10.0.2.10", dst="10.0.2.1", ttl=64) / TCP(sport=445, dport=51000, flags="SA", window=1024)
    second = Ether() / IP(src="10.0.2.11", dst="10.0.2.1", ttl=64) / TCP(sport=445, dport=51001, flags="SA", window=1024)
    ingest_packet_record(db_session, process_packet(first), org_id)
    ingest_packet_record(db_session, process_packet(second), org_id)
    db_session.commit()

    apply_hostname_hints(db_session, [("10.0.2.10", "WORKGROUP")], org_id)
    db_session.commit()
    assert db_session.query(Device).filter(Device.ip == "10.0.2.10").one().hostname == "WORKGROUP"

    apply_hostname_hints(db_session, [("10.0.2.11", "WORKGROUP")], org_id)
    db_session.commit()

    assert db_session.query(Device).filter(Device.ip == "10.0.2.10").one().hostname is None
    assert db_session.query(Device).filter(Device.ip == "10.0.2.11").one().hostname is None

    # a real, unique-per-host name still applies normally afterwards
    apply_hostname_hints(db_session, [("10.0.2.11", "KR63203-HMI01")], org_id)
    db_session.commit()
    assert db_session.query(Device).filter(Device.ip == "10.0.2.11").one().hostname == "KR63203-HMI01"


def test_hostname_hint_enriches_existing_device_but_never_creates_one(db_session, org_id):
    from app.inventory.inventory_service import apply_hostname_hints

    pkt = Ether() / IP(src="10.0.0.50", dst="10.0.0.5", ttl=64) / TCP(sport=502, dport=51000, flags="SA", window=1024)
    ingest_packet_record(db_session, process_packet(pkt), org_id)
    db_session.commit()

    apply_hostname_hints(db_session, [("10.0.0.50", "PLC-LINE3"), ("203.0.113.9", "unrelated-public-host")], org_id)
    db_session.commit()

    known = db_session.query(Device).filter(Device.ip == "10.0.0.50").one()
    assert known.hostname == "PLC-LINE3"
    assert known.display_name == "PLC-LINE3"

    assert db_session.query(Device).filter(Device.ip == "203.0.113.9").one_or_none() is None


def test_custom_name_overrides_auto_detected_hostname(db_session, org_id):
    device = Device(ip="10.0.0.99", hostname="auto-detected")
    db_session.add(device)
    db_session.commit()

    assert device.display_name == "auto-detected"
    device.custom_name = "Manually Renamed"
    assert device.display_name == "Manually Renamed"


def test_flow_created_and_aggregated_for_tcp_conversation(db_session, org_id):
    client_ip, server_ip = "10.0.0.5", "10.0.0.50"
    packets = [
        Ether() / IP(src=client_ip, dst=server_ip, ttl=64) / TCP(sport=51000, dport=502, flags="S", window=1024),
        Ether() / IP(src=server_ip, dst=client_ip, ttl=64) / TCP(sport=502, dport=51000, flags="SA", window=1024),
        Ether() / IP(src=client_ip, dst=server_ip, ttl=64) / TCP(sport=51000, dport=502, flags="A", window=1024),
    ]
    for pkt in packets:
        ingest_packet_record(db_session, process_packet(pkt), org_id)
    db_session.commit()

    flows = db_session.query(Flow).all()
    assert len(flows) == 1
    flow = flows[0]
    assert flow.packet_count == 3
    assert flow.protocol == "modbus"
    assert flow.category == "OT"
    assert flow.transport == "tcp"
    assert flow.port == 502

    client = db_session.query(Device).filter(Device.ip == client_ip).one()
    server = db_session.query(Device).filter(Device.ip == server_ip).one()
    assert flow.server_device_id == server.id
    assert {flow.device_a_id, flow.device_b_id} == {client.id, server.id}
    assert flow.device_a_id < flow.device_b_id  # normalized ordering


def test_nbns_registration_enriches_existing_device_hostname(db_session, org_id):
    tcp_pkt = Ether() / IP(src="10.0.0.40", dst="10.0.0.5", ttl=64) / TCP(sport=502, dport=51000, flags="SA", window=1024)
    ingest_packet_record(db_session, process_packet(tcp_pkt), org_id)

    nbns_pkt = (
        Ether()
        / IP(src="10.0.0.40", dst="10.0.0.255")
        / UDP(sport=137, dport=137)
        / NBNSHeader(OPCODE=0x5, NM_FLAGS=0x11)
        / NBNSRegistrationRequest(QUESTION_NAME="ENGWORKSTATION", SUFFIX="workstation", NB_ADDRESS="10.0.0.40")
    )
    ingest_packet_record(db_session, process_packet(nbns_pkt), org_id)
    db_session.commit()

    device = db_session.query(Device).filter(Device.ip == "10.0.0.40").one()
    assert device.hostname == "ENGWORKSTATION"


def test_cdp_announcement_creates_network_device_by_mac(db_session, org_id):
    pkt = (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="01:00:0c:cc:cc:cc")
        / LLC()
        / SNAP(OUI=0xC, code=0x2000)
        / CDPv2_HDR(msg=[CDPMsgDeviceID(val=b"switch1.corp.local")])
    )
    ingest_packet_record(db_session, process_packet(Ether(bytes(pkt))), org_id)
    db_session.commit()

    device = db_session.query(Device).filter(Device.mac == "aa:bb:cc:dd:ee:ff").one()
    assert device.ip is None
    assert device.hostname == "switch1.corp.local"
    assert device.os_guess == "Network appliance (router/switch/firewall)"
    assert device.os_confidence == 1.0


def test_lldp_announcement_creates_network_device_by_mac(db_session, org_id):
    pkt = (
        Ether(src="10:22:33:44:55:66", dst="01:80:c2:00:00:0e", type=0x88CC)
        / LLDPDUChassisID(subtype=4, id=b"\x10\x22\x33\x44\x55\x66")
        / LLDPDUPortID(subtype=1, id=b"Gi0/1")
        / LLDPDUTimeToLive(ttl=120)
        / LLDPDUSystemName(system_name=b"switch2-access")
        / LLDPDUEndOfLLDPDU()
    )
    ingest_packet_record(db_session, process_packet(Ether(bytes(pkt))), org_id)
    db_session.commit()

    device = db_session.query(Device).filter(Device.mac == "10:22:33:44:55:66").one()
    assert device.ip is None
    assert device.hostname == "switch2-access"
    assert device.os_guess == "Network appliance (router/switch/firewall)"


def test_cdp_discovered_switch_merges_with_later_ip_traffic(db_session, org_id):
    """A switch first seen only via CDP (no IP) should be enriched, not
    duplicated, once the same MAC is later seen sending real IP traffic."""
    cdp_pkt = (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="01:00:0c:cc:cc:cc")
        / LLC()
        / SNAP(OUI=0xC, code=0x2000)
        / CDPv2_HDR(msg=[CDPMsgDeviceID(val=b"switch1.corp.local")])
    )
    ingest_packet_record(db_session, process_packet(Ether(bytes(cdp_pkt))), org_id)
    db_session.commit()

    ip_pkt = Ether(src="aa:bb:cc:dd:ee:ff") / IP(src="10.0.0.9", dst="10.0.0.5", ttl=255) / TCP(
        sport=22, dport=51000, flags="SA", window=4096
    )
    ingest_packet_record(db_session, process_packet(ip_pkt), org_id)
    db_session.commit()

    devices = db_session.query(Device).filter(Device.mac == "aa:bb:cc:dd:ee:ff").all()
    assert len(devices) == 1
    assert devices[0].ip == "10.0.0.9"
    assert devices[0].hostname == "switch1.corp.local"


def test_cdp_announcement_sets_device_type_network_device(db_session, org_id):
    pkt = (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="01:00:0c:cc:cc:cc")
        / LLC()
        / SNAP(OUI=0xC, code=0x2000)
        / CDPv2_HDR(msg=[CDPMsgDeviceID(val=b"switch1.corp.local")])
    )
    ingest_packet_record(db_session, process_packet(Ether(bytes(pkt))), org_id)
    db_session.commit()

    device = db_session.query(Device).filter(Device.mac == "aa:bb:cc:dd:ee:ff").one()
    assert device.device_type == "network_device"
    assert device.device_type_confidence >= 0.7


def test_profinet_rtc_creates_mac_only_device_classified_as_plc(db_session, org_id):
    """PROFINET's real-time cyclic I/O (PNIO_PS in Wireshark) runs raw over
    Ethernet -- no IP layer at all -- so the device is keyed by MAC alone,
    same as a CDP/LLDP-only switch. Registered as an OT server protocol,
    with no os_signature to contradict it (no TCP/IP stack involved), it
    should classify as PLC -- exactly what a real PROFINET IO device is."""
    pkt = Ether(src="00:1b:1b:aa:bb:cc", dst="00:1b:1b:dd:ee:ff") / ProfinetIO(frameID=0x8000)
    ingest_packet_record(db_session, process_packet(Ether(bytes(pkt))), org_id)
    db_session.commit()

    device = db_session.query(Device).filter(Device.mac == "00:1b:1b:aa:bb:cc").one()
    assert device.ip is None
    protocols = db_session.query(DeviceProtocol).filter(DeviceProtocol.device_id == device.id).all()
    assert len(protocols) == 1
    assert protocols[0].protocol == "pnio_ps"
    assert protocols[0].category == "OT"
    assert device.is_ot_suspected is True
    assert device.display_device_type == "plc"


def test_profinet_dcp_sets_hostname_from_name_of_station(db_session, org_id):
    pkt = (
        Ether(src="00:1b:1b:11:22:33", dst="01:0e:cf:00:00:00")
        / ProfinetIO(frameID=DCP_IDENTIFY_RESPONSE_FRAME_ID)
        / ProfinetDCP(service_id=5, service_type=1, dcp_data_length=20)
        / DCPNameOfStationBlock(name_of_station=b"plc-line3")
    )
    ingest_packet_record(db_session, process_packet(Ether(bytes(pkt))), org_id)
    db_session.commit()

    device = db_session.query(Device).filter(Device.mac == "00:1b:1b:11:22:33").one()
    assert device.hostname == "plc-line3"
    protocols = db_session.query(DeviceProtocol).filter(DeviceProtocol.device_id == device.id).all()
    assert protocols[0].protocol == "pn-dcp"


def test_profinet_mac_only_device_merges_with_later_ip_traffic(db_session, org_id):
    """Same merge-by-MAC behavior as a CDP-only switch: a PLC first seen
    only via PROFINET RTC (no IP) should be enriched, not duplicated, once
    the same MAC is later seen sending real IP traffic (e.g. its web UI)."""
    rtc = Ether(src="00:1b:1b:aa:bb:cc", dst="00:1b:1b:dd:ee:ff") / ProfinetIO(frameID=0x8000)
    ingest_packet_record(db_session, process_packet(Ether(bytes(rtc))), org_id)
    db_session.commit()

    ip_pkt = Ether(src="00:1b:1b:aa:bb:cc") / IP(src="10.0.4.20", dst="10.0.4.5", ttl=64) / TCP(
        sport=80, dport=51000, flags="SA", window=8192
    )
    ingest_packet_record(db_session, process_packet(ip_pkt), org_id)
    db_session.commit()

    devices = db_session.query(Device).filter(Device.mac == "00:1b:1b:aa:bb:cc").all()
    assert len(devices) == 1
    assert devices[0].ip == "10.0.4.20"


def test_modbus_server_sets_device_type_plc(db_session, org_id):
    syn = Ether() / IP(src="10.0.4.5", dst="10.0.4.60", ttl=64) / TCP(sport=41000, dport=502, flags="S", window=1024)
    ingest_packet_record(db_session, process_packet(syn), org_id)
    db_session.commit()

    plc = db_session.query(Device).filter(Device.ip == "10.0.4.60").one()
    assert plc.device_type == "plc"
    assert plc.device_type_confidence >= 0.7
    assert "protocolo industrial" in plc.device_type_evidence


def test_modbus_server_on_windows_stack_sets_device_type_hmi_not_plc(db_session, org_id):
    """A single SYN-ACK from port 502 with a Windows-shaped TCP signature
    (TTL 128, SACK, window scale, no timestamps) both assigns the Modbus
    server protocol *and* fingerprints the OS in the same packet -- the
    combination should classify as HMI (SCADA/engineering software on a
    real OS), not PLC (an embedded controller wouldn't look like this)."""
    synack = Ether() / IP(src="10.0.4.65", dst="10.0.4.5", ttl=128) / TCP(
        sport=502, dport=51000, flags="SA", window=8192, options=[("WScale", 8), ("SAckOK", b"")]
    )
    ingest_packet_record(db_session, process_packet(synack), org_id)
    db_session.commit()

    hmi = db_session.query(Device).filter(Device.ip == "10.0.4.65").one()
    assert hmi.os_guess == "Windows (7/8/10/11 family)"
    assert hmi.device_type == "hmi"
    assert hmi.device_type_confidence >= 0.7
    assert "SO de propósito general" in hmi.device_type_evidence


def test_arp_only_industrial_vendor_sets_device_type_plc(db_session, org_id):
    """A device only ever seen via ARP has no protocol/OS evidence at all --
    but its vendor OUI (0001E3 -> Siemens AG in the bundled manuf table) is
    still real evidence worth a classification attempt."""
    who_has = Ether() / ARP(op=1, hwsrc="00:01:e3:aa:bb:cc", psrc="10.0.4.70", pdst="10.0.4.1")
    ingest_packet_record(db_session, process_packet(who_has), org_id)
    db_session.commit()

    device = db_session.query(Device).filter(Device.ip == "10.0.4.70").one()
    assert device.vendor == "Siemens AG"
    assert device.device_type == "plc"
    assert 0 < device.device_type_confidence < 0.7


def test_arp_only_weintek_vendor_sets_device_type_hmi(db_session, org_id):
    who_has = Ether() / ARP(op=1, hwsrc="00:0c:26:aa:bb:cc", psrc="10.0.4.71", pdst="10.0.4.1")
    ingest_packet_record(db_session, process_packet(who_has), org_id)
    db_session.commit()

    device = db_session.query(Device).filter(Device.ip == "10.0.4.71").one()
    assert device.vendor == "Weintek Labs. Inc."
    assert device.device_type == "hmi"
    assert device.device_type_secondary is None


def test_arp_only_industrial_software_co_vendor_sets_other_transport_controller(db_session, org_id):
    who_has = Ether() / ARP(op=1, hwsrc="14:b1:26:aa:bb:cc", psrc="10.0.4.72", pdst="10.0.4.1")
    ingest_packet_record(db_session, process_packet(who_has), org_id)
    db_session.commit()

    device = db_session.query(Device).filter(Device.ip == "10.0.4.72").one()
    assert device.vendor == "Industrial Software Co"
    assert device.device_type == "other"
    assert device.device_type_secondary == "transport_controller"


def test_hostname_hint_can_upgrade_device_type_classification(db_session, org_id):
    """A device with no distinguishing evidence starts unclassified; once
    an HMI-style hostname arrives, it should reclassify as hmi. Plain ACK
    (not SYN/SYN-ACK) on unclassified ports avoids any OS-fingerprint or
    protocol-based vote, isolating this to the hostname signal alone."""
    from app.inventory.inventory_service import apply_hostname_hints

    ack = Ether() / IP(src="10.0.4.80", dst="10.0.4.90", ttl=64) / TCP(
        sport=51000, dport=51099, flags="A", window=1024
    )
    ingest_packet_record(db_session, process_packet(ack), org_id)
    db_session.commit()

    before = db_session.query(Device).filter(Device.ip == "10.0.4.80").one()
    assert before.device_type is None

    apply_hostname_hints(db_session, [("10.0.4.80", "K787395-HMI01")], org_id)
    db_session.commit()

    after = db_session.query(Device).filter(Device.ip == "10.0.4.80").one()
    assert after.device_type == "hmi"


def test_get_or_create_device_tolerates_pre_existing_duplicate_ip(db_session, org_id):
    """ip alone is not actually a unique key: the DB constraint is on the
    (mac, ip) pair, and two NULL macs don't collide under it either -- so a
    large/long capture (concurrent uploads racing, an address briefly
    reused/conflicting on the LAN) can leave two Device rows sharing one ip.
    Regression for a real bug: a big pcap upload hit exactly this and every
    subsequent packet touching that ip crashed the whole capture with
    'Multiple rows were found when one or none was required'. Ingesting
    should tolerate the anomaly (deterministically use the oldest row)
    instead of raising."""
    from app.inventory.inventory_service import get_or_create_device

    older = Device(organization_id=org_id, ip="10.0.5.5", mac=None)
    newer = Device(organization_id=org_id, ip="10.0.5.5", mac=None)
    db_session.add(older)
    db_session.add(newer)
    db_session.commit()
    assert older.id < newer.id

    device = get_or_create_device(db_session, ip="10.0.5.5", mac="aa:bb:cc:dd:ee:01", organization_id=org_id)
    db_session.commit()

    assert device.id == older.id
    assert device.mac == "aa:bb:cc:dd:ee:01"
    assert db_session.query(Device).filter(Device.ip == "10.0.5.5").count() == 2


def test_apply_hostname_hints_tolerates_pre_existing_duplicate_ip(db_session, org_id):
    """Same anomaly as above, exercised through apply_hostname_hints's own
    ip-keyed lookup -- must not raise, and should enrich the oldest row."""
    from app.inventory.inventory_service import apply_hostname_hints

    older = Device(organization_id=org_id, ip="10.0.5.6", mac=None)
    newer = Device(organization_id=org_id, ip="10.0.5.6", mac=None)
    db_session.add(older)
    db_session.add(newer)
    db_session.commit()

    apply_hostname_hints(db_session, [("10.0.5.6", "PLC-DUPE")], org_id)
    db_session.commit()

    db_session.refresh(older)
    db_session.refresh(newer)
    assert older.hostname == "PLC-DUPE"
    assert newer.hostname is None


def test_apply_hostname_hints_clears_shared_name_from_every_claimant(db_session, org_id):
    """The anti-collision rule ("a name shared by 2+ IPs isn't real, clear
    it from all of them") must actually clear *every* other claimant, not
    just the first one found, if a name somehow ended up on more than one
    other device already."""
    from app.inventory.inventory_service import apply_hostname_hints

    target = Device(organization_id=org_id, ip="10.0.5.10", mac=None)
    claimant_a = Device(organization_id=org_id, ip="10.0.5.11", mac=None, hostname="WORKGROUP")
    claimant_b = Device(organization_id=org_id, ip="10.0.5.12", mac=None, hostname="WORKGROUP")
    db_session.add_all([target, claimant_a, claimant_b])
    db_session.commit()

    apply_hostname_hints(db_session, [("10.0.5.10", "WORKGROUP")], org_id)
    db_session.commit()

    db_session.refresh(claimant_a)
    db_session.refresh(claimant_b)
    db_session.refresh(target)
    assert claimant_a.hostname is None
    assert claimant_b.hostname is None
    assert target.hostname is None


def test_gateway_detection_flags_mac_shared_across_public_ips(db_session, org_id):
    """A router/NAT gateway forwarding return traffic from the internet
    transmits those frames itself -- so its MAC (never the destination's,
    see get_or_create_device) ends up attached to every distinct public IP
    it ever forwarded, each becoming its own inventory row. Two or more
    such rows sharing one MAC is the signature: one of them should be
    picked as the real gateway (network_device / router_nat), and neither
    picked-and-not-picked distinction should touch the local LAN host on
    the other end of those flows."""
    from app.inventory.inventory_service import apply_gateway_detection

    GATEWAY_MAC = "aa:bb:cc:00:00:01"
    reply1 = Ether(src=GATEWAY_MAC) / IP(src="8.8.8.8", dst="10.0.6.5", ttl=64) / TCP(
        sport=443, dport=51000, flags="SA", window=8192
    )
    reply2 = Ether(src=GATEWAY_MAC) / IP(src="93.184.216.34", dst="10.0.6.5", ttl=64) / TCP(
        sport=443, dport=51001, flags="SA", window=8192
    )
    ingest_packet_record(db_session, process_packet(reply1), org_id)
    ingest_packet_record(db_session, process_packet(reply2), org_id)
    db_session.commit()

    pub1 = db_session.query(Device).filter(Device.ip == "8.8.8.8").one()
    pub2 = db_session.query(Device).filter(Device.ip == "93.184.216.34").one()
    lan_host = db_session.query(Device).filter(Device.ip == "10.0.6.5").one()
    assert pub1.mac == GATEWAY_MAC
    assert pub2.mac == GATEWAY_MAC
    assert pub1.device_type != "network_device"  # not yet classified

    apply_gateway_detection(db_session, org_id)
    db_session.commit()

    db_session.refresh(pub1)
    db_session.refresh(pub2)
    db_session.refresh(lan_host)

    primary, other = (pub1, pub2) if pub1.id < pub2.id else (pub2, pub1)
    assert primary.display_device_type == "network_device"
    assert primary.display_device_type_secondary == "router_nat"
    assert primary.device_type_confidence == 1.0
    # the non-chosen duplicate is untouched otherwise -- still a real row,
    # not reclassified or deleted, just not the one picked to represent
    # the gateway.
    assert other.device_type != "network_device"
    # the actual LAN host these were replies to is never touched by this.
    assert lan_host.mac is None
    assert lan_host.display_device_type != "network_device"


def test_gateway_detection_never_promotes_a_private_ip_sharing_the_mac(db_session, org_id):
    """A private-IP row sharing the gateway's MAC is never safe to treat as
    "the gateway's own LAN identity" -- inter-VLAN routing produces the
    exact same sender-MAC pattern for a real, distinct host on a different
    subnet whose return traffic happens to pass through this same gateway.
    There's no reliable way to tell those two cases apart, so the primary
    is always one of the public-IP duplicates instead; a private IP is
    always left alone as its own independently-classified device, even
    when it's the only private-IP member of the group."""
    from app.inventory.inventory_service import apply_gateway_detection

    GATEWAY_MAC = "aa:bb:cc:00:00:02"
    reply1 = Ether(src=GATEWAY_MAC) / IP(src="8.8.4.4", dst="10.0.6.6", ttl=64) / TCP(
        sport=443, dport=51000, flags="SA", window=8192
    )
    reply2 = Ether(src=GATEWAY_MAC) / IP(src="1.1.1.1", dst="10.0.6.6", ttl=64) / TCP(
        sport=443, dport=51001, flags="SA", window=8192
    )
    # a real host on a different private subnet, reached via the same
    # gateway (inter-VLAN routing) -- must never be mislabeled as it.
    routed = Ether(src=GATEWAY_MAC) / IP(src="10.0.9.20", dst="10.0.6.6", ttl=63) / TCP(
        sport=445, dport=51002, flags="SA", window=8192
    )
    ingest_packet_record(db_session, process_packet(reply1), org_id)
    ingest_packet_record(db_session, process_packet(reply2), org_id)
    ingest_packet_record(db_session, process_packet(routed), org_id)
    db_session.commit()

    apply_gateway_detection(db_session, org_id)
    db_session.commit()

    routed_device = db_session.query(Device).filter(Device.ip == "10.0.9.20").one()
    assert routed_device.display_device_type != "network_device"
    assert routed_device.display_device_type_secondary is None

    primary = db_session.query(Device).filter(Device.device_type_secondary == "router_nat").one()
    assert primary.ip in ("8.8.4.4", "1.1.1.1")


def test_gateway_detection_ignores_a_single_shared_public_ip(db_session, org_id):
    """One public IP alone sharing a MAC with something else proves
    nothing on its own -- the gateway pattern needs at least two."""
    from app.inventory.inventory_service import apply_gateway_detection

    GATEWAY_MAC = "aa:bb:cc:00:00:03"
    reply = Ether(src=GATEWAY_MAC) / IP(src="8.8.8.8", dst="10.0.6.7", ttl=64) / TCP(
        sport=443, dport=51000, flags="SA", window=8192
    )
    ingest_packet_record(db_session, process_packet(reply), org_id)
    db_session.commit()

    apply_gateway_detection(db_session, org_id)
    db_session.commit()

    pub_device = db_session.query(Device).filter(Device.ip == "8.8.8.8").one()
    assert pub_device.display_device_type != "network_device"


def _modbus_object(object_id: int, value: str) -> bytes:
    return bytes([object_id, len(value)]) + value.encode()


def test_enip_list_identity_sets_hmi_device_type_end_to_end(db_session, org_id):
    """A CIP Identity object's deviceType is authoritative enough to
    override the generic classifier outright -- same "direct-set" pattern
    as apply_gateway_detection."""
    item = ENIPListIdentityItem(
        itemTypeCode=0x0C,
        sinFamily=2,
        sinPort=44818,
        sinAddress="10.0.4.10",
        vendorId=1,
        deviceType=0x18,  # Human-Machine Interface
        productNameLength=len("MyHMI-9000"),
        productName="MyHMI-9000",
    )
    enip = ENIPTCP(commandId=0x63, status=0) / ENIPListIdentity(itemCount=1, items=[item])
    pkt = Ether(bytes(Ether() / IP(src="10.0.4.10", dst="10.0.4.99", ttl=64) / TCP(sport=44818, dport=51000) / enip))
    ingest_packet_record(db_session, process_packet(pkt), org_id)
    db_session.commit()

    device = db_session.query(Device).filter(Device.ip == "10.0.4.10").one()
    assert device.device_type == "hmi"
    assert device.device_type_confidence == 1.0
    assert device.hostname == "MyHMI-9000"


def test_modbus_device_identification_sets_vendor_end_to_end(db_session, org_id):
    payload = bytes([0x2B, 0x0E, 0x0E, 0x83, 0x00, 0x00, 2])
    payload += _modbus_object(0x00, "Acme Corp") + _modbus_object(0x04, "Widget-9000")
    adu = bytes([0, 1, 0, 0, 0, len(payload) + 1, 0xFF]) + payload
    pkt = Ether(bytes(Ether() / IP(src="10.0.4.11", dst="10.0.4.99", ttl=64) / TCP(sport=502, dport=51000) / adu))
    ingest_packet_record(db_session, process_packet(pkt), org_id)
    db_session.commit()

    device = db_session.query(Device).filter(Device.ip == "10.0.4.11").one()
    assert device.vendor == "Acme Corp"
    assert device.hostname == "Widget-9000"


def test_modbus_identification_never_overwrites_a_known_oui_vendor(db_session, org_id):
    """Vendor only fills in when unknown -- a real MAC-OUI vendor always
    outranks a protocol-level self-reported string."""
    payload = bytes([0x2B, 0x0E, 0x0E, 0x83, 0x00, 0x00, 1])
    payload += _modbus_object(0x00, "Some Other Vendor")
    adu = bytes([0, 1, 0, 0, 0, len(payload) + 1, 0xFF]) + payload
    pkt = Ether(
        bytes(
            Ether(src="00:01:e3:aa:bb:cc")
            / IP(src="10.0.4.12", dst="10.0.4.99", ttl=64)
            / TCP(sport=502, dport=51000)
            / adu
        )
    )
    ingest_packet_record(db_session, process_packet(pkt), org_id)
    db_session.commit()

    device = db_session.query(Device).filter(Device.ip == "10.0.4.12").one()
    assert device.vendor == "Siemens AG"  # from the 0001E3 OUI, not the Modbus hint


def test_bacnet_i_am_fills_evidence_only_without_asserting_a_device_type(db_session, org_id):
    """BACnet's vendor-id is a numeric registry ID this app doesn't bundle
    a lookup table for -- it must never become Device.vendor/hostname, and
    must never assert a device_type override; only device_type_evidence
    fills in, and only when nothing else has classified this device yet."""
    apdu = bytes([0x10, 0x00])
    object_id = (8 << 22) | 1234
    apdu += bytes([0xC4]) + object_id.to_bytes(4, "big")
    apdu += bytes([0x22, 0x04, 0x00])
    apdu += bytes([0x91, 0x00])
    apdu += bytes([0x21, 42])
    npdu = bytes([0x01, 0x00])
    bvlc_len = 4 + len(npdu) + len(apdu)
    bvlc = bytes([0x81, 0x0A]) + bvlc_len.to_bytes(2, "big")
    data = bvlc + npdu + apdu
    pkt = Ether(
        bytes(Ether() / IP(src="10.0.4.13", dst="10.0.4.255", ttl=64) / UDP(sport=47808, dport=47808) / data)
    )
    ingest_packet_record(db_session, process_packet(pkt), org_id)
    db_session.commit()

    device = db_session.query(Device).filter(Device.ip == "10.0.4.13").one()
    assert device.vendor is None
    assert device.hostname is None
    assert device.device_type is None
    assert device.device_type_evidence is not None
    assert "1234" in device.device_type_evidence
    assert "42" in device.device_type_evidence
