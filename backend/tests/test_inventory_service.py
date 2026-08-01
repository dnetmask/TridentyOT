from scapy.contrib.cdp import CDPMsgDeviceID, CDPv2_HDR
from scapy.contrib.lldp import (
    LLDPDUChassisID,
    LLDPDUEndOfLLDPDU,
    LLDPDUPortID,
    LLDPDUSystemName,
    LLDPDUTimeToLive,
)
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import LLC, SNAP, Ether
from scapy.layers.netbios import NBNSHeader, NBNSRegistrationRequest

from app.capture.packet_processor import process_packet
from app.inventory.inventory_service import ingest_packet_record
from app.models import Device, DeviceProtocol, Flow


def test_ingest_modbus_syn_creates_device_and_ot_protocol(db_session):
    pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.50", ttl=64) / TCP(
        sport=51000, dport=502, flags="S", window=1024, options=[("MSS", 536)]
    )
    record = process_packet(pkt)
    ingest_packet_record(db_session, record)
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


def test_ingest_repeated_packets_increments_count_not_rows(db_session):
    for _ in range(3):
        pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.50", ttl=64) / TCP(sport=51000, dport=502, flags="A", window=1024)
        ingest_packet_record(db_session, process_packet(pkt))
    db_session.commit()

    rows = db_session.query(DeviceProtocol).all()
    assert len(rows) == 1
    assert rows[0].packet_count == 3


def test_arp_only_host_is_registered(db_session):
    from scapy.layers.l2 import ARP

    pkt = Ether() / ARP(psrc="10.0.0.77", pdst="10.0.0.1", hwsrc="aa:bb:cc:dd:ee:01")
    ingest_packet_record(db_session, process_packet(pkt))
    db_session.commit()

    device = db_session.query(Device).filter(Device.ip == "10.0.0.77").one()
    assert device.mac == "aa:bb:cc:dd:ee:01"


def test_vendor_is_auto_populated_from_mac(db_session):
    pkt = Ether(src="00:1b:1b:aa:bb:cc") / IP(src="10.0.0.50", dst="10.0.0.5", ttl=64) / TCP(
        sport=502, dport=51000, flags="SA", window=1024
    )
    ingest_packet_record(db_session, process_packet(pkt))
    db_session.commit()

    device = db_session.query(Device).filter(Device.ip == "10.0.0.50").one()
    assert device.mac == "00:1b:1b:aa:bb:cc"
    assert device.vendor == "Siemens AG"
    assert device.display_vendor == "Siemens AG"


def test_destination_mac_is_never_learned_as_device_identity(db_session):
    """A SYN's destination MAC is merely what the sender resolved via its
    own ARP cache (here scapy's synthetic default, an arbitrary locally
    administered address) -- never an authoritative statement from that
    device about its own hardware address. Only a device speaking as the
    packet's *source* should have its MAC recorded."""
    syn = Ether() / IP(src="10.0.0.5", dst="10.0.0.60", ttl=64) / TCP(sport=51000, dport=502, flags="S", window=1024)
    ingest_packet_record(db_session, process_packet(syn))
    db_session.commit()

    server_before = db_session.query(Device).filter(Device.ip == "10.0.0.60").one()
    assert server_before.mac is None

    synack = Ether(src="00:1b:1b:aa:bb:cc") / IP(src="10.0.0.60", dst="10.0.0.5", ttl=64) / TCP(
        sport=502, dport=51000, flags="SA", window=1024
    )
    ingest_packet_record(db_session, process_packet(synack))
    db_session.commit()

    server_after = db_session.query(Device).filter(Device.ip == "10.0.0.60").one()
    assert server_after.mac == "00:1b:1b:aa:bb:cc"


def test_broadcast_and_multicast_macs_are_never_recorded(db_session):
    from scapy.layers.inet import UDP

    pkt = Ether(src="ff:ff:ff:ff:ff:ff") / IP(src="10.0.0.60", dst="10.0.0.1") / UDP(sport=67, dport=68)
    ingest_packet_record(db_session, process_packet(pkt))
    db_session.commit()

    device = db_session.query(Device).filter(Device.ip == "10.0.0.60").one()
    assert device.mac is None
    assert device.vendor is None


def test_broadcast_and_multicast_ips_never_become_devices(db_session):
    """255.255.255.255 (limited broadcast), an mDNS/SSDP-style multicast
    group, and the DHCP pre-lease 0.0.0.0 are never a specific device's own
    address -- inventoried them and they'd just be junk rows, never a real
    asset (see is_real_unicast_ip)."""
    for src_ip in ("255.255.255.255", "224.0.0.251", "0.0.0.0"):
        pkt = Ether() / IP(src=src_ip, dst="10.0.0.1") / UDP(sport=5353, dport=5353)
        ingest_packet_record(db_session, process_packet(pkt))
    db_session.commit()

    for src_ip in ("255.255.255.255", "224.0.0.251", "0.0.0.0"):
        assert db_session.query(Device).filter(Device.ip == src_ip).one_or_none() is None

    # the real destination is unaffected
    assert db_session.query(Device).filter(Device.ip == "10.0.0.1").one_or_none() is not None


def test_apply_hostname_hints_clears_a_name_shared_by_two_ips(db_session):
    """A NetBIOS group/domain name (e.g. "WORKGROUP" registered with the
    group bit unset by some stacks) slips past extract_nbns_hostname's own
    checks: this is the backstop. Once a *second* IP claims a name the
    first one already has, that proves it's shared, not a real per-host
    identity -- so both get cleared instead of one keeping a misleading
    name that arrived first by chance of packet ordering."""
    from app.inventory.inventory_service import apply_hostname_hints

    first = Ether() / IP(src="10.0.2.10", dst="10.0.2.1", ttl=64) / TCP(sport=445, dport=51000, flags="SA", window=1024)
    second = Ether() / IP(src="10.0.2.11", dst="10.0.2.1", ttl=64) / TCP(sport=445, dport=51001, flags="SA", window=1024)
    ingest_packet_record(db_session, process_packet(first))
    ingest_packet_record(db_session, process_packet(second))
    db_session.commit()

    apply_hostname_hints(db_session, [("10.0.2.10", "WORKGROUP")])
    db_session.commit()
    assert db_session.query(Device).filter(Device.ip == "10.0.2.10").one().hostname == "WORKGROUP"

    apply_hostname_hints(db_session, [("10.0.2.11", "WORKGROUP")])
    db_session.commit()

    assert db_session.query(Device).filter(Device.ip == "10.0.2.10").one().hostname is None
    assert db_session.query(Device).filter(Device.ip == "10.0.2.11").one().hostname is None

    # a real, unique-per-host name still applies normally afterwards
    apply_hostname_hints(db_session, [("10.0.2.11", "KR63203-HMI01")])
    db_session.commit()
    assert db_session.query(Device).filter(Device.ip == "10.0.2.11").one().hostname == "KR63203-HMI01"


def test_hostname_hint_enriches_existing_device_but_never_creates_one(db_session):
    from app.inventory.inventory_service import apply_hostname_hints

    pkt = Ether() / IP(src="10.0.0.50", dst="10.0.0.5", ttl=64) / TCP(sport=502, dport=51000, flags="SA", window=1024)
    ingest_packet_record(db_session, process_packet(pkt))
    db_session.commit()

    apply_hostname_hints(db_session, [("10.0.0.50", "PLC-LINE3"), ("203.0.113.9", "unrelated-public-host")])
    db_session.commit()

    known = db_session.query(Device).filter(Device.ip == "10.0.0.50").one()
    assert known.hostname == "PLC-LINE3"
    assert known.display_name == "PLC-LINE3"

    assert db_session.query(Device).filter(Device.ip == "203.0.113.9").one_or_none() is None


def test_custom_name_overrides_auto_detected_hostname(db_session):
    device = Device(ip="10.0.0.99", hostname="auto-detected")
    db_session.add(device)
    db_session.commit()

    assert device.display_name == "auto-detected"
    device.custom_name = "Manually Renamed"
    assert device.display_name == "Manually Renamed"


def test_flow_created_and_aggregated_for_tcp_conversation(db_session):
    client_ip, server_ip = "10.0.0.5", "10.0.0.50"
    packets = [
        Ether() / IP(src=client_ip, dst=server_ip, ttl=64) / TCP(sport=51000, dport=502, flags="S", window=1024),
        Ether() / IP(src=server_ip, dst=client_ip, ttl=64) / TCP(sport=502, dport=51000, flags="SA", window=1024),
        Ether() / IP(src=client_ip, dst=server_ip, ttl=64) / TCP(sport=51000, dport=502, flags="A", window=1024),
    ]
    for pkt in packets:
        ingest_packet_record(db_session, process_packet(pkt))
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


def test_nbns_registration_enriches_existing_device_hostname(db_session):
    tcp_pkt = Ether() / IP(src="10.0.0.40", dst="10.0.0.5", ttl=64) / TCP(sport=502, dport=51000, flags="SA", window=1024)
    ingest_packet_record(db_session, process_packet(tcp_pkt))

    nbns_pkt = (
        Ether()
        / IP(src="10.0.0.40", dst="10.0.0.255")
        / UDP(sport=137, dport=137)
        / NBNSHeader(OPCODE=0x5, NM_FLAGS=0x11)
        / NBNSRegistrationRequest(QUESTION_NAME="ENGWORKSTATION", SUFFIX="workstation", NB_ADDRESS="10.0.0.40")
    )
    ingest_packet_record(db_session, process_packet(nbns_pkt))
    db_session.commit()

    device = db_session.query(Device).filter(Device.ip == "10.0.0.40").one()
    assert device.hostname == "ENGWORKSTATION"


def test_cdp_announcement_creates_network_device_by_mac(db_session):
    pkt = (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="01:00:0c:cc:cc:cc")
        / LLC()
        / SNAP(OUI=0xC, code=0x2000)
        / CDPv2_HDR(msg=[CDPMsgDeviceID(val=b"switch1.corp.local")])
    )
    ingest_packet_record(db_session, process_packet(Ether(bytes(pkt))))
    db_session.commit()

    device = db_session.query(Device).filter(Device.mac == "aa:bb:cc:dd:ee:ff").one()
    assert device.ip is None
    assert device.hostname == "switch1.corp.local"
    assert device.os_guess == "Network appliance (router/switch/firewall)"
    assert device.os_confidence == 1.0


def test_lldp_announcement_creates_network_device_by_mac(db_session):
    pkt = (
        Ether(src="10:22:33:44:55:66", dst="01:80:c2:00:00:0e", type=0x88CC)
        / LLDPDUChassisID(subtype=4, id=b"\x10\x22\x33\x44\x55\x66")
        / LLDPDUPortID(subtype=1, id=b"Gi0/1")
        / LLDPDUTimeToLive(ttl=120)
        / LLDPDUSystemName(system_name=b"switch2-access")
        / LLDPDUEndOfLLDPDU()
    )
    ingest_packet_record(db_session, process_packet(Ether(bytes(pkt))))
    db_session.commit()

    device = db_session.query(Device).filter(Device.mac == "10:22:33:44:55:66").one()
    assert device.ip is None
    assert device.hostname == "switch2-access"
    assert device.os_guess == "Network appliance (router/switch/firewall)"


def test_cdp_discovered_switch_merges_with_later_ip_traffic(db_session):
    """A switch first seen only via CDP (no IP) should be enriched, not
    duplicated, once the same MAC is later seen sending real IP traffic."""
    cdp_pkt = (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="01:00:0c:cc:cc:cc")
        / LLC()
        / SNAP(OUI=0xC, code=0x2000)
        / CDPv2_HDR(msg=[CDPMsgDeviceID(val=b"switch1.corp.local")])
    )
    ingest_packet_record(db_session, process_packet(Ether(bytes(cdp_pkt))))
    db_session.commit()

    ip_pkt = Ether(src="aa:bb:cc:dd:ee:ff") / IP(src="10.0.0.9", dst="10.0.0.5", ttl=255) / TCP(
        sport=22, dport=51000, flags="SA", window=4096
    )
    ingest_packet_record(db_session, process_packet(ip_pkt))
    db_session.commit()

    devices = db_session.query(Device).filter(Device.mac == "aa:bb:cc:dd:ee:ff").all()
    assert len(devices) == 1
    assert devices[0].ip == "10.0.0.9"
    assert devices[0].hostname == "switch1.corp.local"
