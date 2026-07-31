from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

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

    pkt = Ether(src="ff:ff:ff:ff:ff:ff") / IP(src="255.255.255.255", dst="10.0.0.1") / UDP(sport=67, dport=68)
    ingest_packet_record(db_session, process_packet(pkt))
    db_session.commit()

    device = db_session.query(Device).filter(Device.ip == "255.255.255.255").one()
    assert device.mac is None
    assert device.vendor is None


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
