from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from app.capture.packet_processor import process_packet
from app.inventory.inventory_service import ingest_packet_record
from app.models import Device, DeviceProtocol


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
