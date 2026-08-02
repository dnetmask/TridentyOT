"""Offline analysis of previously captured .pcap/.pcapng files.

Used both for the "upload a capture" API flow and for local development in
sandboxed environments where sniffing live network traffic isn't possible.
"""

import datetime

from scapy.utils import PcapReader
from sqlalchemy.orm import Session

from app.capture.packet_processor import process_packet
from app.inventory.inventory_service import apply_gateway_detection, ingest_packet_record
from app.models import CaptureSession


def process_pcap_file(db_session: Session, filepath: str, capture_session: CaptureSession) -> None:
    count = 0
    try:
        with PcapReader(filepath) as reader:
            for pkt in reader:
                record = process_packet(pkt)
                if record is not None:
                    ingest_packet_record(db_session, record, capture_session_id=capture_session.id)
                count += 1
        # Whole-table pass: the router/NAT gateway pattern (one MAC shared
        # by several public IPs) only shows up once the file has been read
        # in full, not from any single packet.
        apply_gateway_detection(db_session)
        capture_session.packet_count = count
        capture_session.status = "completed"
    except Exception as exc:
        capture_session.status = "error"
        capture_session.error_message = str(exc)
        capture_session.packet_count = count
    finally:
        capture_session.ended_at = datetime.datetime.now(datetime.timezone.utc)
        db_session.commit()
