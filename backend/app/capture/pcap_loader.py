"""Offline analysis of previously captured .pcap/.pcapng files.

Used both for the "upload a capture" API flow and for local development in
sandboxed environments where sniffing live network traffic isn't possible.
"""

import datetime
import os
import time

from scapy.utils import PcapReader
from sqlalchemy.orm import Session

from app.capture.packet_processor import process_packet
from app.inventory.inventory_service import (
    IngestCache,
    apply_flow_link_candidates,
    apply_gateway_detection,
    apply_segment_classification,
    ingest_packet_record,
)
from app.models import CaptureSession

# Minimum wall-clock time between progress commits. This is a *time* bound,
# not a packet-count one, on purpose: get_or_create_device() explicitly
# flushes as soon as it creates a new device (see inventory_service.py), so
# SQLite's one write transaction opens the moment the first new device in
# a batch is seen and stays open -- holding the one write lock SQLite
# allows -- until the next commit() here. A packet-count interval (e.g.
# "every 500 packets") doesn't bound how long that stays open: a file with
# heavy device churn or slow per-packet classification can turn 500
# packets into many seconds with the lock held the whole time.
# Checking wall-clock time instead bounds the worst case to roughly this
# interval regardless of how slow or device-heavy the file turns out to be.
_PROGRESS_COMMIT_INTERVAL_SECONDS = 1.0

# After each periodic commit, yield the write lock for a moment before
# reopening a transaction on the next packet. Without this, this thread is
# CPU-bound enough to reliably reacquire SQLite's one write lock before a
# competing writer elsewhere (e.g. a login inserting an auth_tokens row)
# ever gets scheduled -- classic writer starvation: PRAGMA busy_timeout
# (db.py) only helps a waiter that actually gets a chance to retry *during*
# a released window, and a window measured in microseconds most retries
# never land in. A real (if brief) sleep here is what actually gives a
# blocked writer a fair shot at the lock instead of just timing out.
_LOCK_YIELD_SECONDS = 0.05


def process_pcap_file(db_session: Session, filepath: str, capture_session: CaptureSession) -> None:
    count = 0
    # One cache for the whole file: real traffic re-touches the same
    # handful of devices/protocols/flows on nearly every packet, and
    # without this ingest_packet_record re-queries the database for that
    # same row every single time -- cheap against SQLite's in-process
    # access, but dominant at Postgres's per-round-trip latency (see
    # IngestCache's docstring; this is what turned a 97MB pcap's ~2-4
    # minute upload into 40+ minutes after the move to Postgres).
    cache = IngestCache()
    try:
        capture_session.total_bytes = os.path.getsize(filepath)
        db_session.commit()
        last_commit = time.monotonic()
        with PcapReader(filepath) as reader:
            for pkt in reader:
                record = process_packet(pkt)
                if record is not None:
                    ingest_packet_record(
                        db_session,
                        record,
                        organization_id=capture_session.organization_id,
                        capture_session_id=capture_session.id,
                        cache=cache,
                        sensor_id=capture_session.sensor_id,
                    )
                count += 1
                now = time.monotonic()
                if now - last_commit >= _PROGRESS_COMMIT_INTERVAL_SECONDS:
                    capture_session.packet_count = count
                    # PcapReader and PcapNgReader both keep the underlying
                    # file object on .f -- its read position is the
                    # simplest available proxy for "how much of the file
                    # is done", since neither format's header carries a
                    # packet count to divide by instead.
                    capture_session.bytes_processed = reader.f.tell()
                    db_session.commit()
                    time.sleep(_LOCK_YIELD_SECONDS)
                    last_commit = time.monotonic()
        # Whole-table pass: the router/NAT gateway pattern (one MAC shared
        # by several public IPs) only shows up once the file has been read
        # in full, not from any single packet.
        apply_gateway_detection(db_session, capture_session.organization_id)
        apply_segment_classification(db_session, capture_session.organization_id)
        apply_flow_link_candidates(db_session, capture_session.organization_id)
        capture_session.packet_count = count
        capture_session.bytes_processed = capture_session.total_bytes
        capture_session.status = "completed"
    except Exception as exc:
        # If the failure was a DB-level error (a flush/commit that violated
        # a constraint, e.g. the devices.firmware_version VARCHAR-length
        # incident this pattern guards against generally), the session's
        # transaction is left in a failed state on Postgres -- any further
        # statement on it raises "current transaction is aborted" until an
        # explicit rollback. Without this, the finally block's own commit()
        # below would raise *that* new exception instead, which propagates
        # out of this function entirely uncaught (nothing above this frame
        # catches it either -- see routes_capture.py's background task).
        # The capture_session row would then never actually reach status
        # "error": it freezes at whatever the last successful progress
        # commit recorded, indistinguishable in the UI from a capture still
        # quietly running.
        db_session.rollback()
        capture_session.status = "error"
        capture_session.error_message = str(exc)
        capture_session.packet_count = count
    finally:
        capture_session.ended_at = datetime.datetime.now(datetime.timezone.utc)
        db_session.commit()
