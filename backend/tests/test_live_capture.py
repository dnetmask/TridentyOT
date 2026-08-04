"""Exercises the producer/consumer queue+batch pipeline in
app.capture.live_capture directly, without a real network interface (no
raw-socket capture privileges in CI) -- these tests start only the
consumer thread and feed it PacketRecords the way the real AsyncSniffer
callback would, via the worker's internals."""

import queue
import time

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from app.capture.live_capture import _CaptureWorker
from app.capture.packet_processor import process_packet
from app.models import CaptureSession, Device, utcnow


def _make_record(src_ip: str, dst_ip: str, dport: int = 502):
    pkt = Ether() / IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=41000, dport=dport, flags="S", window=1024)
    return process_packet(pkt)


def _running_session(db_session, org_id) -> CaptureSession:
    session_obj = CaptureSession(
        organization_id=org_id, name="live:eth0", source_type="live", source="eth0", status="running",
        started_at=utcnow(),
    )
    db_session.add(session_obj)
    db_session.commit()
    db_session.refresh(session_obj)
    return session_obj


def _wait_until(predicate, timeout=2.0, interval=0.02):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def test_worker_batches_queued_records_into_the_database(db_session, org_id):
    session_obj = _running_session(db_session, org_id)
    worker = _CaptureWorker(session_obj.id, interface="dummy0", bpf_filter=None)

    for i in range(5):
        worker._queue.put(_make_record(f"10.0.9.{10 + i}", "10.0.9.200"))

    worker._consumer_thread.start()
    try:

        def _done():
            db_session.refresh(session_obj)
            return session_obj.packet_count >= 5

        assert _wait_until(_done), f"packet_count stuck at {session_obj.packet_count}"
    finally:
        worker._stop_event.set()
        worker._consumer_thread.join(timeout=2)

    assert session_obj.packet_count == 5
    assert session_obj.dropped_count == 0
    # ingest_packet_record actually ran against the shared DB, not just counted
    assert db_session.query(Device).filter(Device.ip == "10.0.9.200").one_or_none() is not None


def test_worker_counts_drops_once_the_queue_is_full(db_session, org_id):
    session_obj = _running_session(db_session, org_id)
    worker = _CaptureWorker(session_obj.id, interface="dummy0", bpf_filter=None)
    worker._queue = queue.Queue(maxsize=2)  # force overflow with few packets

    # Nothing is draining the queue yet, so the 3rd packet must be dropped.
    for i in range(3):
        worker._on_packet(
            Ether() / IP(src=f"10.0.9.{20 + i}", dst="10.0.9.200", ttl=64) / TCP(sport=1, dport=2, flags="S")
        )
    assert worker._dropped_since_last_batch == 1

    worker._consumer_thread.start()
    try:

        def _done():
            db_session.refresh(session_obj)
            return session_obj.dropped_count >= 1

        assert _wait_until(_done), f"dropped_count stuck at {session_obj.dropped_count}"
    finally:
        worker._stop_event.set()
        worker._consumer_thread.join(timeout=2)

    assert session_obj.packet_count == 2
    assert session_obj.dropped_count == 1


def test_stop_flushes_whatever_is_still_queued(db_session, org_id):
    """Stopping mid-flight must still ingest everything already queued --
    a capture the operator explicitly stopped shouldn't silently lose the
    last batch just because the consumer hadn't gotten to it yet."""
    session_obj = _running_session(db_session, org_id)
    worker = _CaptureWorker(session_obj.id, interface="dummy0", bpf_filter=None)

    for i in range(10):
        worker._queue.put(_make_record(f"10.0.9.{30 + i}", "10.0.9.201"))

    worker._consumer_thread.start()
    # Signal stop essentially immediately -- the point is that the final
    # flush drains what's queued rather than abandoning it.
    worker._stop_event.set()
    worker._consumer_thread.join(timeout=2)

    db_session.refresh(session_obj)
    assert session_obj.packet_count == 10
