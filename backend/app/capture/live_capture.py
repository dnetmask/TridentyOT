"""Live packet capture on a network interface, listening directly on the
wire (e.g. a SPAN/mirror port on an OT switch) using scapy's AsyncSniffer --
the same libpcap machinery underneath tcpdump/wireshark/tshark.

Requires the process to have raw-socket capture privileges (root, or
CAP_NET_RAW+CAP_NET_ADMIN on Linux, e.g. via `setcap` on the python
interpreter) and, in most environments, that tcpdump/libpcap is installed.

Capture and database writes run on two different threads, connected by a
bounded queue, rather than one DB transaction per packet on Scapy's own
capture thread:

  AsyncSniffer thread            consumer thread
  (process_packet only) --queue--> (batched ingest_packet_record + 1 commit)

A DB round-trip is milliseconds; a busy SPAN port delivers packets far
faster than that. If the capture callback did the DB write itself, any
slowness there stalls the *reading* of packets too, and libpcap's own
kernel-side buffer -- not this queue -- starts silently dropping frames
before this process ever sees them. Decoupling the two means the consumer
falling behind only ever drops from a queue we can *count*, never
invisibly inside the kernel.
"""

import datetime
import logging
import queue
import threading
import time

from scapy.sendrecv import AsyncSniffer

from app.capture.packet_processor import PacketRecord, process_packet
from app.db import session_scope
from app.i18n import bilingual, encode_i18n
from app.inventory.inventory_service import IngestCache, apply_gateway_detection, ingest_packet_record
from app.models import CaptureSession

logger = logging.getLogger(__name__)

# Bound the queue so a consumer that falls permanently behind (DB down,
# disk full) can't grow memory without limit -- it drops instead (counted
# in CaptureSession.dropped_count) once full.
QUEUE_MAXSIZE = 20_000

# One DB transaction per this many records, or this many seconds of
# waiting for the queue to fill up, whichever comes first -- keeps
# latency (how stale the UI's view of a live capture gets) bounded even
# when traffic is light.
BATCH_MAX_RECORDS = 500
BATCH_MAX_SECONDS = 0.2


class _CaptureWorker:
    """Owns one AsyncSniffer plus the background thread that drains its
    queue into the database in batches."""

    def __init__(self, capture_session_id: int, interface: str, bpf_filter: str | None) -> None:
        self.capture_session_id = capture_session_id
        self._queue: queue.Queue[PacketRecord] = queue.Queue(maxsize=QUEUE_MAXSIZE)
        self._stop_event = threading.Event()
        self._dropped_lock = threading.Lock()
        self._dropped_since_last_batch = 0
        self._consumer_thread = threading.Thread(
            target=self._consume_loop, name=f"capture-consumer-{capture_session_id}", daemon=True
        )
        self._sniffer = AsyncSniffer(iface=interface, filter=bpf_filter or None, prn=self._on_packet, store=False)

    def start(self) -> None:
        self._consumer_thread.start()
        try:
            self._sniffer.start()
        except Exception:
            # Started the consumer thread already -- if the sniffer itself
            # fails to come up (bad interface, no capture privileges), stop
            # it too rather than leaking a thread that busy-polls an empty
            # queue for the rest of the process's life.
            self._stop_event.set()
            self._consumer_thread.join(timeout=5)
            raise

    def stop(self) -> None:
        self._sniffer.stop()
        self._stop_event.set()
        self._consumer_thread.join(timeout=5)

    # -- producer: runs on Scapy's own capture thread ------------------

    def _on_packet(self, pkt) -> None:
        # Cheap and CPU-only, no I/O: process_packet() just dissects the
        # packet already in memory. Handing the result to the queue and
        # returning immediately is what keeps this thread free to keep
        # reading off the wire instead of blocking on a DB write.
        record = process_packet(pkt)
        if record is None:
            return
        try:
            self._queue.put_nowait(record)
        except queue.Full:
            with self._dropped_lock:
                self._dropped_since_last_batch += 1

    # -- consumer: runs on its own thread -------------------------------

    def _consume_loop(self) -> None:
        while True:
            batch = self._drain_batch()
            if batch:
                # A batch that fails to commit (e.g. a value violating a
                # column constraint -- see the devices.firmware_version
                # VARCHAR-length incident this guards against) must not
                # kill this thread: an unhandled exception here is a
                # daemon thread dying silently, with the sniffer left
                # running and no consumer left to drain its queue -- from
                # the UI, a capture that simply stops advancing forever,
                # with no error shown anywhere. Losing the one bad batch
                # and continuing is far better than that.
                try:
                    self._ingest_batch(batch)
                except Exception:
                    logger.exception(
                        "Capture session %d: failed to ingest a batch of %d record(s); dropping it and continuing",
                        self.capture_session_id,
                        len(batch),
                    )
                    with self._dropped_lock:
                        self._dropped_since_last_batch += len(batch)
            elif self._stop_event.is_set():
                return

    def _drain_batch(self) -> list[PacketRecord]:
        batch: list[PacketRecord] = []
        if self._stop_event.is_set():
            # Final flush: grab whatever's left right now rather than
            # waiting for more that will never arrive.
            while len(batch) < BATCH_MAX_RECORDS:
                try:
                    batch.append(self._queue.get_nowait())
                except queue.Empty:
                    break
            return batch

        deadline = time.monotonic() + BATCH_MAX_SECONDS
        while len(batch) < BATCH_MAX_RECORDS:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                batch.append(self._queue.get(timeout=remaining))
            except queue.Empty:
                break
        return batch

    def _ingest_batch(self, batch: list[PacketRecord]) -> None:
        with self._dropped_lock:
            dropped = self._dropped_since_last_batch
            self._dropped_since_last_batch = 0

        with session_scope() as db:
            capture_session = db.get(CaptureSession, self.capture_session_id)
            if capture_session is None or capture_session.status != "running":
                return
            # Scoped to this one batch, not the capture session as a whole:
            # session_scope() opens a fresh Session per batch, and a cached
            # ORM object doesn't survive past the Session that loaded it.
            # Still a real win within a batch of up to BATCH_MAX_RECORDS --
            # e.g. a PLC's polling loop hits the same device/protocol/flow
            # repeatedly inside that window (see IngestCache's docstring).
            cache = IngestCache()
            for record in batch:
                ingest_packet_record(
                    db,
                    record,
                    organization_id=capture_session.organization_id,
                    capture_session_id=self.capture_session_id,
                    cache=cache,
                    sensor_id=capture_session.sensor_id,
                )
            # Whole-table pass, not per-packet: the router/NAT gateway
            # pattern (one MAC shared by several public IPs) only shows up
            # once enough distinct public IPs have accumulated, which no
            # single packet's ingest can tell on its own.
            apply_gateway_detection(db, capture_session.organization_id)
            capture_session.packet_count += len(batch)
            capture_session.dropped_count += dropped


class LiveCaptureManager:
    def __init__(self) -> None:
        self._workers: dict[int, _CaptureWorker] = {}
        self._lock = threading.Lock()

    def start(self, capture_session_id: int, interface: str, bpf_filter: str | None) -> None:
        worker = _CaptureWorker(capture_session_id, interface, bpf_filter)
        try:
            worker.start()
        except Exception as exc:
            raise RuntimeError(f"Could not start capture on interface '{interface}': {exc}") from exc

        with self._lock:
            self._workers[capture_session_id] = worker

    def stop(self, capture_session_id: int) -> bool:
        with self._lock:
            worker = self._workers.pop(capture_session_id, None)
        if worker is None:
            return False
        worker.stop()
        return True

    def is_running(self, capture_session_id: int) -> bool:
        with self._lock:
            return capture_session_id in self._workers

    def stop_all(self) -> None:
        with self._lock:
            session_ids = list(self._workers.keys())
        for session_id in session_ids:
            self.stop(session_id)


live_capture_manager = LiveCaptureManager()


def mark_orphaned_live_sessions_stopped() -> None:
    """Called once at app startup. `live_capture_manager`, `nmap_scan_manager`
    (see app/capture/nmap_discovery.py) and `snmp_scan_manager`/
    `snmp_walk_manager` (see app/capture/snmp_discovery.py) are always empty
    at this point -- fresh in-memory objects -- so any live capture or
    active-discovery scan session still marked "running" in the database is
    necessarily a leftover from a previous process (e.g. the server was
    restarted or crashed mid-capture/mid-scan). Left alone, the "Detener"
    button for one of these used to 409 forever, since there was never a
    real sniffer/subprocess/sweep left to stop.
    """
    with session_scope() as db:
        orphaned = (
            db.query(CaptureSession)
            .filter(
                CaptureSession.source_type.in_(["live", "active_nmap", "active_snmp", "active_snmp_walk"]),
                CaptureSession.status == "running",
            )
            .all()
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        for session_obj in orphaned:
            session_obj.status = "stopped"
            session_obj.ended_at = now
            session_obj.error_message = encode_i18n(
                bilingual(
                    es="Interrumpida: el servidor se reinició mientras esta captura/escaneo estaba activo.",
                    en="Interrupted: the server restarted while this capture/scan was active.",
                )
            )
