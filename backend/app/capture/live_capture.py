"""Live packet capture on a network interface, listening directly on the
wire (e.g. a SPAN/mirror port on an OT switch) using scapy's AsyncSniffer --
the same libpcap machinery underneath tcpdump/wireshark/tshark.

Requires the process to have raw-socket capture privileges (root, or
CAP_NET_RAW+CAP_NET_ADMIN on Linux, e.g. via `setcap` on the python
interpreter) and, in most environments, that tcpdump/libpcap is installed.
"""

import threading

from scapy.sendrecv import AsyncSniffer

from app.capture.packet_processor import process_packet
from app.db import session_scope
from app.inventory.inventory_service import ingest_packet_record
from app.models import CaptureSession


class LiveCaptureManager:
    def __init__(self) -> None:
        self._sniffers: dict[int, AsyncSniffer] = {}
        self._lock = threading.Lock()

    def start(self, capture_session_id: int, interface: str, bpf_filter: str | None) -> None:
        def on_packet(pkt) -> None:
            record = process_packet(pkt)
            if record is None:
                return
            with session_scope() as db:
                capture_session = db.get(CaptureSession, capture_session_id)
                if capture_session is None or capture_session.status != "running":
                    return
                ingest_packet_record(db, record)
                capture_session.packet_count += 1

        try:
            sniffer = AsyncSniffer(iface=interface, filter=bpf_filter or None, prn=on_packet, store=False)
            sniffer.start()
        except Exception as exc:
            raise RuntimeError(f"Could not start capture on interface '{interface}': {exc}") from exc

        with self._lock:
            self._sniffers[capture_session_id] = sniffer

    def stop(self, capture_session_id: int) -> bool:
        with self._lock:
            sniffer = self._sniffers.pop(capture_session_id, None)
        if sniffer is None:
            return False
        sniffer.stop()
        return True

    def is_running(self, capture_session_id: int) -> bool:
        with self._lock:
            return capture_session_id in self._sniffers

    def stop_all(self) -> None:
        with self._lock:
            session_ids = list(self._sniffers.keys())
        for session_id in session_ids:
            self.stop(session_id)


live_capture_manager = LiveCaptureManager()
