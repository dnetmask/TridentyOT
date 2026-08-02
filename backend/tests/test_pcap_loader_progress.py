import os
import threading

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from app.capture import pcap_loader
from app.capture.pcap_loader import process_pcap_file
from app.models import CaptureSession


def _make_packets(n):
    return [
        Ether() / IP(src="10.9.0.5", dst="10.9.0.6", ttl=64) / TCP(
            sport=40000 + i, dport=80, flags="S", window=1024
        )
        for i in range(n)
    ]


def _make_new_device_packets(n):
    """Each packet is a *distinct* new device, unlike _make_packets() above
    -- worst case for get_or_create_device()'s per-new-device flush() (see
    test_pcap_upload_does_not_lock_out_concurrent_writes below)."""
    return [
        Ether() / IP(src=f"10.9.{(i // 250) % 255}.{i % 250 + 1}", dst="10.9.0.1", ttl=64) / TCP(
            sport=40000 + (i % 10000), dport=80, flags="S", window=1024
        )
        for i in range(n)
    ]


def test_progress_fields_reach_100_percent_on_completion(db_session, tmp_path):
    pcap_path = tmp_path / "progress.pcap"
    wrpcap(str(pcap_path), _make_packets(3))
    session_obj = CaptureSession(name="progress.pcap", source_type="pcap", source="progress.pcap", status="running")
    db_session.add(session_obj)
    db_session.commit()
    db_session.refresh(session_obj)

    process_pcap_file(db_session, str(pcap_path), session_obj)

    db_session.refresh(session_obj)
    assert session_obj.status == "completed"
    assert session_obj.total_bytes == os.path.getsize(pcap_path)
    assert session_obj.bytes_processed == session_obj.total_bytes
    assert session_obj.progress_percent == 100.0


def test_progress_advances_across_periodic_commits(db_session, tmp_path, monkeypatch):
    """With the commit interval forced down to 0s, every packet is past
    the threshold -- bytes_processed should climb monotonically across
    multiple mid-loop commits, not just jump straight from 0 to 100 at the
    very end -- that's the whole point of exposing it while a large file
    is still being read."""
    monkeypatch.setattr(pcap_loader, "_PROGRESS_COMMIT_INTERVAL_SECONDS", 0)

    pcap_path = tmp_path / "progress2.pcap"
    wrpcap(str(pcap_path), _make_packets(9))
    session_obj = CaptureSession(name="progress2.pcap", source_type="pcap", source="progress2.pcap", status="running")
    db_session.add(session_obj)
    db_session.commit()
    db_session.refresh(session_obj)

    snapshots = []
    real_commit = db_session.commit

    def _spy_commit():
        real_commit()
        snapshots.append(session_obj.bytes_processed)

    monkeypatch.setattr(db_session, "commit", _spy_commit)

    process_pcap_file(db_session, str(pcap_path), session_obj)

    # at least: the initial total_bytes commit (0), a couple of mid-loop
    # commits, and the final one -- and it never goes backwards.
    assert len(snapshots) >= 4
    assert snapshots == sorted(snapshots)
    assert snapshots[-1] == session_obj.total_bytes
    assert any(0 < s < session_obj.total_bytes for s in snapshots)


def test_pcap_upload_does_not_lock_out_concurrent_writes(client, tmp_path):
    """Regression test: progress tracking commits periodically mid-upload,
    which briefly opens/closes SQLite's one write transaction many times
    over instead of once at the very end. get_or_create_device() flushes
    as soon as it sees a new device, so with heavy device churn (every
    packet here is a distinct new device -- the worst case) this thread
    is CPU-bound enough to reliably reacquire the write lock before any
    other writer -- e.g. a login inserting an auth_tokens row -- gets
    scheduled, starving it out for the entire PRAGMA busy_timeout window
    regardless of how short the commit interval is (see
    pcap_loader._LOCK_YIELD_SECONDS). A login attempted concurrently with
    a pcap upload must still succeed, not 500 with "database is locked"."""
    pcap_path = tmp_path / "concurrency.pcap"
    wrpcap(str(pcap_path), _make_new_device_packets(5000))

    from fastapi.testclient import TestClient

    from app.config import DEFAULT_ADMIN_PASSWORD, DEFAULT_ADMIN_USERNAME
    from app.main import app

    results = []

    def hammer_logins():
        anon = TestClient(app, raise_server_exceptions=False)
        for _ in range(6):
            r = anon.post(
                "/api/auth/login",
                json={"username": DEFAULT_ADMIN_USERNAME, "password": DEFAULT_ADMIN_PASSWORD},
            )
            results.append(r.status_code)

    t = threading.Thread(target=hammer_logins)
    t.start()

    with open(pcap_path, "rb") as f:
        upload_resp = client.post(
            "/api/capture/pcap", files={"file": ("concurrency.pcap", f, "application/vnd.tcpdump.pcap")}
        )
    t.join(timeout=30)

    assert upload_resp.status_code == 200
    assert not t.is_alive(), "login-hammering thread never finished"
    assert results, "no login attempts were recorded"
    assert all(code == 200 for code in results), f"some concurrent logins failed: {results}"
