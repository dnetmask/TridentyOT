from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from app.capture.live_capture import mark_orphaned_live_sessions_stopped
from app.models import CaptureSession, utcnow


def test_delete_session_removes_it(client, tmp_path):
    syn = Ether() / IP(src="10.0.0.5", dst="10.0.0.50", ttl=64) / TCP(sport=41000, dport=502, flags="S", window=1024)
    pcap_path = tmp_path / "s.pcap"
    wrpcap(str(pcap_path), [syn])
    with open(pcap_path, "rb") as f:
        session_id = client.post(
            "/api/capture/pcap", files={"file": ("s.pcap", f, "application/vnd.tcpdump.pcap")}
        ).json()["id"]

    assert client.get(f"/api/capture/sessions/{session_id}").status_code == 200
    resp = client.delete(f"/api/capture/sessions/{session_id}")
    assert resp.status_code == 204
    assert client.get(f"/api/capture/sessions/{session_id}").status_code == 404


def test_delete_unknown_session_is_404(client):
    assert client.delete("/api/capture/sessions/999999").status_code == 404


def test_deleting_session_removes_its_devices_protocols_flows_and_findings(client, tmp_path):
    syn = Ether() / IP(src="10.0.1.5", dst="10.0.1.100", ttl=64) / TCP(
        sport=41000, dport=23, flags="S", window=1024
    )
    pcap_path = tmp_path / "telnet.pcap"
    wrpcap(str(pcap_path), [syn])
    with open(pcap_path, "rb") as f:
        session_id = client.post(
            "/api/capture/pcap", files={"file": ("telnet.pcap", f, "application/vnd.tcpdump.pcap")}
        ).json()["id"]

    assert len(client.get("/api/inventory/devices").json()) == 2
    assert len(client.get("/api/inventory/flows").json()) == 1

    scan_findings = client.post("/api/vuln/scan", json={"use_nvd": False}).json()
    assert any(f["title"].lower().count("telnet") for f in scan_findings)
    assert len(client.get("/api/vuln/findings").json()) >= 1

    assert client.delete(f"/api/capture/sessions/{session_id}").status_code == 204

    assert client.get("/api/inventory/devices").json() == []
    assert client.get("/api/inventory/flows").json() == []
    assert client.get("/api/vuln/findings").json() == []


def test_deleting_session_keeps_a_device_still_referenced_by_another_session(client, tmp_path):
    """A client IP that appears in two separate captures, talking to a
    different server in each, must survive deleting the first capture --
    the second capture's flow still references it -- while the
    first capture's own, now-unreferenced server device must go."""
    first_syn = Ether() / IP(src="10.0.1.5", dst="10.0.1.100", ttl=64) / TCP(
        sport=41000, dport=502, flags="S", window=1024
    )
    first_pcap = tmp_path / "first.pcap"
    wrpcap(str(first_pcap), [first_syn])
    with open(first_pcap, "rb") as f:
        first_session_id = client.post(
            "/api/capture/pcap", files={"file": ("first.pcap", f, "application/vnd.tcpdump.pcap")}
        ).json()["id"]

    second_syn = Ether() / IP(src="10.0.1.5", dst="10.0.1.200", ttl=64) / TCP(
        sport=41001, dport=23, flags="S", window=1024
    )
    second_pcap = tmp_path / "second.pcap"
    wrpcap(str(second_pcap), [second_syn])
    with open(second_pcap, "rb") as f:
        client.post("/api/capture/pcap", files={"file": ("second.pcap", f, "application/vnd.tcpdump.pcap")})

    devices_before = client.get("/api/inventory/devices").json()
    assert {d["ip"] for d in devices_before} == {"10.0.1.5", "10.0.1.100", "10.0.1.200"}
    assert len(client.get("/api/inventory/flows").json()) == 2

    assert client.delete(f"/api/capture/sessions/{first_session_id}").status_code == 204

    devices_after = client.get("/api/inventory/devices").json()
    assert {d["ip"] for d in devices_after} == {"10.0.1.5", "10.0.1.200"}

    flows_after = client.get("/api/inventory/flows").json()
    assert len(flows_after) == 1
    assert flows_after[0]["port"] == 23


def test_stopping_a_session_the_manager_no_longer_tracks_still_succeeds(client, db_session):
    """Regression test: previously, if the in-process live_capture_manager
    had lost track of a session (e.g. after a server restart left it stuck
    as "running" in the database), calling /live/stop used to 409 forever
    with no way to clear it. It must now succeed unconditionally for any
    live-type session."""
    orphaned = CaptureSession(
        name="live:eth0", source_type="live", source="eth0", status="running", started_at=utcnow()
    )
    db_session.add(orphaned)
    db_session.commit()
    db_session.refresh(orphaned)

    resp = client.post(f"/api/capture/live/stop/{orphaned.id}")
    assert resp.status_code == 200
    assert resp.json()["status"] == "stopped"


def test_stopping_a_non_live_session_is_rejected(client, tmp_path):
    syn = Ether() / IP(src="10.0.0.5", dst="10.0.0.50", ttl=64) / TCP(sport=41000, dport=502, flags="S", window=1024)
    pcap_path = tmp_path / "s.pcap"
    wrpcap(str(pcap_path), [syn])
    with open(pcap_path, "rb") as f:
        session_id = client.post(
            "/api/capture/pcap", files={"file": ("s.pcap", f, "application/vnd.tcpdump.pcap")}
        ).json()["id"]

    resp = client.post(f"/api/capture/live/stop/{session_id}")
    assert resp.status_code == 400


def test_orphaned_live_sessions_are_swept_to_stopped_on_startup(db_session):
    """mark_orphaned_live_sessions_stopped() is what main.py's lifespan
    calls at startup, when live_capture_manager is guaranteed to be a
    fresh, empty tracker -- so any "running" live session at that point is
    necessarily a leftover from a previous process."""
    orphaned = CaptureSession(
        name="live:eth0", source_type="live", source="eth0", status="running", started_at=utcnow()
    )
    still_running_pcap = CaptureSession(  # not a live session: must be left alone
        name="upload.pcap", source_type="pcap", source="upload.pcap", status="running", started_at=utcnow()
    )
    already_stopped = CaptureSession(
        name="live:eth1", source_type="live", source="eth1", status="stopped", started_at=utcnow()
    )
    db_session.add_all([orphaned, still_running_pcap, already_stopped])
    db_session.commit()
    db_session.refresh(orphaned)
    db_session.refresh(still_running_pcap)

    mark_orphaned_live_sessions_stopped()

    db_session.refresh(orphaned)
    db_session.refresh(still_running_pcap)
    assert orphaned.status == "stopped"
    assert orphaned.error_message is not None
    assert still_running_pcap.status == "running"  # untouched: not a live session
