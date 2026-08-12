"""Tests for active discovery via a real `nmap` scan -- see
app/capture/nmap_discovery.py and app/api/routes_discovery.py.

Runs actual `nmap` against a throwaway TCP listener on loopback (not a
mock): _NMAP_ARGS is monkeypatched to target that exact port directly
(-p) instead of relying on it falling inside nmap's default "fast" port
list, which decouples the test from nmap version/build quirks about
exactly which ~100 ports -F covers.

Unlike PROFINET DCP, this scan has no fixed duration and runs in a real
background thread (NmapScanManager), not a FastAPI BackgroundTask -- so
TestClient's "runs background tasks before the response returns" trick
doesn't apply here, and these tests poll for completion the same way a
real browser client would.
"""

import socket
import threading
import time

import app.capture.nmap_discovery as nmap_discovery


def _listen_on_loopback() -> tuple[socket.socket, int]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]

    def _accept_loop():
        while True:
            try:
                conn, _ = sock.accept()
            except OSError:
                return
            conn.close()

    threading.Thread(target=_accept_loop, daemon=True).start()
    return sock, port


def _wait_until_done(client, session_id, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        session = client.get(f"/api/capture/sessions/{session_id}").json()
        if session["status"] != "running":
            return session
        time.sleep(0.2)
    raise AssertionError(f"session {session_id} did not finish within {timeout}s")


def test_nmap_scan_discovers_an_open_port(client, db_session, monkeypatch):
    from app.models import Sensor

    sock, port = _listen_on_loopback()
    monkeypatch.setattr(
        nmap_discovery, "_NMAP_ARGS", ["-T4", "-p", str(port), "-sV", "--version-light", "-O", "-v"]
    )
    try:
        sensor = db_session.query(Sensor).filter(Sensor.name == "Sensor interno").one()

        resp = client.post("/api/discovery/nmap", json={"target": "127.0.0.1", "sensor_id": sensor.id})
        assert resp.status_code == 200, resp.text
        session = resp.json()
        assert session["source_type"] == "active_nmap"
        assert session["status"] == "running"

        finished = _wait_until_done(client, session["id"])
        assert finished["status"] == "completed", finished
        assert finished["packet_count"] == 1  # repurposed as "hosts identified" -- see run_nmap_scan
        assert finished["progress_percent"] == 100.0

        devices = client.get("/api/inventory/devices").json()
        matches = [d for d in devices if d["ip"] == "127.0.0.1"]
        assert len(matches) == 1, devices
        device = matches[0]
        assert device["protocol_count"] >= 1

        detail = client.get(f"/api/inventory/devices/{device['id']}").json()
        assert any(p["port"] == port for p in detail["protocols"]), detail["protocols"]
    finally:
        sock.close()


def test_nmap_scan_progress_updates_while_running(client, db_session, monkeypatch):
    """The whole point of dropping the fixed duration: progress climbs
    live instead of only being knowable once the scan is fully done."""
    from app.models import Sensor

    # A held-open connection makes nmap take noticeably longer on this one
    # port (RST doesn't arrive immediately), giving the test a window to
    # observe a "running" session with an in-between progress reading.
    monkeypatch.setattr(
        nmap_discovery, "_NMAP_ARGS", ["-T4", "-p", "1-50", "-sV", "--version-light", "-v"]
    )
    sensor = db_session.query(Sensor).filter(Sensor.name == "Sensor interno").one()

    resp = client.post("/api/discovery/nmap", json={"target": "127.0.0.1", "sensor_id": sensor.id})
    assert resp.status_code == 200, resp.text
    session_id = resp.json()["id"]

    saw_total = False
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        session = client.get(f"/api/capture/sessions/{session_id}").json()
        if session["total_bytes"] == 1:  # a single target (127.0.0.1) -- set as soon as the worker starts
            saw_total = True
        if session["status"] != "running":
            break
        time.sleep(0.2)
    assert saw_total, "expected total_bytes (target count) to be set while running"


def test_nmap_scan_can_be_stopped(client, db_session, monkeypatch):
    from app.models import Sensor

    # A big, slow-ish range so the scan is still "running" by the time
    # this test calls stop -- deliberately never reaching completion on
    # its own within the test.
    monkeypatch.setattr(
        nmap_discovery, "_NMAP_ARGS", ["-T4", "-p", "1-100", "--scan-delay", "300ms"]
    )
    sensor = db_session.query(Sensor).filter(Sensor.name == "Sensor interno").one()

    resp = client.post("/api/discovery/nmap", json={"target": "127.0.0.1/30", "sensor_id": sensor.id})
    assert resp.status_code == 200, resp.text
    session_id = resp.json()["id"]
    time.sleep(1)  # let the worker actually launch the nmap subprocess

    stop_resp = client.post(f"/api/discovery/nmap/stop/{session_id}")
    assert stop_resp.status_code == 200, stop_resp.text

    finished = _wait_until_done(client, session_id, timeout=20)
    assert finished["status"] == "stopped", finished


def test_nmap_scan_rejects_an_external_sensor(client):
    site = client.post("/api/sites", json={"name": "Planta Externa"}).json()
    zone = client.post("/api/zones", json={"site_id": site["id"], "name": "Zona externa"}).json()
    sensor = client.post(
        "/api/sensors", json={"zone_id": zone["id"], "name": "Sensor externo", "kind": "external"}
    ).json()

    resp = client.post("/api/discovery/nmap", json={"target": "127.0.0.1", "sensor_id": sensor["id"]})
    assert resp.status_code == 400


def test_nmap_scan_requires_admin(client, make_client, db_session):
    from app.models import Sensor

    sensor = db_session.query(Sensor).filter(Sensor.name == "Sensor interno").one()
    client.post("/api/users", json={"username": "viewer-nmap", "password": "secret1", "role": "viewer"})
    viewer = make_client("viewer-nmap", "secret1")

    resp = viewer.post("/api/discovery/nmap", json={"target": "127.0.0.1", "sensor_id": sensor.id})
    assert resp.status_code == 403


def test_nmap_scan_rejects_another_organizations_sensor(client, db_session):
    from app.auth import ROLE_ADMIN
    from app.auth.security import hash_password
    from app.models import Organization, Sensor, Site, User, Zone

    org = Organization(name="Org B", slug="org-b-nmap")
    db_session.add(org)
    db_session.flush()
    site = Site(organization_id=org.id, name="Site B")
    db_session.add(site)
    db_session.flush()
    zone = Zone(site_id=site.id, name="Zone B")
    db_session.add(zone)
    db_session.flush()
    sensor = Sensor(zone_id=zone.id, name="Sensor B")
    db_session.add(sensor)
    salt, password_hash = hash_password("secret123")
    db_session.add(
        User(organization_id=org.id, username="org-b-nmap-admin", password_salt=salt, password_hash=password_hash, role=ROLE_ADMIN)
    )
    db_session.commit()

    resp = client.post("/api/discovery/nmap", json={"target": "127.0.0.1", "sensor_id": sensor.id})
    assert resp.status_code == 404


def test_nmap_scan_requires_a_target(client, db_session):
    from app.models import Sensor

    sensor = db_session.query(Sensor).filter(Sensor.name == "Sensor interno").one()
    resp = client.post("/api/discovery/nmap", json={"target": "", "sensor_id": sensor.id})
    assert resp.status_code == 422


def test_stopping_a_non_nmap_session_is_rejected(client, tmp_path):
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.utils import wrpcap

    syn = Ether() / IP(src="10.0.1.5", dst="10.0.1.100", ttl=64) / TCP(sport=41000, dport=23, flags="S", window=1024)
    pcap_path = tmp_path / "t.pcap"
    wrpcap(str(pcap_path), [syn])
    with open(pcap_path, "rb") as f:
        session = client.post(
            "/api/capture/pcap", files={"file": ("t.pcap", f, "application/vnd.tcpdump.pcap")}
        ).json()

    resp = client.post(f"/api/discovery/nmap/stop/{session['id']}")
    assert resp.status_code == 400
