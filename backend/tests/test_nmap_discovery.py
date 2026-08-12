"""Tests for active discovery via a real `nmap` scan -- see
app/capture/nmap_discovery.py and app/api/routes_discovery.py.

Runs actual `nmap` against a throwaway TCP listener on loopback (not a
mock): _NMAP_ARGS is monkeypatched to target that exact port directly
(-p) instead of relying on it falling inside nmap's default "fast" port
list, which decouples the test from nmap version/build quirks about
exactly which ~100 ports -F covers.
"""

import socket
import threading

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


def test_nmap_scan_discovers_an_open_port(client, db_session, monkeypatch):
    from app.models import Sensor

    sock, port = _listen_on_loopback()
    monkeypatch.setattr(nmap_discovery, "_NMAP_ARGS", ["-T4", "-p", str(port), "-sV", "--version-light", "-O"])
    try:
        sensor = db_session.query(Sensor).filter(Sensor.name == "Sensor interno").one()

        resp = client.post(
            "/api/discovery/nmap",
            json={"target": "127.0.0.1", "sensor_id": sensor.id, "duration_seconds": 30},
        )
        assert resp.status_code == 200, resp.text
        session = resp.json()
        assert session["source_type"] == "active_nmap"

        finished = client.get(f"/api/capture/sessions/{session['id']}").json()
        assert finished["status"] == "completed", finished
        assert finished["packet_count"] == 1  # repurposed as "hosts found up" -- see run_nmap_scan

        devices = client.get("/api/inventory/devices").json()
        matches = [d for d in devices if d["ip"] == "127.0.0.1"]
        assert len(matches) == 1, devices
        device = matches[0]
        assert device["protocol_count"] >= 1

        detail = client.get(f"/api/inventory/devices/{device['id']}").json()
        assert any(p["port"] == port for p in detail["protocols"]), detail["protocols"]
    finally:
        sock.close()


def test_nmap_scan_with_no_open_ports_still_completes(client, db_session, monkeypatch):
    from app.models import Sensor

    # Nothing listens on this port -- a legitimate "found nothing" result,
    # not an error.
    monkeypatch.setattr(nmap_discovery, "_NMAP_ARGS", ["-T4", "-p", "1", "-sV", "--version-light"])
    sensor = db_session.query(Sensor).filter(Sensor.name == "Sensor interno").one()

    resp = client.post(
        "/api/discovery/nmap",
        json={"target": "127.0.0.1", "sensor_id": sensor.id, "duration_seconds": 30},
    )
    assert resp.status_code == 200, resp.text
    finished = client.get(f"/api/capture/sessions/{resp.json()['id']}").json()
    assert finished["status"] == "completed", finished


def test_nmap_scan_rejects_an_external_sensor(client):
    site = client.post("/api/sites", json={"name": "Planta Externa"}).json()
    zone = client.post("/api/zones", json={"site_id": site["id"], "name": "Zona externa"}).json()
    sensor = client.post(
        "/api/sensors", json={"zone_id": zone["id"], "name": "Sensor externo", "kind": "external"}
    ).json()

    resp = client.post(
        "/api/discovery/nmap",
        json={"target": "127.0.0.1", "sensor_id": sensor["id"], "duration_seconds": 30},
    )
    assert resp.status_code == 400


def test_nmap_scan_requires_admin(client, make_client, db_session):
    from app.models import Sensor

    sensor = db_session.query(Sensor).filter(Sensor.name == "Sensor interno").one()
    client.post("/api/users", json={"username": "viewer-nmap", "password": "secret1", "role": "viewer"})
    viewer = make_client("viewer-nmap", "secret1")

    resp = viewer.post(
        "/api/discovery/nmap",
        json={"target": "127.0.0.1", "sensor_id": sensor.id, "duration_seconds": 30},
    )
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

    resp = client.post(
        "/api/discovery/nmap",
        json={"target": "127.0.0.1", "sensor_id": sensor.id, "duration_seconds": 30},
    )
    assert resp.status_code == 404


def test_nmap_scan_duration_is_bounded(client, db_session):
    from app.models import Sensor

    sensor = db_session.query(Sensor).filter(Sensor.name == "Sensor interno").one()

    too_long = client.post(
        "/api/discovery/nmap", json={"target": "127.0.0.1", "sensor_id": sensor.id, "duration_seconds": 1000}
    )
    assert too_long.status_code == 422

    too_short = client.post(
        "/api/discovery/nmap", json={"target": "127.0.0.1", "sensor_id": sensor.id, "duration_seconds": 1}
    )
    assert too_short.status_code == 422


def test_nmap_scan_requires_a_target(client, db_session):
    from app.models import Sensor

    sensor = db_session.query(Sensor).filter(Sensor.name == "Sensor interno").one()
    resp = client.post("/api/discovery/nmap", json={"target": "", "sensor_id": sensor.id})
    assert resp.status_code == 422
