"""Tests for the fix to a real gap: CaptureSession.sensor_id was never
populated by a live/pcap capture (only by db.py's legacy-row backfill), so
there was no way to know which Sensor/Zona/Sitio produced a given capture --
every Device/Flow/VulnerabilityFinding was only ever scoped by
organization_id, meaning a pcap captured for one Sitio showed up identically
regardless of which Sitio's tree you were looking at. See routes_capture.py
(_resolve_capture_sensor, _get_owned_sensor) and the zone_id/site_id filters
added to routes_capture.list_sessions, routes_inventory.list_devices/
list_flows, and routes_vulns.list_findings.
"""

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap


def _make_site_zone_sensor(client, site_name, zone_name, sensor_name):
    site = client.post("/api/sites", json={"name": site_name}).json()
    zone = client.post("/api/zones", json={"site_id": site["id"], "name": zone_name}).json()
    sensor = client.post("/api/sensors", json={"zone_id": zone["id"], "name": sensor_name}).json()
    return site, zone, sensor


def _upload_pcap(client, tmp_path, filename, sensor_id=None, src="10.0.1.5", dst="10.0.1.100"):
    syn = Ether() / IP(src=src, dst=dst, ttl=64) / TCP(sport=41000, dport=23, flags="S", window=1024)
    pcap_path = tmp_path / filename
    wrpcap(str(pcap_path), [syn])
    data = {"sensor_id": str(sensor_id)} if sensor_id is not None else {}
    with open(pcap_path, "rb") as f:
        resp = client.post(
            "/api/capture/pcap", files={"file": (filename, f, "application/vnd.tcpdump.pcap")}, data=data
        )
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_pcap_upload_auto_picks_the_only_sensor_and_records_it(client, tmp_path):
    session = _upload_pcap(client, tmp_path, "auto.pcap")
    from app.db import SessionLocal
    from app.models import CaptureSession

    with SessionLocal() as db:
        row = db.get(CaptureSession, session["id"])
        assert row.sensor_id is not None


def test_pcap_upload_with_multiple_sensors_requires_sensor_id(client, tmp_path):
    _make_site_zone_sensor(client, "Planta B", "Zona B", "Sensor B")
    syn = Ether() / IP(src="10.0.1.5", dst="10.0.1.100", ttl=64) / TCP(
        sport=41000, dport=23, flags="S", window=1024
    )
    pcap_path = tmp_path / "ambiguous.pcap"
    wrpcap(str(pcap_path), [syn])
    with open(pcap_path, "rb") as f:
        resp = client.post("/api/capture/pcap", files={"file": ("ambiguous.pcap", f, "application/vnd.tcpdump.pcap")})
    assert resp.status_code == 400


def test_live_capture_with_multiple_sensors_requires_sensor_id(client):
    _make_site_zone_sensor(client, "Planta B", "Zona B", "Sensor B")
    resp = client.post("/api/capture/live/start", json={"interface": "lo"})
    assert resp.status_code == 400


def test_devices_are_scoped_to_the_zone_that_captured_them(client, tmp_path):
    site_a, zone_a, sensor_a = _make_site_zone_sensor(client, "Planta A", "Zona A", "Sensor A")
    site_b, zone_b, sensor_b = _make_site_zone_sensor(client, "Planta B", "Zona B", "Sensor B")

    _upload_pcap(client, tmp_path, "a.pcap", sensor_id=sensor_a["id"], src="10.0.1.5", dst="10.0.1.100")
    _upload_pcap(client, tmp_path, "b.pcap", sensor_id=sensor_b["id"], src="10.0.2.5", dst="10.0.2.100")

    devices_a = client.get(f"/api/inventory/devices?zone_id={zone_a['id']}").json()
    devices_b = client.get(f"/api/inventory/devices?zone_id={zone_b['id']}").json()
    devices_all = client.get("/api/inventory/devices").json()

    assert {d["ip"] for d in devices_a} == {"10.0.1.5", "10.0.1.100"}
    assert {d["ip"] for d in devices_b} == {"10.0.2.5", "10.0.2.100"}
    assert len(devices_all) == 4  # unfiltered view is unaffected, still org-wide


def test_devices_are_scoped_to_the_site_aggregating_its_zones(client, tmp_path):
    site_a, zone_a, sensor_a = _make_site_zone_sensor(client, "Planta A", "Zona A1", "Sensor A1")
    zone_a2 = client.post("/api/zones", json={"site_id": site_a["id"], "name": "Zona A2"}).json()
    sensor_a2 = client.post("/api/sensors", json={"zone_id": zone_a2["id"], "name": "Sensor A2"}).json()
    site_b, zone_b, sensor_b = _make_site_zone_sensor(client, "Planta B", "Zona B", "Sensor B")

    _upload_pcap(client, tmp_path, "a1.pcap", sensor_id=sensor_a["id"], src="10.0.1.5", dst="10.0.1.100")
    _upload_pcap(client, tmp_path, "a2.pcap", sensor_id=sensor_a2["id"], src="10.0.3.5", dst="10.0.3.100")
    _upload_pcap(client, tmp_path, "b.pcap", sensor_id=sensor_b["id"], src="10.0.2.5", dst="10.0.2.100")

    devices_site_a = client.get(f"/api/inventory/devices?site_id={site_a['id']}").json()
    assert {d["ip"] for d in devices_site_a} == {"10.0.1.5", "10.0.1.100", "10.0.3.5", "10.0.3.100"}


def test_capture_sessions_are_scoped_by_zone_and_site(client, tmp_path):
    site_a, zone_a, sensor_a = _make_site_zone_sensor(client, "Planta A", "Zona A", "Sensor A")
    site_b, zone_b, sensor_b = _make_site_zone_sensor(client, "Planta B", "Zona B", "Sensor B")
    session_a = _upload_pcap(client, tmp_path, "a.pcap", sensor_id=sensor_a["id"])
    session_b = _upload_pcap(client, tmp_path, "b.pcap", sensor_id=sensor_b["id"])

    ids_zone_a = {s["id"] for s in client.get(f"/api/capture/sessions?zone_id={zone_a['id']}").json()}
    ids_zone_b = {s["id"] for s in client.get(f"/api/capture/sessions?zone_id={zone_b['id']}").json()}
    assert ids_zone_a == {session_a["id"]}
    assert ids_zone_b == {session_b["id"]}

    ids_site_a = {s["id"] for s in client.get(f"/api/capture/sessions?site_id={site_a['id']}").json()}
    assert ids_site_a == {session_a["id"]}


def test_findings_are_scoped_by_zone(client, tmp_path):
    site_a, zone_a, sensor_a = _make_site_zone_sensor(client, "Planta A", "Zona A", "Sensor A")
    site_b, zone_b, sensor_b = _make_site_zone_sensor(client, "Planta B", "Zona B", "Sensor B")
    _upload_pcap(client, tmp_path, "a.pcap", sensor_id=sensor_a["id"], src="10.0.1.5", dst="10.0.1.100")
    _upload_pcap(client, tmp_path, "b.pcap", sensor_id=sensor_b["id"], src="10.0.2.5", dst="10.0.2.100")
    client.post("/api/vuln/scan", json={"use_nvd": False})

    findings_a = client.get(f"/api/vuln/findings?zone_id={zone_a['id']}").json()
    findings_b = client.get(f"/api/vuln/findings?zone_id={zone_b['id']}").json()
    findings_all = client.get("/api/vuln/findings").json()

    device_ips_a = {f["device_ip"] for f in findings_a}
    device_ips_b = {f["device_ip"] for f in findings_b}
    assert device_ips_a.isdisjoint(device_ips_b) or (not findings_a and not findings_b)
    assert len(findings_all) >= len(findings_a)


def test_cannot_use_another_organizations_sensor_id(client, db_session):
    from app.auth import ROLE_ADMIN
    from app.auth.security import hash_password
    from app.models import Organization, Sensor, Site, User, Zone

    org = Organization(name="Org B", slug="org-b")
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
        User(organization_id=org.id, username="org-b-admin", password_salt=salt, password_hash=password_hash, role=ROLE_ADMIN)
    )
    db_session.commit()

    resp = client.post("/api/capture/live/start", json={"interface": "lo", "sensor_id": sensor.id})
    assert resp.status_code == 404


def test_external_sensor_cannot_start_a_live_capture(client):
    """SENSOR_KIND_EXTERNAL means "pcap-only uploads, no live interface of
    its own" (see models.py) -- remote connectivity for it isn't built yet,
    so the only way to get its data in is a pcap upload."""
    site = client.post("/api/sites", json={"name": "Planta Externa"}).json()
    zone = client.post("/api/zones", json={"site_id": site["id"], "name": "Zona externa"}).json()
    sensor = client.post(
        "/api/sensors", json={"zone_id": zone["id"], "name": "Sensor externo", "kind": "external"}
    ).json()
    assert sensor["kind"] == "external"

    resp = client.post("/api/capture/live/start", json={"interface": "lo", "sensor_id": sensor["id"]})
    assert resp.status_code == 400


def test_external_sensor_accepts_a_pcap_upload(client, tmp_path):
    site = client.post("/api/sites", json={"name": "Planta Externa"}).json()
    zone = client.post("/api/zones", json={"site_id": site["id"], "name": "Zona externa"}).json()
    sensor = client.post(
        "/api/sensors", json={"zone_id": zone["id"], "name": "Sensor externo", "kind": "external"}
    ).json()

    session = _upload_pcap(client, tmp_path, "external.pcap", sensor_id=sensor["id"])
    from app.db import SessionLocal
    from app.models import CaptureSession

    with SessionLocal() as db:
        row = db.get(CaptureSession, session["id"])
        assert row.sensor_id == sensor["id"]


def test_live_capture_auto_pick_skips_an_external_sensor(client):
    """The seeded organization already has exactly one sensor -- the
    "Default" one db.py's startup migration creates, kind=live. Adding an
    external sensor alongside it shouldn't make live-capture auto-pick
    ambiguous: it doesn't count as a second live candidate."""
    site = client.post("/api/sites", json={"name": "Planta Mixta"}).json()
    zone = client.post("/api/zones", json={"site_id": site["id"], "name": "Zona mixta"}).json()
    client.post("/api/sensors", json={"zone_id": zone["id"], "name": "Sensor externo", "kind": "external"})

    resp = client.post("/api/capture/live/start", json={"interface": "lo"})
    assert resp.status_code == 200, resp.text
    try:
        from app.db import SessionLocal
        from app.models import CaptureSession, Sensor

        with SessionLocal() as db:
            default_sensor = db.query(Sensor).filter(Sensor.name == "Default").one()
            row = db.get(CaptureSession, resp.json()["id"])
            assert row.sensor_id == default_sensor.id
    finally:
        client.post(f"/api/capture/live/stop/{resp.json()['id']}")
