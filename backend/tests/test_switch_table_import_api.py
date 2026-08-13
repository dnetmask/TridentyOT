"""End-to-end tests for the two new endpoints backing "Topología por
switch" in Descubrimiento activo:
  - POST /api/inventory/devices (manual switch registration)
  - POST /api/discovery/switch-tables/import (parse + apply a pasted table)
See app/api/routes_inventory.py / routes_discovery.py.
"""

from app.models import CaptureSession, Device, NetworkLink, Sensor

CISCO_MAC_TABLE = """Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
   1    0011.2233.4455    DYNAMIC     Gi0/1
   1    0011.2233.4466    DYNAMIC     Gi0/2
   1    0011.2233.4477    DYNAMIC     Gi0/2
"""


def test_create_device_with_no_sensor_has_no_capture_session(client, db_session, org_id):
    resp = client.post(
        "/api/inventory/devices",
        json={"custom_name": "switch-manual", "ip": "10.9.9.1", "device_type_secondary": "switch_l2"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["custom_name"] == "switch-manual"
    assert body["display_device_type"] == "network_device"
    assert body["display_device_type_secondary"] == "switch_l2"

    device = db_session.get(Device, body["id"])
    assert device.capture_session_id is None


def test_create_device_with_sensor_id_gets_zone_attribution(client, db_session, org_id):
    sensor = db_session.query(Sensor).filter(Sensor.name == "Sensor interno").one()

    resp = client.post(
        "/api/inventory/devices",
        json={"custom_name": "switch-attributed", "ip": "10.9.9.2", "sensor_id": sensor.id},
    )
    assert resp.status_code == 200, resp.text
    device = db_session.get(Device, resp.json()["id"])
    assert device.capture_session_id is not None
    capture_session = db_session.get(CaptureSession, device.capture_session_id)
    assert capture_session.sensor_id == sensor.id
    assert capture_session.source_type == "manual_device"
    assert capture_session.status == "completed"


def test_create_device_duplicate_mac_and_ip_conflicts(client, db_session, org_id):
    first = client.post("/api/inventory/devices", json={"mac": "00:11:22:33:44:00", "ip": "10.9.9.3"})
    assert first.status_code == 200, first.text

    second = client.post("/api/inventory/devices", json={"mac": "00:11:22:33:44:00", "ip": "10.9.9.3"})
    assert second.status_code == 409


def test_create_device_rejects_sensor_from_a_different_organization(client, db_session, org_id):
    from app.models import Organization, Site, Zone

    other_org = Organization(name="Other Org", slug="other-org-switch-1")
    db_session.add(other_org)
    db_session.flush()
    other_site = Site(organization_id=other_org.id, name="Other Site")
    db_session.add(other_site)
    db_session.flush()
    other_zone = Zone(site_id=other_site.id, name="Other Zone")
    db_session.add(other_zone)
    db_session.flush()
    other_sensor = Sensor(zone_id=other_zone.id, name="Other Sensor")
    db_session.add(other_sensor)
    db_session.commit()

    resp = client.post("/api/inventory/devices", json={"ip": "10.9.9.4", "sensor_id": other_sensor.id})
    assert resp.status_code in (400, 404)


def test_import_mac_table_creates_link_and_reports_suspected_uplink(client, db_session, org_id):
    switch_resp = client.post("/api/inventory/devices", json={"custom_name": "switch-1", "ip": "10.9.9.5"})
    switch_id = switch_resp.json()["id"]

    plc = Device(organization_id=org_id, mac="00:11:22:33:44:55", ip="10.0.1.10")
    db_session.add(plc)
    db_session.commit()

    resp = client.post(
        "/api/discovery/switch-tables/import",
        json={"device_id": switch_id, "table_type": "mac_table", "vendor": "cisco", "raw_text": CISCO_MAC_TABLE},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["entries_parsed"] == 3
    assert body["links_created_or_updated"] == 1
    assert body["suspected_uplinks"] == [{"interface": "Gi0/2", "mac_count": 2}]

    link = db_session.query(NetworkLink).one()
    assert {link.device_a_id, link.device_b_id} == {switch_id, plc.id}
    assert link.source == "mac_table"


def test_import_unrecognized_line_is_skipped_not_a_crash(client, db_session, org_id):
    """Regression test for switch_table_parsers._parse_scalance_mac_table's
    StopIteration bug: a line whose only MAC-looking substring is glued to
    a label (no whitespace around it, e.g. real Scalance CLI output using
    "Label:value" columns) used to crash parse_switch_table with an
    unhandled StopIteration, surfacing as an opaque 500 to the user instead
    of just skipping that one unrecognized line."""
    switch_resp = client.post("/api/inventory/devices", json={"custom_name": "switch-2", "ip": "10.9.9.6"})
    switch_id = switch_resp.json()["id"]

    resp = client.post(
        "/api/discovery/switch-tables/import",
        json={
            "device_id": switch_id,
            "table_type": "mac_table",
            "vendor": "siemens_scalance",
            "raw_text": "MAC-Address:00-1B-1B-11-22-33 VLAN:1 Port:P0.1",
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["entries_parsed"] == 0


def test_import_parser_failure_is_a_400_not_a_500(client, db_session, org_id, monkeypatch):
    """Defense-in-depth: whatever the per-vendor parser raises beyond the
    ValueError already handled for an unknown vendor/table_type, it must
    still surface as a normal 400 the user can act on, never an opaque
    500 -- see import_switch_table's broad `except Exception` guard."""
    switch_resp = client.post("/api/inventory/devices", json={"custom_name": "switch-3", "ip": "10.9.9.7"})
    switch_id = switch_resp.json()["id"]

    def _boom(vendor, table_type, raw_text):
        raise RuntimeError("unexpected parser bug")

    monkeypatch.setattr("app.api.routes_discovery.parse_switch_table", _boom)

    resp = client.post(
        "/api/discovery/switch-tables/import",
        json={"device_id": switch_id, "table_type": "mac_table", "vendor": "cisco", "raw_text": "whatever"},
    )
    assert resp.status_code == 400, resp.text


def test_import_rejects_device_from_another_organization(client, db_session, org_id):
    from app.models import Organization

    other_org = Organization(name="Other Org 2", slug="other-org-switch-2")
    db_session.add(other_org)
    db_session.flush()
    other_device = Device(organization_id=other_org.id, custom_name="not-yours")
    db_session.add(other_device)
    db_session.commit()

    resp = client.post(
        "/api/discovery/switch-tables/import",
        json={"device_id": other_device.id, "table_type": "mac_table", "vendor": "cisco", "raw_text": CISCO_MAC_TABLE},
    )
    assert resp.status_code == 404


def test_viewer_cannot_create_device_or_import(client, db_session, org_id, make_client):
    client.post("/api/users", json={"username": "viewer-switch", "password": "secret1", "role": "viewer"})
    viewer_client = make_client("viewer-switch", "secret1")
    resp = viewer_client.post("/api/inventory/devices", json={"custom_name": "nope"})
    assert resp.status_code == 403
