"""Tests for the two additions backing the draw.io-inspired Topología
features (hover-to-drag link creation, orthogonal/curved edge routing,
background boxes and free-text notes) -- see app/models.py's
Device.topology_x/topology_y and TopologyAnnotation docstrings, and
app/api/routes_topology.py's update_topology_positions/create_topology_
annotation/update_topology_annotation/delete_topology_annotation.
"""

from app.models import Device, Organization, Site, TopologyAnnotation, Zone


def _make_device(db_session, org_id, **overrides):
    defaults = dict(organization_id=org_id, ip=None, mac=None)
    defaults.update(overrides)
    device = Device(**defaults)
    db_session.add(device)
    db_session.commit()
    db_session.refresh(device)
    return device


def test_positions_are_null_until_saved_then_persist(client, db_session, org_id):
    device = _make_device(db_session, org_id, custom_name="switch-1")

    body = client.get("/api/topology").json()
    node = next(n for n in body["nodes"] if n["id"] == device.id)
    assert node["x"] is None and node["y"] is None

    resp = client.patch(
        "/api/topology/positions",
        json={"positions": [{"device_id": device.id, "x": 12.5, "y": -30.0}]},
    )
    assert resp.status_code == 204, resp.text

    body = client.get("/api/topology").json()
    node = next(n for n in body["nodes"] if n["id"] == device.id)
    assert node["x"] == 12.5 and node["y"] == -30.0


def test_positions_update_skips_devices_outside_caller_org(client, db_session, org_id):
    other_org = Organization(name="Other Org", slug="other-org-positions")
    db_session.add(other_org)
    db_session.commit()
    other_device = _make_device(db_session, other_org.id, custom_name="not-mine")

    resp = client.patch(
        "/api/topology/positions",
        json={"positions": [{"device_id": other_device.id, "x": 1, "y": 1}]},
    )
    assert resp.status_code == 204, resp.text  # best-effort: silently skips, never 404s the batch

    db_session.refresh(other_device)
    assert other_device.topology_x is None and other_device.topology_y is None


def test_viewer_cannot_update_positions(client, db_session, org_id, make_client):
    device = _make_device(db_session, org_id, custom_name="switch-2")
    client.post("/api/users", json={"username": "viewer-pos", "password": "secret1", "role": "viewer"})
    viewer = make_client("viewer-pos", "secret1")

    resp = viewer.patch(
        "/api/topology/positions",
        json={"positions": [{"device_id": device.id, "x": 1, "y": 1}]},
    )
    assert resp.status_code == 403


def test_create_list_update_delete_annotation(client, db_session, org_id):
    create_resp = client.post(
        "/api/topology/annotations",
        json={"kind": "box", "label": "Zona DMZ", "x": 10, "y": 20, "width": 300, "height": 180},
    )
    assert create_resp.status_code == 200, create_resp.text
    created = create_resp.json()
    assert created["kind"] == "box"
    assert created["z_order"] == 0
    annotation_id = created["id"]

    listed = client.get("/api/topology").json()["annotations"]
    assert len(listed) == 1
    assert listed[0]["label"] == "Zona DMZ"

    update_resp = client.patch(
        f"/api/topology/annotations/{annotation_id}",
        json={"label": "Zona DMZ renombrada", "x": 15, "y": 25, "width": 320, "height": 200, "z_order": -1},
    )
    assert update_resp.status_code == 200, update_resp.text
    updated = update_resp.json()
    assert updated["label"] == "Zona DMZ renombrada"
    assert updated["z_order"] == -1

    delete_resp = client.delete(f"/api/topology/annotations/{annotation_id}")
    assert delete_resp.status_code == 204
    assert client.get("/api/topology").json()["annotations"] == []


def test_annotation_scoped_by_zone_only_shows_in_that_zone(client, db_session, org_id):
    site = Site(organization_id=org_id, name="Site A")
    db_session.add(site)
    db_session.flush()
    zone_a = Zone(site_id=site.id, name="Zona A")
    zone_b = Zone(site_id=site.id, name="Zona B")
    db_session.add_all([zone_a, zone_b])
    db_session.commit()

    resp = client.post(
        "/api/topology/annotations",
        json={"kind": "text", "label": "nota de Zona A", "x": 0, "y": 0, "zone_id": zone_a.id},
    )
    assert resp.status_code == 200, resp.text

    assert len(client.get(f"/api/topology?zone_id={zone_a.id}").json()["annotations"]) == 1
    assert client.get(f"/api/topology?zone_id={zone_b.id}").json()["annotations"] == []


def test_create_annotation_rejects_zone_from_another_organization(client, db_session, org_id):
    other_org = Organization(name="Other Org 2", slug="other-org-annotations")
    db_session.add(other_org)
    db_session.flush()
    other_site = Site(organization_id=other_org.id, name="Other Site")
    db_session.add(other_site)
    db_session.flush()
    other_zone = Zone(site_id=other_site.id, name="Other Zone")
    db_session.add(other_zone)
    db_session.commit()

    resp = client.post(
        "/api/topology/annotations",
        json={"kind": "box", "label": "nope", "x": 0, "y": 0, "zone_id": other_zone.id},
    )
    assert resp.status_code == 404


def test_viewer_cannot_create_or_delete_annotation(client, db_session, org_id, make_client):
    client.post("/api/users", json={"username": "viewer-ann", "password": "secret1", "role": "viewer"})
    viewer = make_client("viewer-ann", "secret1")

    resp = viewer.post(
        "/api/topology/annotations",
        json={"kind": "box", "label": "nope", "x": 0, "y": 0},
    )
    assert resp.status_code == 403

    created = client.post(
        "/api/topology/annotations",
        json={"kind": "box", "label": "real one", "x": 0, "y": 0},
    ).json()
    assert viewer.delete(f"/api/topology/annotations/{created['id']}").status_code == 403


def test_annotation_from_another_organization_is_not_found(client, db_session, org_id):
    other_org = Organization(name="Other Org 3", slug="other-org-annotations-2")
    db_session.add(other_org)
    db_session.commit()
    other_annotation = TopologyAnnotation(organization_id=other_org.id, kind="box", label="not yours", x=0, y=0)
    db_session.add(other_annotation)
    db_session.commit()

    resp = client.patch(
        f"/api/topology/annotations/{other_annotation.id}",
        json={"label": "hijacked", "x": 0, "y": 0, "width": 10, "height": 10, "z_order": 0},
    )
    assert resp.status_code == 404
    assert client.delete(f"/api/topology/annotations/{other_annotation.id}").status_code == 404
