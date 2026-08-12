"""Tests for the network topology graph (GET /api/topology) and its
human-managed links (POST/PATCH/DELETE /api/topology/links) -- see
app/api/routes_topology.py and app/models.py's NetworkLink docstring.
"""

from fastapi.testclient import TestClient

from app.auth import ROLE_SUPER_ADMIN
from app.auth.security import hash_password
from app.models import Device, Flow, Organization, Site, User, Zone


def _make_device(db_session, org_id, **overrides):
    defaults = dict(organization_id=org_id, ip=None, mac=None)
    defaults.update(overrides)
    device = Device(**defaults)
    db_session.add(device)
    db_session.commit()
    db_session.refresh(device)
    return device


def _make_flow(db_session, device_a, device_b, protocol="modbus", port=502):
    a, b = sorted((device_a, device_b), key=lambda d: d.id)
    flow = Flow(
        device_a_id=a.id, device_b_id=b.id, server_device_id=b.id,
        transport="tcp", port=port, protocol=protocol, category="OT", packet_count=5,
    )
    db_session.add(flow)
    db_session.commit()
    return flow


def _make_super_admin_client(db_session, username="root", password="rootpass1") -> TestClient:
    salt, password_hash = hash_password(password)
    db_session.add(
        User(
            organization_id=None, username=username, password_salt=salt,
            password_hash=password_hash, role=ROLE_SUPER_ADMIN,
        )
    )
    db_session.commit()

    from app.main import app

    super_client = TestClient(app)
    resp = super_client.post("/api/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    super_client.headers.update({"Authorization": f"Bearer {resp.json()['token']}"})
    return super_client


def test_topology_maps_device_type_to_icon(client, db_session, org_id):
    plc = _make_device(db_session, org_id, ip="10.0.1.10", device_type="plc", device_type_confidence=1.0)
    hmi = _make_device(db_session, org_id, ip="10.0.1.11", device_type="hmi", device_type_confidence=1.0)
    server = _make_device(db_session, org_id, ip="10.0.1.12", device_type="server", device_type_confidence=1.0)
    pc = _make_device(db_session, org_id, ip="10.0.1.13", device_type="workstation", device_type_confidence=1.0)
    router = _make_device(
        db_session, org_id, ip="10.0.1.1", device_type="network_device", device_type_secondary="router_nat",
        device_type_confidence=1.0,
    )
    switch = _make_device(
        db_session, org_id, ip="10.0.1.2", device_type="network_device", device_type_confidence=1.0,
    )
    unknown = _make_device(db_session, org_id, ip="10.0.1.99")

    resp = client.get("/api/topology")
    assert resp.status_code == 200, resp.text
    icons = {n["id"]: n["icon"] for n in resp.json()["nodes"]}
    assert icons[plc.id] == "plc"
    assert icons[hmi.id] == "hmi"
    assert icons[server.id] == "server"
    assert icons[pc.id] == "pc"
    assert icons[router.id] == "router"
    assert icons[switch.id] == "switch"
    assert icons[unknown.id] == "other"


def test_topology_suggests_edge_from_flow(client, db_session, org_id):
    a = _make_device(db_session, org_id, ip="10.0.1.10")
    b = _make_device(db_session, org_id, ip="10.0.1.20")
    _make_flow(db_session, a, b, protocol="modbus")

    edges = client.get("/api/topology").json()["edges"]
    assert len(edges) == 1
    edge = edges[0]
    assert edge["kind"] == "suggested"
    assert edge["link_id"] is None
    assert {edge["source"], edge["target"]} == {a.id, b.id}
    assert edge["label"] == "modbus"


def test_confirmed_link_outranks_flow_suggestion(client, db_session, org_id):
    a = _make_device(db_session, org_id, ip="10.0.1.10")
    b = _make_device(db_session, org_id, ip="10.0.1.20")
    _make_flow(db_session, a, b)

    resp = client.post(
        "/api/topology/links",
        json={"device_a_id": a.id, "device_b_id": b.id, "source_port": "Gi0/3", "status": "confirmed"},
    )
    assert resp.status_code == 200, resp.text

    edges = client.get("/api/topology").json()["edges"]
    assert len(edges) == 1, edges
    assert edges[0]["kind"] == "confirmed"
    assert edges[0]["link_id"] is not None
    assert edges[0]["source_port"] == "Gi0/3"


def test_create_network_link_normalizes_device_order_and_ports(client, db_session, org_id):
    a = _make_device(db_session, org_id, ip="10.0.1.10")
    b = _make_device(db_session, org_id, ip="10.0.1.20")
    higher, lower = max(a, b, key=lambda d: d.id), min(a, b, key=lambda d: d.id)

    resp = client.post(
        "/api/topology/links",
        json={
            "device_a_id": higher.id, "device_b_id": lower.id,
            "source_port": "eth0", "target_port": "Gi0/3", "status": "uncertain",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["device_a_id"] == lower.id
    assert body["device_b_id"] == higher.id
    assert body["source_port"] == "Gi0/3"  # swapped along with the devices
    assert body["target_port"] == "eth0"
    assert body["status"] == "uncertain"


def test_create_network_link_upserts_same_pair(client, db_session, org_id):
    a = _make_device(db_session, org_id, ip="10.0.1.10")
    b = _make_device(db_session, org_id, ip="10.0.1.20")

    first = client.post(
        "/api/topology/links", json={"device_a_id": a.id, "device_b_id": b.id, "status": "uncertain"}
    ).json()
    second = client.post(
        "/api/topology/links",
        json={"device_a_id": a.id, "device_b_id": b.id, "status": "confirmed", "notes": "confirmado en sitio"},
    ).json()

    assert first["id"] == second["id"]
    assert second["status"] == "confirmed"
    assert second["notes"] == "confirmado en sitio"
    from app.models import NetworkLink

    assert db_session.query(NetworkLink).count() == 1


def test_create_network_link_rejects_self_link(client, db_session, org_id):
    a = _make_device(db_session, org_id, ip="10.0.1.10")
    resp = client.post("/api/topology/links", json={"device_a_id": a.id, "device_b_id": a.id})
    assert resp.status_code == 400


def test_create_network_link_requires_admin(client, make_client, db_session, org_id):
    a = _make_device(db_session, org_id, ip="10.0.1.10")
    b = _make_device(db_session, org_id, ip="10.0.1.20")
    client.post("/api/users", json={"username": "viewer-topo", "password": "secret1", "role": "viewer"})
    viewer = make_client("viewer-topo", "secret1")

    resp = viewer.post("/api/topology/links", json={"device_a_id": a.id, "device_b_id": b.id})
    assert resp.status_code == 403


def test_viewer_can_read_topology(client, make_client, db_session, org_id):
    _make_device(db_session, org_id, ip="10.0.1.10")
    client.post("/api/users", json={"username": "viewer-topo-2", "password": "secret1", "role": "viewer"})
    viewer = make_client("viewer-topo-2", "secret1")

    resp = viewer.get("/api/topology")
    assert resp.status_code == 200
    assert len(resp.json()["nodes"]) == 1


def test_update_network_link(client, db_session, org_id):
    a = _make_device(db_session, org_id, ip="10.0.1.10")
    b = _make_device(db_session, org_id, ip="10.0.1.20")
    link = client.post("/api/topology/links", json={"device_a_id": a.id, "device_b_id": b.id}).json()

    resp = client.patch(
        f"/api/topology/links/{link['id']}",
        json={"source_port": "Gi0/1", "target_port": "eth0", "status": "uncertain", "notes": "revisar"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["source_port"] == "Gi0/1"
    assert body["status"] == "uncertain"
    assert body["notes"] == "revisar"


def test_delete_network_link(client, db_session, org_id):
    a = _make_device(db_session, org_id, ip="10.0.1.10")
    b = _make_device(db_session, org_id, ip="10.0.1.20")
    link = client.post("/api/topology/links", json={"device_a_id": a.id, "device_b_id": b.id}).json()

    resp = client.delete(f"/api/topology/links/{link['id']}")
    assert resp.status_code == 204

    from app.models import NetworkLink

    assert db_session.query(NetworkLink).count() == 0


def test_link_not_found_404s(client):
    resp = client.patch("/api/topology/links/999999", json={"status": "confirmed"})
    assert resp.status_code == 404
    resp = client.delete("/api/topology/links/999999")
    assert resp.status_code == 404


def test_super_admin_rejects_cross_organization_link(client, db_session, org_id):
    other_org = Organization(name="Org Topo B", slug="org-topo-b")
    db_session.add(other_org)
    db_session.flush()
    site = Site(organization_id=other_org.id, name="Site B")
    db_session.add(site)
    db_session.flush()
    db_session.add(Zone(site_id=site.id, name="Zone B"))
    db_session.commit()

    device_a = _make_device(db_session, org_id, ip="10.0.1.10")
    device_b = _make_device(db_session, other_org.id, ip="10.0.2.10")

    super_admin = _make_super_admin_client(db_session)
    resp = super_admin.post("/api/topology/links", json={"device_a_id": device_a.id, "device_b_id": device_b.id})
    assert resp.status_code == 400


def test_topology_scopes_devices_by_organization(client, db_session, org_id):
    other_org = Organization(name="Org Topo C", slug="org-topo-c")
    db_session.add(other_org)
    db_session.commit()

    _make_device(db_session, org_id, ip="10.0.1.10")
    _make_device(db_session, other_org.id, ip="10.0.2.10")

    resp = client.get("/api/topology")
    assert resp.status_code == 200
    assert len(resp.json()["nodes"]) == 1
