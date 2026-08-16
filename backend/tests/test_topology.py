"""Tests for the network topology graph (GET /api/topology) and its
human-managed links (POST/PATCH/DELETE /api/topology/links) -- see
app/api/routes_topology.py and app/models.py's NetworkLink docstring.
"""

from fastapi.testclient import TestClient

from app.auth import ROLE_SUPER_ADMIN
from app.auth.security import hash_password
from app.models import CaptureSession, Device, Flow, Organization, Sensor, Site, User, Zone


def _make_device(db_session, org_id, **overrides):
    defaults = dict(organization_id=org_id, ip=None, mac=None)
    defaults.update(overrides)
    device = Device(**defaults)
    db_session.add(device)
    db_session.commit()
    db_session.refresh(device)
    return device


def _make_device_in_zone(db_session, org_id, site_id, zone_name, **overrides):
    """Same as _make_device, but actually attributed to a real Zona (via a
    Sensor + CaptureSession) instead of capture_session_id=None -- needed
    to test zone_id/zone_name attribution and site_id's multi-Zona union,
    neither of which a capture_session_id=None device can exercise."""
    zone = Zone(site_id=site_id, name=zone_name)
    db_session.add(zone)
    db_session.flush()
    sensor = Sensor(zone_id=zone.id, name=f"Sensor {zone_name}")
    db_session.add(sensor)
    db_session.flush()
    capture_session = CaptureSession(
        organization_id=org_id, sensor_id=sensor.id, source_type="pcap", source="test.pcap", status="completed",
    )
    db_session.add(capture_session)
    db_session.flush()
    device = _make_device(db_session, org_id, capture_session_id=capture_session.id, **overrides)
    return device, zone


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


def test_topology_draws_no_edge_from_flow_alone(client, db_session, org_id):
    """Talking to each other is not proof of a direct cable -- see
    routes_topology.py's module docstring. Flow traffic between two devices
    with no NetworkLink must not produce any edge at all."""
    a = _make_device(db_session, org_id, ip="10.0.1.10")
    b = _make_device(db_session, org_id, ip="10.0.1.20")
    _make_flow(db_session, a, b, protocol="modbus")

    edges = client.get("/api/topology").json()["edges"]
    assert edges == []


def test_confirmed_link_unaffected_by_coexisting_flow(client, db_session, org_id):
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


def _default_site_id(db_session, org_id):
    site = db_session.query(Site).filter(Site.organization_id == org_id).order_by(Site.id.asc()).first()
    return site.id


def test_topology_node_carries_its_zone_attribution(client, db_session, org_id):
    site_id = _default_site_id(db_session, org_id)
    device, zone = _make_device_in_zone(db_session, org_id, site_id, "Linea 1", ip="10.0.1.10")

    resp = client.get("/api/topology")
    assert resp.status_code == 200
    node = next(n for n in resp.json()["nodes"] if n["id"] == device.id)
    assert node["zone_id"] == zone.id
    assert node["zone_name"] == "Linea 1"


def test_topology_node_has_no_zone_when_never_captured(client, db_session, org_id):
    device = _make_device(db_session, org_id, ip="10.0.1.20")
    resp = client.get("/api/topology")
    node = next(n for n in resp.json()["nodes"] if n["id"] == device.id)
    assert node["zone_id"] is None
    assert node["zone_name"] is None


def test_topology_site_id_unifies_every_zone_under_it(client, db_session, org_id):
    """The whole point of site_id: a Sitio's topology is the union of all
    of its Zonas' devices (and any manual link between them), computed by
    the same endpoint with no separate "unify" step -- see the design
    discussion this followed."""
    site_id = _default_site_id(db_session, org_id)
    device_a, zone_a = _make_device_in_zone(db_session, org_id, site_id, "Linea 1", ip="10.0.1.10")
    device_b, zone_b = _make_device_in_zone(db_session, org_id, site_id, "Linea 2", ip="10.0.1.20")
    link_resp = client.post(
        "/api/topology/links",
        json={"device_a_id": device_a.id, "device_b_id": device_b.id, "status": "confirmed"},
    )
    assert link_resp.status_code == 200, link_resp.text

    # Filtering by just Linea 1's own zone_id never sees Linea 2's device,
    # and the cross-zone link is dropped too (see get_topology's own
    # "don't show an edge to a node that isn't drawn" rule).
    zone_scoped = client.get(f"/api/topology?zone_id={zone_a.id}").json()
    assert [n["id"] for n in zone_scoped["nodes"]] == [device_a.id]
    assert zone_scoped["edges"] == []

    site_scoped = client.get(f"/api/topology?site_id={site_id}").json()
    node_ids = {n["id"] for n in site_scoped["nodes"]}
    assert device_a.id in node_ids and device_b.id in node_ids
    zone_ids_by_device = {n["id"]: n["zone_id"] for n in site_scoped["nodes"]}
    assert zone_ids_by_device[device_a.id] == zone_a.id
    assert zone_ids_by_device[device_b.id] == zone_b.id
    assert len(site_scoped["edges"]) == 1
    assert site_scoped["edges"][0]["kind"] == "confirmed"


def _make_sensor_and_devices(db_session, org_id, site_name, zone_name, ip_a, ip_b, vlan=None):
    """Two devices attributed to the *same* real Sensor (unlike
    _make_device_in_zone, which mints a fresh Zone/Sensor per call), each
    with a live ArpObservation on that Sensor -- the precondition
    apply_segment_classification/apply_flow_link_candidates need to ever
    consider a pair a same-segment link candidate."""
    from app.models import ArpObservation

    site = Site(organization_id=org_id, name=site_name)
    db_session.add(site)
    db_session.flush()
    zone = Zone(site_id=site.id, name=zone_name)
    db_session.add(zone)
    db_session.flush()
    sensor = Sensor(zone_id=zone.id, name=f"Sensor {zone_name}")
    db_session.add(sensor)
    db_session.flush()
    capture_session = CaptureSession(
        organization_id=org_id, sensor_id=sensor.id, source_type="pcap", source="test.pcap", status="completed",
    )
    db_session.add(capture_session)
    db_session.flush()
    device_a = _make_device(db_session, org_id, ip=ip_a, capture_session_id=capture_session.id, vlan=vlan)
    device_b = _make_device(db_session, org_id, ip=ip_b, capture_session_id=capture_session.id, vlan=vlan)
    db_session.add(ArpObservation(organization_id=org_id, sensor_id=sensor.id, ip=ip_a, mac="aa:bb:cc:00:01:01"))
    db_session.add(ArpObservation(organization_id=org_id, sensor_id=sensor.id, ip=ip_b, mac="aa:bb:cc:00:01:02"))
    db_session.commit()
    return device_a, device_b, sensor


def _seed_pending_candidate(db_session, org_id, ip_a="10.0.20.5", ip_b="10.0.20.6", vlan=None):
    from app.inventory.inventory_service import apply_flow_link_candidates, apply_segment_classification
    from app.models import FlowLinkCandidate

    device_a, device_b, sensor = _make_sensor_and_devices(
        db_session, org_id, "Planta Candidatos", "Linea 1", ip_a, ip_b, vlan=vlan
    )
    _make_flow(db_session, device_a, device_b)
    apply_segment_classification(db_session, org_id)
    db_session.commit()
    apply_flow_link_candidates(db_session, org_id)
    db_session.commit()

    a_id, b_id = sorted((device_a.id, device_b.id))
    candidate = (
        db_session.query(FlowLinkCandidate)
        .filter(FlowLinkCandidate.device_a_id == a_id, FlowLinkCandidate.device_b_id == b_id)
        .one()
    )
    return device_a, device_b, candidate


def test_list_link_candidates_shows_a_pending_candidate(client, db_session, org_id):
    device_a, device_b, candidate = _seed_pending_candidate(db_session, org_id)

    resp = client.get("/api/topology/link-candidates")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body) == 1
    assert body[0]["id"] == candidate.id
    assert body[0]["status"] == "pending"
    assert {body[0]["device_a_id"], body[0]["device_b_id"]} == {device_a.id, device_b.id}
    assert 0 < body[0]["confidence"] < 1.0


def test_list_link_candidates_filters_by_status(client, db_session, org_id):
    _, _, candidate = _seed_pending_candidate(db_session, org_id)

    assert len(client.get("/api/topology/link-candidates?status=pending").json()) == 1
    assert len(client.get("/api/topology/link-candidates?status=confirmed").json()) == 0

    client.post(f"/api/topology/link-candidates/{candidate.id}/dismiss")
    assert len(client.get("/api/topology/link-candidates?status=pending").json()) == 0
    assert len(client.get("/api/topology/link-candidates?status=dismissed").json()) == 1


def test_vlan_match_scores_higher_confidence_than_no_match(db_session, org_id):
    from app.models import FlowLinkCandidate

    _, _, unmatched = _seed_pending_candidate(db_session, org_id, ip_a="10.0.21.5", ip_b="10.0.21.6")
    _, _, matched = _seed_pending_candidate(db_session, org_id, ip_a="10.0.22.5", ip_b="10.0.22.6", vlan=42)

    unmatched_candidate = db_session.get(FlowLinkCandidate, unmatched.id)
    matched_candidate = db_session.get(FlowLinkCandidate, matched.id)
    assert matched_candidate.confidence > unmatched_candidate.confidence


def test_promote_link_candidate_creates_a_network_link(client, db_session, org_id):
    from app.models import NetworkLink

    device_a, device_b, candidate = _seed_pending_candidate(db_session, org_id)

    resp = client.post(f"/api/topology/link-candidates/{candidate.id}/promote")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["source"] == "flow_candidate"
    assert body["status"] == "confirmed"
    assert {body["device_a_id"], body["device_b_id"]} == {device_a.id, device_b.id}

    assert db_session.query(NetworkLink).count() == 1
    db_session.refresh(candidate)
    assert candidate.status == "confirmed"

    # the promoted pair now has a real link, so a later pass must not spin
    # up a fresh pending candidate for the exact same devices.
    from app.inventory.inventory_service import apply_flow_link_candidates
    from app.models import FlowLinkCandidate

    apply_flow_link_candidates(db_session, org_id)
    db_session.commit()
    assert db_session.query(FlowLinkCandidate).count() == 1


def test_promote_already_resolved_candidate_409s(client, db_session, org_id):
    _, _, candidate = _seed_pending_candidate(db_session, org_id)
    client.post(f"/api/topology/link-candidates/{candidate.id}/promote")

    resp = client.post(f"/api/topology/link-candidates/{candidate.id}/promote")
    assert resp.status_code == 409


def test_dismiss_link_candidate_is_not_resurrected_by_a_later_pass(client, db_session, org_id):
    _, _, candidate = _seed_pending_candidate(db_session, org_id)

    resp = client.post(f"/api/topology/link-candidates/{candidate.id}/dismiss")
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "dismissed"

    from app.inventory.inventory_service import apply_flow_link_candidates

    apply_flow_link_candidates(db_session, org_id)
    db_session.commit()
    db_session.refresh(candidate)
    assert candidate.status == "dismissed"


def test_dismiss_already_resolved_candidate_409s(client, db_session, org_id):
    _, _, candidate = _seed_pending_candidate(db_session, org_id)
    client.post(f"/api/topology/link-candidates/{candidate.id}/dismiss")

    resp = client.post(f"/api/topology/link-candidates/{candidate.id}/dismiss")
    assert resp.status_code == 409


def test_link_candidate_not_found_404s(client):
    resp = client.post("/api/topology/link-candidates/999999/promote")
    assert resp.status_code == 404
    resp = client.post("/api/topology/link-candidates/999999/dismiss")
    assert resp.status_code == 404


def test_promote_and_dismiss_link_candidate_require_admin(client, make_client, db_session, org_id):
    _, _, candidate = _seed_pending_candidate(db_session, org_id)
    client.post("/api/users", json={"username": "viewer-candidates", "password": "secret1", "role": "viewer"})
    viewer = make_client("viewer-candidates", "secret1")

    assert viewer.post(f"/api/topology/link-candidates/{candidate.id}/promote").status_code == 403
    assert viewer.post(f"/api/topology/link-candidates/{candidate.id}/dismiss").status_code == 403
