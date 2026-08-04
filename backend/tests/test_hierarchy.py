"""Tests for Paso 2 of the Organization -> Site -> Zone -> Sensor rollout:
the API that lets a Super Admin create organizations and lets an admin (or
Super Admin) register sites/zones/sensors within one -- see docs (Parte C).
"""

from fastapi.testclient import TestClient

from app.auth import ROLE_SUPER_ADMIN
from app.auth.security import hash_password
from app.models import User


def _make_super_admin_client(db_session, username="root", password="rootpass1") -> TestClient:
    salt, password_hash = hash_password(password)
    db_session.add(
        User(
            organization_id=None,
            username=username,
            password_salt=salt,
            password_hash=password_hash,
            role=ROLE_SUPER_ADMIN,
        )
    )
    db_session.commit()

    from app.main import app

    super_client = TestClient(app)
    resp = super_client.post("/api/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    super_client.headers.update({"Authorization": f"Bearer {resp.json()['token']}"})
    return super_client


def _login(username: str, password: str) -> TestClient:
    from app.main import app

    anon = TestClient(app)
    resp = anon.post("/api/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    anon.headers.update({"Authorization": f"Bearer {resp.json()['token']}"})
    return anon


# ---------------------------------------------------------------------------
# Organizations -- Super Admin only
# ---------------------------------------------------------------------------


def test_only_super_admin_can_list_or_create_organizations(client, db_session):
    assert client.get("/api/organizations").status_code == 403
    assert (
        client.post(
            "/api/organizations",
            json={
                "name": "Cervecería SA",
                "slug": "cerveceria-sa",
                "admin_username": "cerveceria-admin",
                "admin_password": "secret123",
            },
        ).status_code
        == 403
    )


def test_super_admin_creates_organization_and_bootstraps_its_admin(db_session):
    super_admin = _make_super_admin_client(db_session)

    resp = super_admin.post(
        "/api/organizations",
        json={
            "name": "Cervecería SA",
            "slug": "cerveceria-sa",
            "admin_username": "cerveceria-admin",
            "admin_password": "secret123",
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["organization"]["slug"] == "cerveceria-sa"
    assert body["admin_user"]["username"] == "cerveceria-admin"
    assert body["admin_user"]["role"] == "admin"

    # the new organization's admin can log in immediately, and starts with
    # no sites/zones/sensors of its own (no auto-provisioned "Default")
    new_admin = _login("cerveceria-admin", "secret123")
    assert new_admin.get("/api/sites").json() == []

    listed = super_admin.get("/api/organizations").json()
    assert "cerveceria-sa" in {o["slug"] for o in listed}


def test_duplicate_organization_slug_is_rejected(db_session):
    super_admin = _make_super_admin_client(db_session)
    payload = {
        "name": "Cervecería SA",
        "slug": "cerveceria-sa",
        "admin_username": "cerveceria-admin",
        "admin_password": "secret123",
    }
    assert super_admin.post("/api/organizations", json=payload).status_code == 201
    payload2 = dict(payload, admin_username="cerveceria-admin2")
    assert super_admin.post("/api/organizations", json=payload2).status_code == 409


# ---------------------------------------------------------------------------
# Sites / Zones / Sensors -- admin (own org) or Super Admin (any org)
# ---------------------------------------------------------------------------


def test_admin_creates_and_lists_own_sites_zones_sensors(client):
    site = client.post("/api/sites", json={"name": "Planta Bogotá", "city": "Bogotá"}).json()
    assert site["name"] == "Planta Bogotá"

    zone = client.post("/api/zones", json={"site_id": site["id"], "name": "Línea 1"}).json()
    assert zone["site_id"] == site["id"]
    assert zone["security_level"] is None  # optional, no default forced

    sensor = client.post("/api/sensors", json={"zone_id": zone["id"], "name": "Sensor línea 1"}).json()
    assert sensor["zone_id"] == zone["id"]
    assert sensor["kind"] == "live"

    # The seeded organization already has a migration-backfilled "Default"
    # site/zone/sensor (see db.py's _ensure_default_site_zone_sensor_and_
    # backfill) -- listing includes it alongside what this test just made.
    assert site["id"] in {s["id"] for s in client.get("/api/sites").json()}
    assert {z["id"] for z in client.get(f"/api/zones?site_id={site['id']}").json()} == {zone["id"]}
    assert {s["id"] for s in client.get(f"/api/sensors?zone_id={zone['id']}").json()} == {sensor["id"]}


def test_zone_accepts_an_iec_62443_security_level_when_given(client):
    site = client.post("/api/sites", json={"name": "Planta Bogotá"}).json()
    zone = client.post(
        "/api/zones", json={"site_id": site["id"], "name": "Línea crítica", "security_level": "SL2"}
    ).json()
    assert zone["security_level"] == "SL2"


def test_viewer_can_read_but_not_create_hierarchy(client, make_client):
    site = client.post("/api/sites", json={"name": "Planta Bogotá"}).json()
    client.post("/api/users", json={"username": "viewer1", "password": "secret1", "role": "viewer"})
    viewer = make_client("viewer1", "secret1")

    assert viewer.get("/api/sites").status_code == 200
    assert viewer.post("/api/sites", json={"name": "Otra planta"}).status_code == 403
    assert viewer.post("/api/zones", json={"site_id": site["id"], "name": "Zona"}).status_code == 403


def test_admin_cannot_create_a_zone_under_another_organizations_site(db_session):
    super_admin = _make_super_admin_client(db_session)
    org_b = super_admin.post(
        "/api/organizations",
        json={
            "name": "Org B",
            "slug": "org-b",
            "admin_username": "org-b-admin",
            "admin_password": "secret123",
        },
    ).json()
    admin_b = _login("org-b-admin", "secret123")
    site_b = admin_b.post("/api/sites", json={"name": "Sede B"}).json()

    from app.auth.security import hash_password
    from app.models import Organization, User

    org_a = Organization(name="Org A", slug="org-a")
    db_session.add(org_a)
    db_session.flush()
    salt, password_hash = hash_password("secret123")
    db_session.add(
        User(
            organization_id=org_a.id,
            username="org-a-admin",
            password_salt=salt,
            password_hash=password_hash,
            role="admin",
        )
    )
    db_session.commit()
    admin_a = _login("org-a-admin", "secret123")

    resp = admin_a.post("/api/zones", json={"site_id": site_b["id"], "name": "Intrusión"})
    assert resp.status_code == 404
    assert admin_a.get(f"/api/zones?site_id={site_b['id']}").status_code == 404
    assert org_b["organization"]["id"] != org_a.id  # sanity: genuinely two different orgs


def test_super_admin_must_specify_organization_id_to_create_a_site(db_session):
    super_admin = _make_super_admin_client(db_session)
    resp = super_admin.post("/api/sites", json={"name": "Sede huérfana"})
    assert resp.status_code == 400


def test_super_admin_can_create_a_site_for_any_organization(client, db_session):
    super_admin = _make_super_admin_client(db_session)

    # The default seeded org has no site yet; create one as its own admin
    # first, purely to learn its organization_id from the response.
    site = client.post("/api/sites", json={"name": "Sede del cliente"}).json()
    org_id = site["organization_id"]

    created = super_admin.post("/api/sites", json={"name": "Segunda sede", "organization_id": org_id})
    assert created.status_code == 201
    assert created.json()["organization_id"] == org_id
