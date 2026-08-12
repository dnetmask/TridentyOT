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


def test_super_admin_can_rename_an_organization(db_session):
    super_admin = _make_super_admin_client(db_session)
    org = super_admin.post(
        "/api/organizations",
        json={
            "name": "Cervecería SA",
            "slug": "cerveceria-sa",
            "admin_username": "cerveceria-admin",
            "admin_password": "secret123",
        },
    ).json()["organization"]

    resp = super_admin.patch(f"/api/organizations/{org['id']}", json={"name": "Cervecería Nacional SA"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["name"] == "Cervecería Nacional SA"
    # The default seeded org (see conftest._reset_db) is also listed alongside it.
    assert "Cervecería Nacional SA" in {o["name"] for o in super_admin.get("/api/organizations").json()}


def test_only_super_admin_can_rename_an_organization(client, db_session):
    super_admin = _make_super_admin_client(db_session)
    org = super_admin.post(
        "/api/organizations",
        json={
            "name": "Cervecería SA",
            "slug": "cerveceria-sa",
            "admin_username": "cerveceria-admin",
            "admin_password": "secret123",
        },
    ).json()["organization"]

    assert client.patch(f"/api/organizations/{org['id']}", json={"name": "Otro nombre"}).status_code == 403


def test_renaming_an_unknown_organization_404s(db_session):
    super_admin = _make_super_admin_client(db_session)
    assert super_admin.patch("/api/organizations/999999", json={"name": "X"}).status_code == 404


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

    # The seeded organization already has a migration-backfilled "Sensor
    # interno" site/zone/sensor (see db.py's _ensure_default_site_zone_
    # sensor_and_backfill) -- listing includes it alongside what this test
    # just made. Also, create_zone itself auto-provisions its own "Sensor
    # interno" (see routes_hierarchy.create_zone), so this zone has that
    # one plus the "Sensor línea 1" this test created on top of it.
    assert site["id"] in {s["id"] for s in client.get("/api/sites").json()}
    assert {z["id"] for z in client.get(f"/api/zones?site_id={site['id']}").json()} == {zone["id"]}
    zone_sensors = client.get(f"/api/sensors?zone_id={zone['id']}").json()
    assert sensor["id"] in {s["id"] for s in zone_sensors}
    assert any(s["name"] == "Sensor interno" for s in zone_sensors)


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


def test_admin_can_rename_own_site_and_zone(client):
    site = client.post("/api/sites", json={"name": "Planta Bogotá"}).json()
    zone = client.post("/api/zones", json={"site_id": site["id"], "name": "Línea 1"}).json()

    renamed_site = client.patch(f"/api/sites/{site['id']}", json={"name": "Planta Medellín"})
    assert renamed_site.status_code == 200
    assert renamed_site.json()["name"] == "Planta Medellín"

    renamed_zone = client.patch(f"/api/zones/{zone['id']}", json={"name": "Línea crítica"})
    assert renamed_zone.status_code == 200
    assert renamed_zone.json()["name"] == "Línea crítica"


def test_viewer_cannot_rename_site_or_zone(client, make_client):
    site = client.post("/api/sites", json={"name": "Planta Bogotá"}).json()
    zone = client.post("/api/zones", json={"site_id": site["id"], "name": "Línea 1"}).json()
    client.post("/api/users", json={"username": "viewer1", "password": "secret1", "role": "viewer"})
    viewer = make_client("viewer1", "secret1")

    assert viewer.patch(f"/api/sites/{site['id']}", json={"name": "x"}).status_code == 403
    assert viewer.patch(f"/api/zones/{zone['id']}", json={"name": "x"}).status_code == 403


def test_admin_cannot_rename_another_organizations_site_or_zone(db_session):
    super_admin = _make_super_admin_client(db_session)
    org_b = super_admin.post(
        "/api/organizations",
        json={"name": "Org B", "slug": "org-b", "admin_username": "org-b-admin", "admin_password": "secret123"},
    ).json()
    admin_b = _login("org-b-admin", "secret123")
    site_b = admin_b.post("/api/sites", json={"name": "Sede B"}).json()
    zone_b = admin_b.post("/api/zones", json={"site_id": site_b["id"], "name": "Zona B"}).json()

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

    assert admin_a.patch(f"/api/sites/{site_b['id']}", json={"name": "Intrusión"}).status_code == 404
    assert admin_a.patch(f"/api/zones/{zone_b['id']}", json={"name": "Intrusión"}).status_code == 404
    assert org_b["organization"]["id"] != org_a.id  # sanity: genuinely two different orgs


def test_super_admin_can_rename_any_organizations_site_or_zone(db_session):
    super_admin = _make_super_admin_client(db_session)
    org_b = super_admin.post(
        "/api/organizations",
        json={"name": "Org B", "slug": "org-b", "admin_username": "org-b-admin", "admin_password": "secret123"},
    ).json()
    admin_b = _login("org-b-admin", "secret123")
    site_b = admin_b.post("/api/sites", json={"name": "Sede B"}).json()
    zone_b = admin_b.post("/api/zones", json={"site_id": site_b["id"], "name": "Zona B"}).json()

    assert super_admin.patch(f"/api/sites/{site_b['id']}", json={"name": "Sede B renombrada"}).status_code == 200
    assert super_admin.patch(f"/api/zones/{zone_b['id']}", json={"name": "Zona B renombrada"}).status_code == 200
    assert org_b["organization"]["id"] is not None  # sanity


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


# ---------------------------------------------------------------------------
# Sensors -- default provisioning and editing (name/description/interface)
# ---------------------------------------------------------------------------


def test_creating_a_zone_auto_provisions_a_sensor_interno(client):
    """So Captura/Descubrimiento activo always have at least one Sensor to
    select right away -- see routes_hierarchy.create_zone."""
    site = client.post("/api/sites", json={"name": "Planta Bogotá"}).json()
    zone = client.post("/api/zones", json={"site_id": site["id"], "name": "Línea 1"}).json()

    sensors = client.get(f"/api/sensors?zone_id={zone['id']}").json()
    assert len(sensors) == 1
    assert sensors[0]["name"] == "Sensor interno"
    assert sensors[0]["kind"] == "live"
    assert sensors[0]["interface"] is None


def test_admin_can_edit_a_sensors_name_description_and_interface(client):
    site = client.post("/api/sites", json={"name": "Planta Bogotá"}).json()
    zone = client.post("/api/zones", json={"site_id": site["id"], "name": "Línea 1"}).json()
    sensor = client.get(f"/api/sensors?zone_id={zone['id']}").json()[0]

    resp = client.patch(
        f"/api/sensors/{sensor['id']}",
        json={"name": "Sensor renombrado", "description": "eth0 del gabinete 3", "interface": "eth0"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["name"] == "Sensor renombrado"
    assert body["description"] == "eth0 del gabinete 3"
    assert body["interface"] == "eth0"

    # Clearing it back out (e.g. the physical NIC changed) is a normal PATCH too.
    resp = client.patch(f"/api/sensors/{sensor['id']}", json={"name": "Sensor renombrado", "interface": None})
    assert resp.json()["interface"] is None


def test_viewer_cannot_edit_a_sensor(client, make_client):
    site = client.post("/api/sites", json={"name": "Planta Bogotá"}).json()
    zone = client.post("/api/zones", json={"site_id": site["id"], "name": "Línea 1"}).json()
    sensor = client.get(f"/api/sensors?zone_id={zone['id']}").json()[0]
    client.post("/api/users", json={"username": "viewer-sensor", "password": "secret1", "role": "viewer"})
    viewer = make_client("viewer-sensor", "secret1")

    resp = viewer.patch(f"/api/sensors/{sensor['id']}", json={"name": "Intrusión", "interface": "eth0"})
    assert resp.status_code == 403


def test_admin_cannot_edit_another_organizations_sensor(db_session):
    super_admin = _make_super_admin_client(db_session)
    org_b = super_admin.post(
        "/api/organizations",
        json={"name": "Org B", "slug": "org-b", "admin_username": "org-b-admin", "admin_password": "secret123"},
    ).json()
    admin_b = _login("org-b-admin", "secret123")
    site_b = admin_b.post("/api/sites", json={"name": "Sede B"}).json()
    zone_b = admin_b.post("/api/zones", json={"site_id": site_b["id"], "name": "Zona B"}).json()
    sensor_b = admin_b.get(f"/api/sensors?zone_id={zone_b['id']}").json()[0]

    from app.auth.security import hash_password
    from app.models import Organization, User

    org_a = Organization(name="Org A", slug="org-a")
    db_session.add(org_a)
    db_session.flush()
    salt, password_hash = hash_password("secret123")
    db_session.add(
        User(organization_id=org_a.id, username="org-a-admin", password_salt=salt, password_hash=password_hash, role="admin")
    )
    db_session.commit()
    admin_a = _login("org-a-admin", "secret123")

    assert admin_a.patch(f"/api/sensors/{sensor_b['id']}", json={"name": "Intrusión"}).status_code == 404
    assert org_b["organization"]["id"] != org_a.id  # sanity: genuinely two different orgs


def test_editing_an_unknown_sensor_404s(client):
    assert client.patch("/api/sensors/999999", json={"name": "X"}).status_code == 404
