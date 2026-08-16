"""Tests for PATCH /api/organizations/me -- self-service organization
settings (Ajustes, under Administración), open to that org's own admin.
Distinct from PATCH /api/organizations/{id}, which is platform-level
management restricted to a super_admin acting on any organization by id
(see test_users.py)."""

from app.auth import ROLE_SUPER_ADMIN
from app.auth.security import hash_password


def test_default_organization_timezone_is_utc(client):
    me = client.get("/api/auth/me").json()
    assert me["organization_timezone"] == "UTC"


def test_admin_can_update_own_organization_timezone(client):
    resp = client.patch("/api/organizations/me", json={"timezone": "America/Bogota"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["timezone"] == "America/Bogota"

    me = client.get("/api/auth/me").json()
    assert me["organization_timezone"] == "America/Bogota"


def test_invalid_timezone_is_rejected(client):
    resp = client.patch("/api/organizations/me", json={"timezone": "Not/AZone"})
    assert resp.status_code == 400


def test_viewer_cannot_update_organization_timezone(client, make_client):
    client.post("/api/users", json={"username": "viewer1", "password": "secret1", "role": "viewer"})
    viewer = make_client("viewer1", "secret1")

    resp = viewer.patch("/api/organizations/me", json={"timezone": "America/Bogota"})
    assert resp.status_code == 403


def test_super_admin_has_no_organization_of_their_own_to_update(db_session):
    from fastapi.testclient import TestClient

    from app.main import app
    from app.models import User

    username, password = "super1", "secret123"
    salt, password_hash = hash_password(password)
    db_session.add(
        User(organization_id=None, username=username, password_salt=salt, password_hash=password_hash, role=ROLE_SUPER_ADMIN)
    )
    db_session.commit()

    super_client = TestClient(app)
    token = super_client.post("/api/auth/login", json={"username": username, "password": password}).json()["token"]
    super_client.headers.update({"Authorization": f"Bearer {token}"})

    resp = super_client.patch("/api/organizations/me", json={"timezone": "America/Bogota"})
    assert resp.status_code == 404
