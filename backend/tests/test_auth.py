from app.config import DEFAULT_ADMIN_PASSWORD, DEFAULT_ADMIN_USERNAME


def test_login_with_default_admin_succeeds(anonymous_client):
    resp = anonymous_client.post(
        "/api/auth/login", json={"username": DEFAULT_ADMIN_USERNAME, "password": DEFAULT_ADMIN_PASSWORD}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["token"]
    assert body["user"]["username"] == "admin"
    assert body["user"]["role"] == "admin"


def test_login_with_wrong_password_fails(anonymous_client):
    resp = anonymous_client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert resp.status_code == 401


def test_login_with_unknown_user_fails(anonymous_client):
    resp = anonymous_client.post("/api/auth/login", json={"username": "nobody", "password": "x"})
    assert resp.status_code == 401


def test_me_requires_a_valid_token(anonymous_client):
    resp = anonymous_client.get("/api/auth/me")
    assert resp.status_code == 401

    anonymous_client.headers.update({"Authorization": "Bearer not-a-real-token"})
    resp = anonymous_client.get("/api/auth/me")
    assert resp.status_code == 401


def test_me_returns_current_user_with_valid_token(client):
    resp = client.get("/api/auth/me")
    assert resp.status_code == 200
    assert resp.json()["username"] == "admin"


def test_me_includes_organization_name_for_an_org_scoped_user(client):
    """The frontend nav tree needs this to label its root for an admin/
    viewer, who can't call GET /api/organizations (super_admin only)."""
    body = client.get("/api/auth/me").json()
    assert body["organization_id"] is not None
    assert body["organization_name"] == "Default Organization"


def test_me_has_no_organization_for_a_super_admin(db_session):
    from fastapi.testclient import TestClient

    from app.auth import ROLE_SUPER_ADMIN
    from app.auth.security import hash_password
    from app.main import app
    from app.models import User

    salt, password_hash = hash_password("rootpass1")
    db_session.add(
        User(
            organization_id=None,
            username="root",
            password_salt=salt,
            password_hash=password_hash,
            role=ROLE_SUPER_ADMIN,
        )
    )
    db_session.commit()

    super_client = TestClient(app)
    login = super_client.post("/api/auth/login", json={"username": "root", "password": "rootpass1"})
    assert login.json()["user"]["organization_id"] is None
    assert login.json()["user"]["organization_name"] is None

    super_client.headers.update({"Authorization": f"Bearer {login.json()['token']}"})
    me = super_client.get("/api/auth/me").json()
    assert me["organization_id"] is None
    assert me["organization_name"] is None


def test_logout_invalidates_the_token(client):
    resp = client.get("/api/auth/me")
    assert resp.status_code == 200

    logout = client.post("/api/auth/logout")
    assert logout.status_code == 204

    resp = client.get("/api/auth/me")
    assert resp.status_code == 401


def test_anonymous_requests_are_rejected_on_protected_routes(anonymous_client):
    assert anonymous_client.get("/api/inventory/devices").status_code == 401
    assert anonymous_client.get("/api/capture/sessions").status_code == 401
    assert anonymous_client.get("/api/vuln/findings").status_code == 401
    assert anonymous_client.post("/api/vuln/scan", json={"use_nvd": False}).status_code == 401


def test_health_endpoint_stays_public(anonymous_client):
    assert anonymous_client.get("/api/health").status_code == 200
