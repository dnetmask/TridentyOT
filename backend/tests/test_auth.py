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
