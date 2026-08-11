def test_admin_can_create_list_and_delete_a_viewer(client):
    resp = client.post("/api/users", json={"username": "ana", "password": "secret1", "role": "viewer"})
    assert resp.status_code == 201
    user = resp.json()
    assert user["username"] == "ana"
    assert user["role"] == "viewer"

    listed = client.get("/api/users").json()
    assert {u["username"] for u in listed} == {"admin", "ana"}

    resp = client.delete(f"/api/users/{user['id']}")
    assert resp.status_code == 204
    assert {u["username"] for u in client.get("/api/users").json()} == {"admin"}


def test_creating_duplicate_username_fails(client):
    client.post("/api/users", json={"username": "ana", "password": "secret1", "role": "viewer"})
    resp = client.post("/api/users", json={"username": "ana", "password": "other12", "role": "admin"})
    assert resp.status_code == 409


def test_viewer_cannot_manage_users_or_mutate_data(client, make_client):
    client.post("/api/users", json={"username": "viewer1", "password": "secret1", "role": "viewer"})
    viewer = make_client("viewer1", "secret1")

    assert viewer.get("/api/inventory/devices").status_code == 200  # reads are fine

    assert viewer.get("/api/users").status_code == 403
    assert viewer.post("/api/users", json={"username": "x", "password": "secret1", "role": "viewer"}).status_code == 403
    assert viewer.post("/api/vuln/scan", json={"use_nvd": False}).status_code == 403
    assert (
        viewer.post("/api/capture/live/start", json={"interface": "eth0"}).status_code == 403
    )


def test_cannot_delete_own_user(client):
    me = client.get("/api/auth/me").json()
    resp = client.delete(f"/api/users/{me['id']}")
    assert resp.status_code == 400


def test_cannot_remove_the_last_admin(client):
    me = client.get("/api/auth/me").json()

    # demoting the only admin to viewer would leave zero admins
    resp = client.patch(f"/api/users/{me['id']}", json={"role": "viewer"})
    assert resp.status_code == 400

    resp = client.delete(f"/api/users/{me['id']}")
    assert resp.status_code == 400  # also blocked by the "can't delete yourself" rule, but for the right reason too


def test_can_remove_an_admin_when_another_admin_remains(client):
    second = client.post("/api/users", json={"username": "admin2", "password": "secret1", "role": "admin"}).json()
    me = client.get("/api/auth/me").json()

    resp = client.patch(f"/api/users/{me['id']}", json={"role": "viewer"})
    assert resp.status_code == 200
    assert resp.json()["role"] == "viewer"

    # now current session belongs to a viewer account; further mutations should be forbidden
    assert client.get("/api/users").status_code == 403
    assert second["role"] == "admin"


def test_update_user_password_takes_effect(client, anonymous_client):
    created = client.post("/api/users", json={"username": "bob", "password": "oldpass1", "role": "viewer"}).json()
    client.patch(f"/api/users/{created['id']}", json={"password": "newpass1"})

    old_login = anonymous_client.post("/api/auth/login", json={"username": "bob", "password": "oldpass1"})
    assert old_login.status_code == 401

    new_login = anonymous_client.post("/api/auth/login", json={"username": "bob", "password": "newpass1"})
    assert new_login.status_code == 200


def _make_super_admin_client(db_session, username="root", password="rootpass1"):
    from fastapi.testclient import TestClient

    from app.auth import ROLE_SUPER_ADMIN
    from app.auth.security import hash_password
    from app.main import app
    from app.models import User

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

    super_client = TestClient(app)
    resp = super_client.post("/api/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    super_client.headers.update({"Authorization": f"Bearer {resp.json()['token']}"})
    return super_client


def test_super_admin_sees_every_organizations_users_by_default(client, db_session):
    super_admin = _make_super_admin_client(db_session)
    org_b = super_admin.post(
        "/api/organizations",
        json={"name": "Org B", "slug": "org-b", "admin_username": "org-b-admin", "admin_password": "secret123"},
    ).json()

    listed = super_admin.get("/api/users").json()
    assert {"admin", "org-b-admin"} <= {u["username"] for u in listed}
    assert org_b["admin_user"]["organization_id"] in {u["organization_id"] for u in listed}


def test_super_admin_can_filter_users_by_organization(client, db_session):
    super_admin = _make_super_admin_client(db_session)
    org_b = super_admin.post(
        "/api/organizations",
        json={"name": "Org B", "slug": "org-b", "admin_username": "org-b-admin", "admin_password": "secret123"},
    ).json()
    default_org_id = client.get("/api/auth/me").json()["organization_id"]
    org_b_id = org_b["organization"]["id"]

    filtered_b = super_admin.get(f"/api/users?organization_id={org_b_id}").json()
    assert {u["username"] for u in filtered_b} == {"org-b-admin"}

    filtered_default = super_admin.get(f"/api/users?organization_id={default_org_id}").json()
    assert {u["username"] for u in filtered_default} == {"admin"}


def test_admin_cannot_use_organization_id_to_see_another_orgs_users(client, db_session):
    super_admin = _make_super_admin_client(db_session)
    org_b = super_admin.post(
        "/api/organizations",
        json={"name": "Org B", "slug": "org-b", "admin_username": "org-b-admin", "admin_password": "secret123"},
    ).json()

    # An admin's own organization_id query param is ignored, not honored --
    # they always see only their own organization's users.
    listed = client.get(f"/api/users?organization_id={org_b['organization']['id']}").json()
    assert {u["username"] for u in listed} == {"admin"}


def test_super_admin_must_specify_organization_id_to_create_a_user(db_session):
    super_admin = _make_super_admin_client(db_session)
    resp = super_admin.post("/api/users", json={"username": "huerfano", "password": "secret1", "role": "viewer"})
    assert resp.status_code == 400


def test_super_admin_can_create_a_user_within_a_specific_organization(client, db_session):
    super_admin = _make_super_admin_client(db_session)
    default_org_id = client.get("/api/auth/me").json()["organization_id"]

    resp = super_admin.post(
        "/api/users",
        json={"username": "delegado", "password": "secret1", "role": "viewer", "organization_id": default_org_id},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["organization_id"] == default_org_id

    listed = client.get("/api/users").json()
    assert "delegado" in {u["username"] for u in listed}


def test_admin_cannot_use_organization_id_to_create_a_user_in_another_org(client, db_session):
    super_admin = _make_super_admin_client(db_session)
    org_b = super_admin.post(
        "/api/organizations",
        json={"name": "Org B", "slug": "org-b", "admin_username": "org-b-admin", "admin_password": "secret123"},
    ).json()

    # An admin's organization_id is ignored, not honored -- the new user
    # always lands in the admin's own organization regardless.
    resp = client.post(
        "/api/users",
        json={
            "username": "colado",
            "password": "secret1",
            "role": "viewer",
            "organization_id": org_b["organization"]["id"],
        },
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["organization_id"] != org_b["organization"]["id"]
