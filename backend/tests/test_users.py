def test_editor_can_create_list_and_delete_a_viewer(client):
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
    resp = client.post("/api/users", json={"username": "ana", "password": "other12", "role": "editor"})
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


def test_cannot_remove_the_last_editor(client):
    me = client.get("/api/auth/me").json()

    # demoting the only editor to viewer would leave zero editors
    resp = client.patch(f"/api/users/{me['id']}", json={"role": "viewer"})
    assert resp.status_code == 400

    resp = client.delete(f"/api/users/{me['id']}")
    assert resp.status_code == 400  # also blocked by the "can't delete yourself" rule, but for the right reason too


def test_can_remove_an_editor_when_another_editor_remains(client):
    second = client.post("/api/users", json={"username": "editor2", "password": "secret1", "role": "editor"}).json()
    me = client.get("/api/auth/me").json()

    resp = client.patch(f"/api/users/{me['id']}", json={"role": "viewer"})
    assert resp.status_code == 200
    assert resp.json()["role"] == "viewer"

    # now current session belongs to a viewer account; further mutations should be forbidden
    assert client.get("/api/users").status_code == 403
    assert second["role"] == "editor"


def test_update_user_password_takes_effect(client, anonymous_client):
    created = client.post("/api/users", json={"username": "bob", "password": "oldpass1", "role": "viewer"}).json()
    client.patch(f"/api/users/{created['id']}", json={"password": "newpass1"})

    old_login = anonymous_client.post("/api/auth/login", json={"username": "bob", "password": "oldpass1"})
    assert old_login.status_code == 401

    new_login = anonymous_client.post("/api/auth/login", json={"username": "bob", "password": "newpass1"})
    assert new_login.status_code == 200
