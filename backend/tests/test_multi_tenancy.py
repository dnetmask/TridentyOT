"""Two organizations sharing one database/instance (the central-console
topology -- see docs) must never see or affect each other's data. There's
no API to create an organization yet (every deployment today provisions
exactly one via db.py's startup migration), so these tests create the
second org/user directly against the DB, the same way a future admin
endpoint would.
"""

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap
from fastapi.testclient import TestClient

from app.auth import ROLE_EDITOR
from app.auth.security import hash_password
from app.models import Organization, User


def _make_other_org_client(db_session, username="other-admin", password="other-pass") -> TestClient:
    """Creates a brand-new Organization and an editor user in it, then
    returns a TestClient already authenticated as that user."""
    org = Organization(name="Other Org", slug="other-org")
    db_session.add(org)
    db_session.flush()

    salt, password_hash = hash_password(password)
    db_session.add(
        User(
            organization_id=org.id,
            username=username,
            password_salt=salt,
            password_hash=password_hash,
            role=ROLE_EDITOR,
        )
    )
    db_session.commit()

    from app.main import app

    other_client = TestClient(app)
    resp = other_client.post("/api/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    other_client.headers.update({"Authorization": f"Bearer {resp.json()['token']}"})
    return other_client


def _upload_pcap_as(client, tmp_path, filename="telnet.pcap"):
    syn = Ether() / IP(src="10.0.1.5", dst="10.0.1.100", ttl=64) / TCP(
        sport=41000, dport=23, flags="S", window=1024
    )
    pcap_path = tmp_path / filename
    wrpcap(str(pcap_path), [syn])
    with open(pcap_path, "rb") as f:
        resp = client.post("/api/capture/pcap", files={"file": (filename, f, "application/vnd.tcpdump.pcap")})
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_devices_are_scoped_to_the_caller_s_organization(client, db_session, tmp_path):
    _upload_pcap_as(client, tmp_path)
    assert len(client.get("/api/inventory/devices").json()) == 2

    other = _make_other_org_client(db_session)
    assert other.get("/api/inventory/devices").json() == []
    assert other.get("/api/inventory/flows").json() == []
    assert other.get("/api/vuln/findings").json() == []
    assert other.get("/api/capture/sessions").json() == []


def test_device_from_another_org_is_a_404_not_a_cross_tenant_leak(client, db_session, tmp_path):
    _upload_pcap_as(client, tmp_path)
    device_id = client.get("/api/inventory/devices").json()[0]["id"]

    other = _make_other_org_client(db_session)
    assert other.get(f"/api/inventory/devices/{device_id}").status_code == 404
    assert other.patch(f"/api/inventory/devices/{device_id}", json={"custom_name": "hijacked"}).status_code == 404


def test_capture_session_from_another_org_is_a_404(client, db_session, tmp_path):
    session_id = _upload_pcap_as(client, tmp_path)["id"]

    other = _make_other_org_client(db_session)
    assert other.get(f"/api/capture/sessions/{session_id}").status_code == 404
    assert other.delete(f"/api/capture/sessions/{session_id}").status_code == 404


def test_scan_all_only_scans_the_caller_s_organization_s_devices(client, db_session, tmp_path):
    _upload_pcap_as(client, tmp_path)

    other = _make_other_org_client(db_session)
    other_findings = other.post("/api/vuln/scan", json={"use_nvd": False}).json()
    assert other_findings == []
    # The other org's scan must not have touched org A's findings either.
    assert len(client.get("/api/vuln/findings").json()) == 0  # not scanned yet from A's own client
    own_findings = client.post("/api/vuln/scan", json={"use_nvd": False}).json()
    assert len(own_findings) >= 1


def test_wipe_database_never_touches_another_organization_s_data(client, db_session, tmp_path):
    _upload_pcap_as(client, tmp_path)
    other = _make_other_org_client(db_session)
    _upload_pcap_as(other, tmp_path, filename="other.pcap")
    assert len(other.get("/api/inventory/devices").json()) == 2

    assert client.delete("/api/capture/wipe").status_code == 200

    assert client.get("/api/inventory/devices").json() == []
    assert len(other.get("/api/inventory/devices").json()) == 2


def test_users_list_is_scoped_to_the_caller_s_organization(client, db_session):
    other = _make_other_org_client(db_session)

    own_usernames = {u["username"] for u in client.get("/api/users").json()}
    other_usernames = {u["username"] for u in other.get("/api/users").json()}
    assert "other-admin" not in own_usernames
    assert "admin" not in other_usernames


def test_username_uniqueness_is_still_global_not_per_organization(client, db_session):
    """Documented current limitation (see models.py's User.organization_id
    comment): usernames are globally unique, not scoped per-org, until the
    central console actually needs more than one org sharing an instance.
    A second org creating "admin" today collides with org A's seed user."""
    other = _make_other_org_client(db_session)
    resp = other.post("/api/users", json={"username": "admin", "password": "whatever1", "role": "viewer"})
    assert resp.status_code == 409
