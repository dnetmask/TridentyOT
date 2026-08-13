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

from app.auth import ROLE_ADMIN, ROLE_SUPER_ADMIN
from app.auth.security import hash_password
from app.models import Organization, Sensor, Site, User, Zone


def _make_other_org_client(db_session, username="other-admin", password="other-pass") -> TestClient:
    """Creates a brand-new Organization (with a default Site/Zone/Sensor,
    same as db.py's startup migration gives the seeded org -- a pcap
    upload needs one to attribute the capture to) and an admin user in it,
    then returns a TestClient already authenticated as that user."""
    org = Organization(name="Other Org", slug="other-org")
    db_session.add(org)
    db_session.flush()

    site = Site(organization_id=org.id, name="Other Site")
    db_session.add(site)
    db_session.flush()
    zone = Zone(site_id=site.id, name="Other Zone")
    db_session.add(zone)
    db_session.flush()
    db_session.add(Sensor(zone_id=zone.id, name="Other Sensor"))

    salt, password_hash = hash_password(password)
    db_session.add(
        User(
            organization_id=org.id,
            username=username,
            password_salt=salt,
            password_hash=password_hash,
            role=ROLE_ADMIN,
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


def test_username_uniqueness_is_scoped_per_organization(client, db_session):
    """A second organization picking "admin" as a username no longer
    collides with org A's seed user -- see models.py's
    User.__table_args__ (uq_user_org_username)."""
    other = _make_other_org_client(db_session)
    resp = other.post("/api/users", json={"username": "admin", "password": "whatever1", "role": "viewer"})
    assert resp.status_code == 201


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


def test_super_admin_username_must_be_globally_unique(db_session):
    """Two super_admin rows (organization_id IS NULL) must never share a
    username -- the composite (organization_id, username) constraint alone
    wouldn't catch this, since NULL != NULL. See models.py's
    uq_user_username_super_admin partial index."""
    _make_super_admin_client(db_session, username="root")

    from sqlalchemy.exc import IntegrityError

    salt, password_hash = hash_password("other-pass1")
    db_session.add(
        User(
            organization_id=None,
            username="root",
            password_salt=salt,
            password_hash=password_hash,
            role=ROLE_SUPER_ADMIN,
        )
    )
    try:
        db_session.commit()
        assert False, "expected a uniqueness violation"
    except IntegrityError:
        db_session.rollback()


def test_super_admin_sees_devices_and_sessions_across_every_organization(client, db_session, tmp_path):
    _upload_pcap_as(client, tmp_path)
    other = _make_other_org_client(db_session)
    _upload_pcap_as(other, tmp_path, filename="other.pcap")

    super_admin = _make_super_admin_client(db_session)
    assert len(super_admin.get("/api/inventory/devices").json()) == 4
    assert len(super_admin.get("/api/capture/sessions").json()) == 2
    assert len(super_admin.get("/api/users").json()) >= 3  # org A admin, org B admin, super_admin itself


def test_super_admin_can_filter_devices_sessions_and_findings_by_organization_id(
    client, db_session, org_id, tmp_path
):
    """Regression test: a super admin browsing a specific organization (e.g.
    a brand-new one with zero data) must see only that organization's rows
    when passing organization_id -- not every organization's, which is what
    list_devices/list_sessions/list_findings used to return before they
    learned about the organization_id query param (they only ever filtered
    for non-super-admin callers, same as this file's already-existing
    test_super_admin_sees_devices_and_sessions_across_every_organization
    covers for the *unfiltered* case)."""
    _upload_pcap_as(client, tmp_path)  # 2 devices in org_id, session named "telnet.pcap"
    own_findings = client.post("/api/vuln/scan", json={"use_nvd": False}).json()
    assert own_findings  # telnet (port 23) trips the insecure-protocol rule

    other = _make_other_org_client(db_session)
    other_org_id = db_session.query(User).filter(User.username == "other-admin").one().organization_id
    _upload_pcap_as(other, tmp_path, filename="other.pcap")  # 2 more devices, in other_org_id
    other_findings = other.post("/api/vuln/scan", json={"use_nvd": False}).json()
    assert other_findings

    super_admin = _make_super_admin_client(db_session)

    own_devices = super_admin.get(f"/api/inventory/devices?organization_id={org_id}").json()
    other_devices = super_admin.get(f"/api/inventory/devices?organization_id={other_org_id}").json()
    assert len(own_devices) == 2
    assert len(other_devices) == 2
    assert {d["id"] for d in own_devices}.isdisjoint({d["id"] for d in other_devices})

    own_sessions = super_admin.get(f"/api/capture/sessions?organization_id={org_id}").json()
    other_sessions = super_admin.get(f"/api/capture/sessions?organization_id={other_org_id}").json()
    assert [s["name"] for s in own_sessions] == ["telnet.pcap"]
    assert [s["name"] for s in other_sessions] == ["other.pcap"]

    own_finding_devices = {f["device_id"] for f in super_admin.get(f"/api/vuln/findings?organization_id={org_id}").json()}
    other_finding_devices = {
        f["device_id"] for f in super_admin.get(f"/api/vuln/findings?organization_id={other_org_id}").json()
    }
    assert own_finding_devices and own_finding_devices <= {d["id"] for d in own_devices}
    assert other_finding_devices and other_finding_devices <= {d["id"] for d in other_devices}

    # A brand-new, still-empty organization must show up as empty, not as
    # "every organization" (the reported bug).
    empty_org = Organization(name="Empty Org", slug="empty-org")
    db_session.add(empty_org)
    db_session.commit()
    assert super_admin.get(f"/api/inventory/devices?organization_id={empty_org.id}").json() == []
    assert super_admin.get(f"/api/capture/sessions?organization_id={empty_org.id}").json() == []
    assert super_admin.get(f"/api/vuln/findings?organization_id={empty_org.id}").json() == []
