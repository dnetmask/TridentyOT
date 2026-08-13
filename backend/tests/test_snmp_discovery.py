"""Tests for active discovery via a light SNMP sweep -- see
app/capture/snmp_discovery.py and app/api/routes_discovery.py.

Runs a real SNMP GET/response round trip over loopback UDP/161 using
scapy's own SNMP layer (not a mock): a background thread plays the part
of a toy SNMP agent, decoding the actual request bytes this app sends and
replying with hand-built varbinds -- the same "exercise the real wire
protocol against a throwaway listener" approach test_nmap_discovery.py
uses for TCP.

Like nmap, this scan runs in a real background thread (SnmpScanManager),
not a FastAPI BackgroundTask -- so these tests poll for completion the
same way a real browser client would.
"""

import socket
import threading
import time

from scapy.asn1.asn1 import ASN1_STRING

from scapy.layers.snmp import SNMP, SNMPresponse, SNMPvarbind

import app.capture.snmp_discovery as snmp_discovery


def _run_fake_snmp_agent(sock, values, replies=1):
    """Answers `replies` incoming GET requests with whatever OIDs in
    `values` (a dict of oid string -> reply string) the request actually
    asked for -- an OID the caller didn't provide a value for is simply
    left out of the response, the same way a real agent would omit an
    unsupported object rather than return junk."""
    for _ in range(replies):
        try:
            data, addr = sock.recvfrom(4096)
        except OSError:
            return
        request = SNMP(data)
        varbinds = [
            SNMPvarbind(oid=vb.oid, value=ASN1_STRING(values[vb.oid.val]))
            for vb in request.PDU.varbindlist
            if vb.oid.val in values
        ]
        if not varbinds:
            continue
        response = SNMP(community=request.community, PDU=SNMPresponse(id=request.PDU.id, varbindlist=varbinds))
        sock.sendto(bytes(response), addr)


def _wait_until_done(client, session_id, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        session = client.get(f"/api/capture/sessions/{session_id}").json()
        if session["status"] != "running":
            return session
        time.sleep(0.2)
    raise AssertionError(f"session {session_id} did not finish within {timeout}s")


def test_snmp_scan_discovers_a_responding_host(client, db_session):
    from app.models import Sensor

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 161))
    values = {
        snmp_discovery._OID_SYS_DESCR: "Linux fakebox 5.4.0",
        snmp_discovery._OID_SYS_OBJECT_ID: "1.3.6.1.4.1.9.1.1",
        # Deliberately a hostname with no device_classifier.py keyword
        # match (no "plc"/"hmi"/"srv"/...) -- this test is about SNMP's
        # own wiring, not about the hostname-based classifier heuristic,
        # and a keyword match would overwrite device_type_evidence before
        # this test gets to check it still holds the sysObjectID text.
        snmp_discovery._OID_SYS_NAME: "device-1.example",
    }
    threading.Thread(target=_run_fake_snmp_agent, args=(sock, values), daemon=True).start()

    try:
        sensor = db_session.query(Sensor).filter(Sensor.name == "Sensor interno").one()
        resp = client.post("/api/discovery/snmp", json={"target": "127.0.0.1", "sensor_id": sensor.id})
        assert resp.status_code == 200, resp.text
        session = resp.json()
        assert session["source_type"] == "active_snmp"
        assert session["status"] == "running"

        finished = _wait_until_done(client, session["id"])
        assert finished["status"] == "completed", finished
        assert finished["packet_count"] == 1  # repurposed as "hosts found" -- see snmp_discovery
        assert finished["progress_percent"] == 100.0

        devices = client.get("/api/inventory/devices").json()
        matches = [d for d in devices if d["ip"] == "127.0.0.1"]
        assert len(matches) == 1, devices
        device = matches[0]
        assert device["hostname"] == "device-1.example"
        assert device["os_guess"] == "Linux fakebox 5.4.0"
        assert "1.3.6.1.4.1.9.1.1" in (device["device_type_evidence"] or "")

        detail = client.get(f"/api/inventory/devices/{device['id']}").json()
        assert any(p["port"] == 161 and p["protocol"] == "snmp" for p in detail["protocols"]), detail["protocols"]
    finally:
        sock.close()


def test_snmp_scan_progress_updates_while_running(client, db_session, monkeypatch):
    """The point of no fixed duration: progress climbs live instead of
    only being knowable once the whole sweep is done."""
    from app.models import Sensor

    monkeypatch.setattr(snmp_discovery, "_PER_CHUNK_TIMEOUT_SECONDS", 2.0)
    sensor = db_session.query(Sensor).filter(Sensor.name == "Sensor interno").one()

    # 127.0.0.2 never answers -- the sweep has to sit out the full
    # per-chunk timeout before this session leaves "running", giving this
    # test a window to see an in-between progress reading.
    resp = client.post("/api/discovery/snmp", json={"target": "127.0.0.2", "sensor_id": sensor.id})
    assert resp.status_code == 200, resp.text
    session_id = resp.json()["id"]

    saw_total = False
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        session = client.get(f"/api/capture/sessions/{session_id}").json()
        if session["total_bytes"] == 1:  # a single target -- set as soon as the worker starts
            saw_total = True
        if session["status"] != "running":
            break
        time.sleep(0.1)
    assert saw_total, "expected total_bytes (target count) to be set while running"

    finished = _wait_until_done(client, session_id)
    assert finished["status"] == "completed", finished
    assert finished["packet_count"] == 0  # nobody answered


def test_snmp_scan_can_be_stopped(client, db_session, monkeypatch):
    """Stubs out sr() itself rather than relying on real network timing:
    a real loopback sweep answers (or gets ICMP-rejected) fast enough that
    a timing-based test would be racy about catching it mid-flight. A slow
    fake sr() gives full, deterministic control over when each chunk
    "finishes", so the test can stop the scan mid-sweep on its own clock."""
    from app.models import Sensor

    def _slow_sr(packets, **kwargs):
        time.sleep(1.0)
        return [], packets

    monkeypatch.setattr(snmp_discovery, "sr", _slow_sr)
    monkeypatch.setattr(snmp_discovery, "_CHUNK_SIZE", 2)
    sensor = db_session.query(Sensor).filter(Sensor.name == "Sensor interno").one()

    resp = client.post("/api/discovery/snmp", json={"target": "127.0.0.0/29", "sensor_id": sensor.id})
    assert resp.status_code == 200, resp.text
    session_id = resp.json()["id"]
    time.sleep(0.3)  # well within the first (still in-flight) chunk's fake 1s sr() call

    stop_resp = client.post(f"/api/discovery/snmp/stop/{session_id}")
    assert stop_resp.status_code == 200, stop_resp.text

    finished = _wait_until_done(client, session_id, timeout=20)
    assert finished["status"] == "stopped", finished


def test_snmp_scan_rejects_an_invalid_target(client, db_session):
    from app.models import Sensor

    sensor = db_session.query(Sensor).filter(Sensor.name == "Sensor interno").one()
    resp = client.post("/api/discovery/snmp", json={"target": "not-an-ip-or-cidr", "sensor_id": sensor.id})
    assert resp.status_code == 400


def test_snmp_scan_rejects_an_external_sensor(client):
    site = client.post("/api/sites", json={"name": "Planta Externa SNMP"}).json()
    zone = client.post("/api/zones", json={"site_id": site["id"], "name": "Zona externa"}).json()
    sensor = client.post(
        "/api/sensors", json={"zone_id": zone["id"], "name": "Sensor externo", "kind": "external"}
    ).json()

    resp = client.post("/api/discovery/snmp", json={"target": "127.0.0.1", "sensor_id": sensor["id"]})
    assert resp.status_code == 400


def test_snmp_scan_requires_admin(client, make_client, db_session):
    from app.models import Sensor

    sensor = db_session.query(Sensor).filter(Sensor.name == "Sensor interno").one()
    client.post("/api/users", json={"username": "viewer-snmp", "password": "secret1", "role": "viewer"})
    viewer = make_client("viewer-snmp", "secret1")

    resp = viewer.post("/api/discovery/snmp", json={"target": "127.0.0.1", "sensor_id": sensor.id})
    assert resp.status_code == 403


def test_snmp_scan_rejects_another_organizations_sensor(client, db_session):
    from app.auth import ROLE_ADMIN
    from app.auth.security import hash_password
    from app.models import Organization, Sensor, Site, User, Zone

    org = Organization(name="Org C", slug="org-c-snmp")
    db_session.add(org)
    db_session.flush()
    site = Site(organization_id=org.id, name="Site C")
    db_session.add(site)
    db_session.flush()
    zone = Zone(site_id=site.id, name="Zone C")
    db_session.add(zone)
    db_session.flush()
    sensor = Sensor(zone_id=zone.id, name="Sensor C")
    db_session.add(sensor)
    salt, password_hash = hash_password("secret123")
    db_session.add(
        User(organization_id=org.id, username="org-c-snmp-admin", password_salt=salt, password_hash=password_hash, role=ROLE_ADMIN)
    )
    db_session.commit()

    resp = client.post("/api/discovery/snmp", json={"target": "127.0.0.1", "sensor_id": sensor.id})
    assert resp.status_code == 404


def test_snmp_scan_requires_a_target(client, db_session):
    from app.models import Sensor

    sensor = db_session.query(Sensor).filter(Sensor.name == "Sensor interno").one()
    resp = client.post("/api/discovery/snmp", json={"target": "", "sensor_id": sensor.id})
    assert resp.status_code == 422


def test_stopping_a_non_snmp_session_is_rejected(client, tmp_path):
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.utils import wrpcap

    syn = Ether() / IP(src="10.0.1.5", dst="10.0.1.100", ttl=64) / TCP(sport=41000, dport=23, flags="S", window=1024)
    pcap_path = tmp_path / "t.pcap"
    wrpcap(str(pcap_path), [syn])
    with open(pcap_path, "rb") as f:
        session = client.post(
            "/api/capture/pcap", files={"file": ("t.pcap", f, "application/vnd.tcpdump.pcap")}
        ).json()

    resp = client.post(f"/api/discovery/snmp/stop/{session['id']}")
    assert resp.status_code == 400


# ---------------------------------------------------------------------
# Table walk (_SnmpWalkWorker / POST /api/discovery/snmp/switch-walk) --
# see snmp_discovery.py's module docstring, second half.
# ---------------------------------------------------------------------


def _run_fake_snmp_walk_agent(sock, table, replies):
    """Plays a toy switch answering GETNEXT (not GET): `table` is a dict of
    oid string -> ASN1 value, walked in numeric OID order the same way a
    real agent would -- an OID with nothing configured after it in the
    combined tree (including subtrees this fake agent has nothing at all
    in) simply gets no reply, same as a real device's endOfMibView."""
    sorted_oids = sorted(table.keys(), key=lambda o: [int(x) for x in o.split(".")])

    def _next_oid(requested):
        parts = [int(x) for x in requested.split(".")]
        for oid in sorted_oids:
            if [int(x) for x in oid.split(".")] > parts:
                return oid
        return None

    for _ in range(replies):
        try:
            data, addr = sock.recvfrom(4096)
        except OSError:
            return
        request = SNMP(data)
        requested_oid = request.PDU.varbindlist[0].oid.val
        next_oid = _next_oid(requested_oid)
        if next_oid is None:
            continue  # no reply -- exactly what lets the walk's caller time out and move on
        from scapy.asn1.asn1 import ASN1_OID

        varbind = SNMPvarbind(oid=ASN1_OID(next_oid), value=table[next_oid])
        response = SNMP(community=request.community, PDU=SNMPresponse(id=request.PDU.id, varbindlist=[varbind]))
        sock.sendto(bytes(response), addr)


def test_snmp_switch_walk_creates_a_link_from_a_single_mac_port(client, db_session, org_id, monkeypatch):
    """End-to-end: a switch with one MAC address table entry, on a port
    that matches an existing Device's MAC, should come out the other end
    as a NetworkLink -- same outcome POST /api/discovery/switch-tables/import
    produces for a pasted table, just fed by a live walk instead."""
    from scapy.asn1.asn1 import ASN1_INTEGER, ASN1_STRING

    from app.models import Device, NetworkLink, Sensor

    # Nothing else in this test's fake agent answers at all (no ARP, no
    # LLDP columns) -- keep those walks' per-row timeout short so the test
    # doesn't sit through several full 2s waits for subtrees with no data.
    monkeypatch.setattr(snmp_discovery, "_PER_CHUNK_TIMEOUT_SECONDS", 0.3)

    plc_mac = "00:11:22:33:44:55"
    plc = Device(organization_id=org_id, mac=plc_mac, ip="10.0.1.10")
    db_session.add(plc)
    db_session.commit()

    mac_bytes = bytes(int(b, 16) for b in plc_mac.split(":"))
    fdb_oid = snmp_discovery._OID_DOT1D_TP_FDB_PORT + "." + ".".join(str(b) for b in mac_bytes)
    ifindex_oid = snmp_discovery._OID_DOT1D_BASE_PORT_IFINDEX + ".1"
    ifdescr_oid = snmp_discovery._OID_IF_DESCR + ".100"
    table = {
        fdb_oid: ASN1_INTEGER(1),
        ifindex_oid: ASN1_INTEGER(100),
        ifdescr_oid: ASN1_STRING(b"Gi0/1"),
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 161))
    threading.Thread(target=_run_fake_snmp_walk_agent, args=(sock, table, 50), daemon=True).start()

    try:
        sensor = db_session.query(Sensor).filter(Sensor.name == "Sensor interno").one()
        resp = client.post(
            "/api/discovery/snmp/switch-walk",
            json={"targets": ["127.0.0.1"], "sensor_id": sensor.id, "community": "public", "version": "v2c"},
        )
        assert resp.status_code == 200, resp.text
        session = resp.json()
        assert session["source_type"] == "active_snmp_walk"

        finished = _wait_until_done(client, session["id"], timeout=30)
        assert finished["status"] == "completed", finished

        switches = [d for d in client.get("/api/inventory/devices").json() if d["ip"] == "127.0.0.1"]
        assert len(switches) == 1, switches
        switch_id = switches[0]["id"]

        link = db_session.query(NetworkLink).one()
        assert {link.device_a_id, link.device_b_id} == {switch_id, plc.id}
        assert link.source == "mac_table"
        assert "Gi0/1" in (link.source_port, link.target_port)
    finally:
        sock.close()


def test_snmp_switch_walk_can_be_stopped(client, db_session, monkeypatch):
    def _slow_sr(packets, **kwargs):
        time.sleep(1.0)
        return [], packets

    monkeypatch.setattr(snmp_discovery, "sr", _slow_sr)
    from app.models import Sensor

    sensor = db_session.query(Sensor).filter(Sensor.name == "Sensor interno").one()
    resp = client.post(
        "/api/discovery/snmp/switch-walk",
        json={"targets": ["127.0.0.1", "127.0.0.2"], "sensor_id": sensor.id},
    )
    assert resp.status_code == 200, resp.text
    session_id = resp.json()["id"]
    time.sleep(0.3)

    stop_resp = client.post(f"/api/discovery/snmp/switch-walk/stop/{session_id}")
    assert stop_resp.status_code == 200, stop_resp.text

    finished = _wait_until_done(client, session_id, timeout=20)
    assert finished["status"] == "stopped", finished


def test_stopping_a_non_walk_session_is_rejected(client, db_session):
    from app.models import Sensor

    sensor = db_session.query(Sensor).filter(Sensor.name == "Sensor interno").one()
    resp = client.post("/api/discovery/snmp", json={"target": "127.0.0.3", "sensor_id": sensor.id})
    session_id = resp.json()["id"]

    stop_resp = client.post(f"/api/discovery/snmp/switch-walk/stop/{session_id}")
    assert stop_resp.status_code == 400
