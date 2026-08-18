from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from app.capture.live_capture import mark_orphaned_live_sessions_stopped
from app.models import CaptureSession, Sensor, Site, Zone, utcnow


def test_delete_session_removes_it(client, tmp_path):
    syn = Ether() / IP(src="10.0.0.5", dst="10.0.0.50", ttl=64) / TCP(sport=41000, dport=502, flags="S", window=1024)
    pcap_path = tmp_path / "s.pcap"
    wrpcap(str(pcap_path), [syn])
    with open(pcap_path, "rb") as f:
        session_id = client.post(
            "/api/capture/pcap", files={"file": ("s.pcap", f, "application/vnd.tcpdump.pcap")}
        ).json()["id"]

    assert client.get(f"/api/capture/sessions/{session_id}").status_code == 200
    resp = client.delete(f"/api/capture/sessions/{session_id}")
    assert resp.status_code == 204
    assert client.get(f"/api/capture/sessions/{session_id}").status_code == 404


def test_delete_unknown_session_is_404(client):
    assert client.delete("/api/capture/sessions/999999").status_code == 404


def test_deleting_session_removes_its_devices_protocols_flows_and_findings(client, tmp_path):
    syn = Ether() / IP(src="10.0.1.5", dst="10.0.1.100", ttl=64) / TCP(
        sport=41000, dport=23, flags="S", window=1024
    )
    pcap_path = tmp_path / "telnet.pcap"
    wrpcap(str(pcap_path), [syn])
    with open(pcap_path, "rb") as f:
        session_id = client.post(
            "/api/capture/pcap", files={"file": ("telnet.pcap", f, "application/vnd.tcpdump.pcap")}
        ).json()["id"]

    assert len(client.get("/api/inventory/devices").json()) == 2
    assert len(client.get("/api/inventory/flows").json()) == 1

    scan_findings = client.post("/api/vuln/scan", json={"use_nvd": False}).json()
    assert any(f["title"].lower().count("telnet") for f in scan_findings)
    assert len(client.get("/api/vuln/findings").json()) >= 1

    assert client.delete(f"/api/capture/sessions/{session_id}").status_code == 204

    assert client.get("/api/inventory/devices").json() == []
    assert client.get("/api/inventory/flows").json() == []
    assert client.get("/api/vuln/findings").json() == []


def test_deleting_session_keeps_a_device_still_referenced_by_another_session(client, tmp_path):
    """A client IP that appears in two separate captures, talking to a
    different server in each, must survive deleting the first capture --
    the second capture's flow still references it -- while the
    first capture's own, now-unreferenced server device must go."""
    first_syn = Ether() / IP(src="10.0.1.5", dst="10.0.1.100", ttl=64) / TCP(
        sport=41000, dport=502, flags="S", window=1024
    )
    first_pcap = tmp_path / "first.pcap"
    wrpcap(str(first_pcap), [first_syn])
    with open(first_pcap, "rb") as f:
        first_session_id = client.post(
            "/api/capture/pcap", files={"file": ("first.pcap", f, "application/vnd.tcpdump.pcap")}
        ).json()["id"]

    second_syn = Ether() / IP(src="10.0.1.5", dst="10.0.1.200", ttl=64) / TCP(
        sport=41001, dport=23, flags="S", window=1024
    )
    second_pcap = tmp_path / "second.pcap"
    wrpcap(str(second_pcap), [second_syn])
    with open(second_pcap, "rb") as f:
        client.post("/api/capture/pcap", files={"file": ("second.pcap", f, "application/vnd.tcpdump.pcap")})

    devices_before = client.get("/api/inventory/devices").json()
    assert {d["ip"] for d in devices_before} == {"10.0.1.5", "10.0.1.100", "10.0.1.200"}
    assert len(client.get("/api/inventory/flows").json()) == 2

    assert client.delete(f"/api/capture/sessions/{first_session_id}").status_code == 204

    devices_after = client.get("/api/inventory/devices").json()
    assert {d["ip"] for d in devices_after} == {"10.0.1.5", "10.0.1.200"}

    flows_after = client.get("/api/inventory/flows").json()
    assert len(flows_after) == 1
    assert flows_after[0]["port"] == 23


def test_deleting_a_manual_switchs_session_also_removes_its_network_links_and_imports(client, db_session, org_id):
    """Regression test: a manually-created switch (POST /api/inventory/
    devices, the only path Descubrimiento activo > Topología por switch
    uses to add one) gets a synthetic CaptureSession tied to whichever
    Sensor was picked -- its only capture_session_id, and therefore the
    only way to ever remove it from Inventario at all (no standalone
    DELETE /api/inventory/devices/{id} exists). Real-world report: once
    that switch had a NetworkLink and a switch-table import against it --
    the entire point of creating one -- deleting its session started
    failing with a 500 Internal Server Error. Cause: purge_capture_session
    deleted the Device row without first clearing NetworkLink/
    FlowLinkCandidate/SwitchTableImport rows still pointing at it -- a
    foreign-key violation on Postgres (production), silently tolerated by
    SQLite (every other test in this suite), which is why nothing caught
    it until now."""
    site = Site(organization_id=org_id, name="Planta Yucateca")
    db_session.add(site)
    db_session.flush()
    zone = Zone(site_id=site.id, name="General")
    db_session.add(zone)
    db_session.flush()
    sensor = Sensor(zone_id=zone.id, name="Sensor A", kind="live")
    db_session.add(sensor)
    db_session.commit()

    other_device = client.post(
        "/api/inventory/devices",
        json={"custom_name": "plc-core", "device_type": "plc", "sensor_id": sensor.id},
    ).json()
    switch = client.post(
        "/api/inventory/devices",
        json={"custom_name": "Switch_Core1", "device_type": "network_device",
              "device_type_secondary": "switch_l2", "sensor_id": sensor.id},
    ).json()

    link = client.post(
        "/api/topology/links",
        json={"device_a_id": other_device["id"], "device_b_id": switch["id"], "source_port": "Gi0/1"},
    )
    assert link.status_code == 200, link.text

    imported = client.post(
        "/api/discovery/switch-tables/import",
        json={
            "device_id": switch["id"], "table_type": "mac_table", "vendor": "cisco",
            "raw_text": "Vlan    Mac Address       Type        Ports\n"
            "   1    0011.2233.4455    DYNAMIC     Gi0/2\n",
        },
    )
    assert imported.status_code == 200, imported.text

    sessions = client.get("/api/capture/sessions").json()
    switch_session = next(s for s in sessions if s["source_type"] == "manual_device" and "Switch_Core1" in s["name"])

    resp = client.delete(f"/api/capture/sessions/{switch_session['id']}")
    assert resp.status_code == 204, resp.text

    remaining_ids = {d["id"] for d in client.get("/api/inventory/devices").json()}
    assert switch["id"] not in remaining_ids
    assert client.get("/api/topology").json()["edges"] == []
    assert client.get("/api/discovery/switch-tables/imports").json() == []


def test_stopping_a_session_the_manager_no_longer_tracks_still_succeeds(client, db_session, org_id):
    """Regression test: previously, if the in-process live_capture_manager
    had lost track of a session (e.g. after a server restart left it stuck
    as "running" in the database), calling /live/stop used to 409 forever
    with no way to clear it. It must now succeed unconditionally for any
    live-type session."""
    orphaned = CaptureSession(
        organization_id=org_id, name="live:eth0", source_type="live", source="eth0", status="running",
        started_at=utcnow(),
    )
    db_session.add(orphaned)
    db_session.commit()
    db_session.refresh(orphaned)

    resp = client.post(f"/api/capture/live/stop/{orphaned.id}")
    assert resp.status_code == 200
    assert resp.json()["status"] == "stopped"


def test_stopping_a_non_live_session_is_rejected(client, tmp_path):
    syn = Ether() / IP(src="10.0.0.5", dst="10.0.0.50", ttl=64) / TCP(sport=41000, dport=502, flags="S", window=1024)
    pcap_path = tmp_path / "s.pcap"
    wrpcap(str(pcap_path), [syn])
    with open(pcap_path, "rb") as f:
        session_id = client.post(
            "/api/capture/pcap", files={"file": ("s.pcap", f, "application/vnd.tcpdump.pcap")}
        ).json()["id"]

    resp = client.post(f"/api/capture/live/stop/{session_id}")
    assert resp.status_code == 400


def test_orphaned_live_sessions_are_swept_to_stopped_on_startup(db_session):
    """mark_orphaned_live_sessions_stopped() is what main.py's lifespan
    calls at startup, when live_capture_manager is guaranteed to be a
    fresh, empty tracker -- so any "running" live session at that point is
    necessarily a leftover from a previous process."""
    orphaned = CaptureSession(
        name="live:eth0", source_type="live", source="eth0", status="running", started_at=utcnow()
    )
    still_running_pcap = CaptureSession(  # not a live session: must be left alone
        name="upload.pcap", source_type="pcap", source="upload.pcap", status="running", started_at=utcnow()
    )
    already_stopped = CaptureSession(
        name="live:eth1", source_type="live", source="eth1", status="stopped", started_at=utcnow()
    )
    db_session.add_all([orphaned, still_running_pcap, already_stopped])
    db_session.commit()
    db_session.refresh(orphaned)
    db_session.refresh(still_running_pcap)

    mark_orphaned_live_sessions_stopped()

    db_session.refresh(orphaned)
    db_session.refresh(still_running_pcap)
    assert orphaned.status == "stopped"
    assert orphaned.error_message is not None
    assert still_running_pcap.status == "running"  # untouched: not a live session


def _make_zone_sensor(db_session, org_id, zone_name):
    zone = Zone(site_id=db_session.query(Site).filter(Site.organization_id == org_id).first().id, name=zone_name)
    db_session.add(zone)
    db_session.flush()
    sensor = Sensor(zone_id=zone.id, name=f"Sensor {zone_name}")
    db_session.add(sensor)
    db_session.commit()
    db_session.refresh(zone)
    db_session.refresh(sensor)
    return zone, sensor


def test_device_and_flow_reattributed_when_re_captured_in_a_different_zone(client, db_session, org_id):
    """Regression test for a real-world report: the exact same capture
    (same devices/conversation) re-uploaded into a second Zona showed
    nothing in that Zona's Inventario/Flujos/Topología, even though the
    upload itself completed successfully -- because a device/flow already
    known to the organization stayed pinned to whichever Zona's Sensor
    first observed it (see get_or_create_device/upsert_flow), and
    _filter_by_zone_or_site inner-joins through that single attribution.
    Re-observing it from a second Zona's Sensor must move it there."""
    envasado_zone, envasado_sensor = _make_zone_sensor(db_session, org_id, "Envasado")

    syn = Ether() / IP(src="10.0.9.5", dst="10.0.9.100", ttl=64) / TCP(
        sport=41000, dport=502, flags="S", window=1024
    )

    def _upload(sensor_id):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as d:
            pcap_path = Path(d) / "cap.pcap"
            wrpcap(str(pcap_path), [syn])
            with open(pcap_path, "rb") as f:
                resp = client.post(
                    "/api/capture/pcap",
                    files={"file": ("cap.pcap", f, "application/vnd.tcpdump.pcap")},
                    data={"sensor_id": sensor_id},
                )
        assert resp.status_code == 200, resp.text

    # First capture, on the org's default "Default" Zona/Sensor (seeded by
    # init_db's backfill -- see db.py).
    default_zone_id = db_session.query(Zone).filter(Zone.name == "Default").one().id
    default_sensor_id = db_session.query(Sensor).filter(Sensor.zone_id == default_zone_id).one().id
    _upload(default_sensor_id)

    devices_default = client.get(f"/api/inventory/devices?zone_id={default_zone_id}").json()
    assert {d["ip"] for d in devices_default} == {"10.0.9.5", "10.0.9.100"}
    assert client.get(f"/api/inventory/devices?zone_id={envasado_zone.id}").json() == []
    flows_default = client.get(f"/api/inventory/flows?zone_id={default_zone_id}").json()
    assert len(flows_default) == 1
    assert client.get(f"/api/inventory/flows?zone_id={envasado_zone.id}").json() == []

    # Same exact capture, re-uploaded on Envasado's Sensor -- the reported
    # scenario. Both devices and the flow between them must now show up
    # under Envasado...
    _upload(envasado_sensor.id)

    devices_envasado = client.get(f"/api/inventory/devices?zone_id={envasado_zone.id}").json()
    assert {d["ip"] for d in devices_envasado} == {"10.0.9.5", "10.0.9.100"}
    flows_envasado = client.get(f"/api/inventory/flows?zone_id={envasado_zone.id}").json()
    assert len(flows_envasado) == 1

    # ...and, since a single Device/Flow row only ever tracks its most
    # recent Sensor (a documented limitation, not a many-to-many audit
    # trail), no longer under Default.
    assert client.get(f"/api/inventory/devices?zone_id={default_zone_id}").json() == []
    assert client.get(f"/api/inventory/flows?zone_id={default_zone_id}").json() == []

    # Org-wide (Reportes-style, no zone_id) visibility is unaffected either way.
    assert {d["ip"] for d in client.get("/api/inventory/devices").json()} == {"10.0.9.5", "10.0.9.100"}
