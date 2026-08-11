"""Tests for active discovery via PROFINET DCP's "Identify All" service --
see app/capture/active_discovery.py and app/api/routes_discovery.py.

Runs the real scan against the loopback interface: a background thread
injects a synthetic DCP Identify Response (the same frame shape scapy's
own pnio_dcp docstring documents) partway through the scan's listen
window, exactly mirroring how a real PROFINET device would answer the
broadcast this endpoint sends.
"""

import threading
import time

from scapy.contrib.pnio import ProfinetIO
from scapy.contrib.pnio_dcp import (
    DCP_IDENTIFY_RESPONSE_FRAME_ID,
    DCP_RESPONSE,
    DCP_SERVICE_ID_IDENTIFY,
    DCPNameOfStationBlock,
    ProfinetDCP,
)
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp


def _send_fake_identify_response(name: str, delay: float = 0.3) -> None:
    def _send():
        time.sleep(delay)
        frame = (
            # A real device's own NIC MAC -- Ether()'s all-zero default
            # source is deliberately rejected as garbage by
            # get_or_create_device's _is_real_unicast_mac check, same as it
            # would be for a genuinely malformed frame.
            Ether(src="00:1b:1b:aa:bb:cc", dst="ff:ff:ff:ff:ff:ff")
            / ProfinetIO(frameID=DCP_IDENTIFY_RESPONSE_FRAME_ID)
            / ProfinetDCP(service_id=DCP_SERVICE_ID_IDENTIFY, service_type=DCP_RESPONSE)
            / DCPNameOfStationBlock(name_of_station=name)
        )
        sendp(frame, iface="lo", verbose=False)

    threading.Thread(target=_send, daemon=True).start()


def test_profinet_dcp_scan_discovers_a_responding_device(client, db_session):
    from app.models import Sensor

    sensor = db_session.query(Sensor).filter(Sensor.name == "Default").one()

    _send_fake_identify_response("plc-line-1")
    resp = client.post(
        "/api/discovery/profinet-dcp",
        json={"interface": "lo", "sensor_id": sensor.id, "duration_seconds": 1},
    )
    assert resp.status_code == 200, resp.text
    session = resp.json()
    assert session["source_type"] == "active_pnio_dcp"

    # The response body is a snapshot taken the instant the session row was
    # created (status "running") -- same as /api/capture/live/start and the
    # pcap upload endpoint -- because BackgroundTasks runs *after* that body
    # is already serialized. TestClient still runs it to completion before
    # this test's client.post() call returns, so a fresh fetch now reflects
    # the real, finished state.
    finished = client.get(f"/api/capture/sessions/{session['id']}").json()
    assert finished["status"] == "completed", finished

    devices = client.get("/api/inventory/devices").json()
    assert any(d["hostname"] == "plc-line-1" for d in devices), devices


def test_profinet_dcp_scan_with_no_replies_creates_no_devices(client, db_session):
    from app.models import Sensor

    sensor = db_session.query(Sensor).filter(Sensor.name == "Default").one()

    resp = client.post(
        "/api/discovery/profinet-dcp",
        json={"interface": "lo", "sensor_id": sensor.id, "duration_seconds": 1},
    )
    assert resp.status_code == 200, resp.text
    finished = client.get(f"/api/capture/sessions/{resp.json()['id']}").json()
    assert finished["status"] == "completed", finished
    # Our own broadcast request must not create a phantom "device" for the
    # sensor's own interface -- see _is_identify_request in
    # app/capture/active_discovery.py.
    assert client.get("/api/inventory/devices").json() == []


def test_profinet_dcp_scan_rejects_an_external_sensor(client):
    site = client.post("/api/sites", json={"name": "Planta Externa"}).json()
    zone = client.post("/api/zones", json={"site_id": site["id"], "name": "Zona externa"}).json()
    sensor = client.post(
        "/api/sensors", json={"zone_id": zone["id"], "name": "Sensor externo", "kind": "external"}
    ).json()

    resp = client.post(
        "/api/discovery/profinet-dcp",
        json={"interface": "lo", "sensor_id": sensor["id"], "duration_seconds": 1},
    )
    assert resp.status_code == 400


def test_profinet_dcp_scan_requires_admin(client, make_client, db_session):
    from app.models import Sensor

    sensor = db_session.query(Sensor).filter(Sensor.name == "Default").one()
    client.post("/api/users", json={"username": "viewer-disc", "password": "secret1", "role": "viewer"})
    viewer = make_client("viewer-disc", "secret1")

    resp = viewer.post(
        "/api/discovery/profinet-dcp",
        json={"interface": "lo", "sensor_id": sensor.id, "duration_seconds": 1},
    )
    assert resp.status_code == 403


def test_profinet_dcp_scan_rejects_another_organizations_sensor(client, db_session):
    from app.auth import ROLE_ADMIN
    from app.auth.security import hash_password
    from app.models import Organization, Sensor, Site, User, Zone

    org = Organization(name="Org B", slug="org-b-disc")
    db_session.add(org)
    db_session.flush()
    site = Site(organization_id=org.id, name="Site B")
    db_session.add(site)
    db_session.flush()
    zone = Zone(site_id=site.id, name="Zone B")
    db_session.add(zone)
    db_session.flush()
    sensor = Sensor(zone_id=zone.id, name="Sensor B")
    db_session.add(sensor)
    salt, password_hash = hash_password("secret123")
    db_session.add(
        User(organization_id=org.id, username="org-b-disc-admin", password_salt=salt, password_hash=password_hash, role=ROLE_ADMIN)
    )
    db_session.commit()

    resp = client.post(
        "/api/discovery/profinet-dcp",
        json={"interface": "lo", "sensor_id": sensor.id, "duration_seconds": 1},
    )
    assert resp.status_code == 404


def test_profinet_dcp_scan_duration_is_bounded(client, db_session):
    from app.models import Sensor

    sensor = db_session.query(Sensor).filter(Sensor.name == "Default").one()

    too_long = client.post(
        "/api/discovery/profinet-dcp",
        json={"interface": "lo", "sensor_id": sensor.id, "duration_seconds": 100},
    )
    assert too_long.status_code == 422

    too_short = client.post(
        "/api/discovery/profinet-dcp",
        json={"interface": "lo", "sensor_id": sensor.id, "duration_seconds": 0},
    )
    assert too_short.status_code == 422
