from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap


def test_upload_pcap_builds_inventory_and_scan_finds_telnet(client, tmp_path):
    syn = Ether() / IP(src="192.168.1.5", dst="192.168.1.100", ttl=64) / TCP(
        sport=40000, dport=23, flags="S", window=1024
    )
    synack = Ether() / IP(src="192.168.1.100", dst="192.168.1.5", ttl=64) / TCP(
        sport=23, dport=40000, flags="SA", window=8192
    )
    pcap_path = tmp_path / "sample.pcap"
    wrpcap(str(pcap_path), [syn, synack])

    with open(pcap_path, "rb") as f:
        resp = client.post(
            "/api/capture/pcap",
            files={"file": ("sample.pcap", f, "application/vnd.tcpdump.pcap")},
        )
    assert resp.status_code == 200
    session_data = resp.json()

    # The initial response is serialized before the background task runs;
    # by the time TestClient.post() returns, the background task (which
    # runs synchronously within the same request lifecycle) has already
    # completed, so a follow-up GET reflects the final state.
    session_after = client.get(f"/api/capture/sessions/{session_data['id']}").json()
    assert session_after["status"] == "completed"
    assert session_after["packet_count"] == 2

    devices = client.get("/api/inventory/devices").json()
    assert len(devices) == 2
    server = next(d for d in devices if d["ip"] == "192.168.1.100")

    scan_resp = client.post("/api/vuln/scan", json={"use_nvd": False})
    assert scan_resp.status_code == 200
    findings = scan_resp.json()
    telnet_finding = next(f for f in findings if f["device_id"] == server["id"] and "telnet" in f["title"])
    assert telnet_finding["device_ip"] == "192.168.1.100"

    detail = client.get(f"/api/inventory/devices/{server['id']}").json()
    assert any(p["protocol"] == "telnet" for p in detail["protocols"])
    assert any("telnet" in f["title"] for f in detail["findings"])

    flows = client.get("/api/inventory/flows").json()
    assert len(flows) == 1
    assert flows[0]["port"] == 23
    assert flows[0]["protocol"] == "telnet"
    assert {flows[0]["device_a_ip"], flows[0]["device_b_ip"]} == {"192.168.1.5", "192.168.1.100"}


def test_patch_device_sets_and_clears_custom_name_and_vendor(client, tmp_path):
    syn = Ether() / IP(src="10.5.0.5", dst="10.5.0.60", ttl=64) / TCP(sport=41000, dport=502, flags="S", window=1024)
    pcap_path = tmp_path / "modbus.pcap"
    wrpcap(str(pcap_path), [syn])
    with open(pcap_path, "rb") as f:
        client.post("/api/capture/pcap", files={"file": ("modbus.pcap", f, "application/vnd.tcpdump.pcap")})

    devices = client.get("/api/inventory/devices").json()
    plc = next(d for d in devices if d["ip"] == "10.5.0.60")
    assert plc["display_name"] is None

    resp = client.patch(f"/api/inventory/devices/{plc['id']}", json={"custom_name": "PLC Linea 3"})
    assert resp.status_code == 200
    updated = resp.json()
    assert updated["custom_name"] == "PLC Linea 3"
    assert updated["display_name"] == "PLC Linea 3"

    resp = client.patch(f"/api/inventory/devices/{plc['id']}", json={"custom_name": None})
    assert resp.status_code == 200
    cleared = resp.json()
    assert cleared["custom_name"] is None
    assert cleared["display_name"] is None


def test_patch_unknown_device_returns_404(client):
    resp = client.patch("/api/inventory/devices/999999", json={"custom_name": "x"})
    assert resp.status_code == 404


def test_patch_device_sets_and_clears_custom_device_type(client, tmp_path):
    syn = Ether() / IP(src="10.5.0.6", dst="10.5.0.61", ttl=64) / TCP(sport=41000, dport=502, flags="S", window=1024)
    pcap_path = tmp_path / "modbus2.pcap"
    wrpcap(str(pcap_path), [syn])
    with open(pcap_path, "rb") as f:
        client.post("/api/capture/pcap", files={"file": ("modbus2.pcap", f, "application/vnd.tcpdump.pcap")})

    devices = client.get("/api/inventory/devices").json()
    plc = next(d for d in devices if d["ip"] == "10.5.0.61")
    # Auto-classified from the Modbus server protocol alone, no override yet.
    assert plc["device_type"] == "plc"
    assert plc["custom_device_type"] is None
    assert plc["display_device_type"] == "plc"

    resp = client.patch(f"/api/inventory/devices/{plc['id']}", json={"custom_device_type": "server"})
    assert resp.status_code == 200
    updated = resp.json()
    assert updated["custom_device_type"] == "server"
    assert updated["display_device_type"] == "server"
    assert updated["device_type"] == "plc"  # auto-detected value is preserved underneath

    resp = client.patch(f"/api/inventory/devices/{plc['id']}", json={"custom_device_type": None})
    assert resp.status_code == 200
    cleared = resp.json()
    assert cleared["custom_device_type"] is None
    assert cleared["display_device_type"] == "plc"


def test_patch_device_rejects_unknown_device_type(client, tmp_path):
    syn = Ether() / IP(src="10.5.0.7", dst="10.5.0.62", ttl=64) / TCP(sport=41000, dport=502, flags="S", window=1024)
    pcap_path = tmp_path / "modbus3.pcap"
    wrpcap(str(pcap_path), [syn])
    with open(pcap_path, "rb") as f:
        client.post("/api/capture/pcap", files={"file": ("modbus3.pcap", f, "application/vnd.tcpdump.pcap")})

    devices = client.get("/api/inventory/devices").json()
    device_id = next(d for d in devices if d["ip"] == "10.5.0.62")["id"]

    resp = client.patch(f"/api/inventory/devices/{device_id}", json={"custom_device_type": "printer"})
    assert resp.status_code == 422


def test_health_endpoint(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_list_interfaces_endpoint_does_not_crash(client):
    resp = client.get("/api/capture/interfaces")
    assert resp.status_code in (200, 500)


def test_public_ip_device_excluded_from_inventory_but_kept_in_flows_and_findings(client, tmp_path):
    """A device out on the public internet was never an asset of *this*
    network -- it shouldn't clutter Inventory -- but the LAN device that
    reached it, and that conversation/finding, are still real and must
    keep showing up in Flows and Vulnerabilities."""
    syn = Ether() / IP(src="10.0.3.5", dst="8.8.8.8", ttl=64) / TCP(sport=41000, dport=23, flags="S", window=1024)
    pcap_path = tmp_path / "public.pcap"
    wrpcap(str(pcap_path), [syn])
    with open(pcap_path, "rb") as f:
        client.post("/api/capture/pcap", files={"file": ("public.pcap", f, "application/vnd.tcpdump.pcap")})

    devices = client.get("/api/inventory/devices").json()
    assert {d["ip"] for d in devices} == {"10.0.3.5"}

    devices_incl_public = client.get("/api/inventory/devices?include_public=true").json()
    assert {d["ip"] for d in devices_incl_public} == {"10.0.3.5", "8.8.8.8"}

    flows = client.get("/api/inventory/flows").json()
    assert len(flows) == 1
    assert {flows[0]["device_a_ip"], flows[0]["device_b_ip"]} == {"10.0.3.5", "8.8.8.8"}

    scan_findings = client.post("/api/vuln/scan", json={"use_nvd": False}).json()
    public_device_id = next(d["id"] for d in devices_incl_public if d["ip"] == "8.8.8.8")
    assert any(f["device_id"] == public_device_id and "telnet" in f["title"].lower() for f in scan_findings)
