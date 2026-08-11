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


def test_patch_device_sets_and_clears_custom_model_and_firmware(client, tmp_path):
    syn = Ether() / IP(src="10.5.0.6", dst="10.5.0.61", ttl=64) / TCP(sport=41000, dport=502, flags="S", window=1024)
    pcap_path = tmp_path / "modbus2.pcap"
    wrpcap(str(pcap_path), [syn])
    with open(pcap_path, "rb") as f:
        client.post("/api/capture/pcap", files={"file": ("modbus2.pcap", f, "application/vnd.tcpdump.pcap")})

    devices = client.get("/api/inventory/devices").json()
    plc = next(d for d in devices if d["ip"] == "10.5.0.61")
    assert plc["display_model"] is None
    assert plc["display_firmware_version"] is None

    resp = client.patch(
        f"/api/inventory/devices/{plc['id']}", json={"custom_model": "1756-L83E", "custom_firmware_version": "33.011"}
    )
    assert resp.status_code == 200
    updated = resp.json()
    assert updated["display_model"] == "1756-L83E"
    assert updated["display_firmware_version"] == "33.011"

    resp = client.patch(
        f"/api/inventory/devices/{plc['id']}", json={"custom_model": None, "custom_firmware_version": None}
    )
    assert resp.status_code == 200
    cleared = resp.json()
    assert cleared["display_model"] is None
    assert cleared["display_firmware_version"] is None


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


def test_patch_device_sets_and_clears_custom_device_type_secondary(client, tmp_path):
    syn = Ether() / IP(src="10.5.0.8", dst="10.5.0.63", ttl=64) / TCP(sport=41000, dport=502, flags="S", window=1024)
    pcap_path = tmp_path / "modbus4.pcap"
    wrpcap(str(pcap_path), [syn])
    with open(pcap_path, "rb") as f:
        client.post("/api/capture/pcap", files={"file": ("modbus4.pcap", f, "application/vnd.tcpdump.pcap")})

    devices = client.get("/api/inventory/devices").json()
    device_id = next(d for d in devices if d["ip"] == "10.5.0.8")["id"]

    resp = client.patch(f"/api/inventory/devices/{device_id}", json={"custom_device_type_secondary": "switch_l2"})
    assert resp.status_code == 200
    updated = resp.json()
    assert updated["custom_device_type_secondary"] == "switch_l2"
    assert updated["display_device_type_secondary"] == "switch_l2"

    resp = client.patch(f"/api/inventory/devices/{device_id}", json={"custom_device_type_secondary": None})
    assert resp.status_code == 200
    assert resp.json()["custom_device_type_secondary"] is None


def test_patch_device_rejects_unknown_device_type_secondary(client, tmp_path):
    syn = Ether() / IP(src="10.5.0.9", dst="10.5.0.64", ttl=64) / TCP(sport=41000, dport=502, flags="S", window=1024)
    pcap_path = tmp_path / "modbus5.pcap"
    wrpcap(str(pcap_path), [syn])
    with open(pcap_path, "rb") as f:
        client.post("/api/capture/pcap", files={"file": ("modbus5.pcap", f, "application/vnd.tcpdump.pcap")})

    devices = client.get("/api/inventory/devices").json()
    device_id = next(d for d in devices if d["ip"] == "10.5.0.9")["id"]

    resp = client.patch(f"/api/inventory/devices/{device_id}", json={"custom_device_type_secondary": "hub"})
    assert resp.status_code == 422


def test_gateway_duplicates_shown_by_default_hidden_only_with_hide_external(client, tmp_path):
    """A router/NAT gateway forwarding replies from two different public
    IPs ends up as two inventory rows sharing one MAC (see
    apply_gateway_detection) -- one gets reclassified as network_device /
    router_nat. Same visibility rule as any other public IP (Device.is_external):
    shown by default, collapsed to the one representative row only when the
    caller opts in with hide_external=true. Still real rows either way,
    always visible in Flows."""
    gateway_mac = "aa:bb:cc:00:01:01"
    reply1 = Ether(src=gateway_mac) / IP(src="8.8.8.8", dst="10.6.1.5", ttl=64) / TCP(
        sport=443, dport=51000, flags="SA", window=8192
    )
    reply2 = Ether(src=gateway_mac) / IP(src="93.184.216.34", dst="10.6.1.5", ttl=64) / TCP(
        sport=443, dport=51001, flags="SA", window=8192
    )
    pcap_path = tmp_path / "gateway.pcap"
    wrpcap(str(pcap_path), [reply1, reply2])
    with open(pcap_path, "rb") as f:
        client.post("/api/capture/pcap", files={"file": ("gateway.pcap", f, "application/vnd.tcpdump.pcap")})

    # default (hide_external not set): both public-IP rows stay visible.
    devices = client.get("/api/inventory/devices").json()
    device_ips = {d["ip"] for d in devices}
    assert {"8.8.8.8", "93.184.216.34", "10.6.1.5"} <= device_ips

    primary = next(d for d in devices if d["display_device_type_secondary"] == "router_nat")
    assert primary["ip"] in ("8.8.8.8", "93.184.216.34")
    assert primary["display_device_type"] == "network_device"

    # hide_external=true: only the representative gateway row remains.
    devices_hidden = client.get("/api/inventory/devices", params={"hide_external": "true"}).json()
    device_ips_hidden = {d["ip"] for d in devices_hidden}
    assert "10.6.1.5" in device_ips_hidden
    assert len({"8.8.8.8", "93.184.216.34"} & device_ips_hidden) == 1

    flows = client.get("/api/inventory/flows").json()
    flow_ips = {f["device_a_ip"] for f in flows} | {f["device_b_ip"] for f in flows}
    assert {"8.8.8.8", "93.184.216.34", "10.6.1.5"} <= flow_ips


def test_gateway_hide_external_never_hides_a_private_ip_sharing_the_mac(client, tmp_path):
    """Regression test: a real host on a *different* private subnet, whose
    traffic happens to be routed through the same gateway (so it's also
    captured with the gateway's MAC as sender -- inter-VLAN routing, same
    mechanism as the public-IP forwarding pattern), must never be swept up
    as a "gateway duplicate" just because it shares that MAC. Only the
    public-IP duplicates are a forwarding artifact; a private IP is always
    a genuine, distinct local asset."""
    gateway_mac = "aa:bb:cc:00:02:02"
    reply1 = Ether(src=gateway_mac) / IP(src="8.8.8.8", dst="10.6.2.5", ttl=64) / TCP(
        sport=443, dport=51000, flags="SA", window=8192
    )
    reply2 = Ether(src=gateway_mac) / IP(src="93.184.216.34", dst="10.6.2.5", ttl=64) / TCP(
        sport=443, dport=51001, flags="SA", window=8192
    )
    # a real host on a different private subnet, reached via the same gateway
    routed_reply = Ether(src=gateway_mac) / IP(src="192.168.9.20", dst="10.6.2.5", ttl=63) / TCP(
        sport=445, dport=51002, flags="SA", window=8192
    )
    pcap_path = tmp_path / "gateway_routed.pcap"
    wrpcap(str(pcap_path), [reply1, reply2, routed_reply])
    with open(pcap_path, "rb") as f:
        client.post("/api/capture/pcap", files={"file": ("gateway_routed.pcap", f, "application/vnd.tcpdump.pcap")})

    devices = client.get("/api/inventory/devices", params={"hide_external": "true"}).json()
    device_ips = {d["ip"] for d in devices}
    assert "192.168.9.20" in device_ips
    assert "10.6.2.5" in device_ips


def test_health_endpoint(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_list_interfaces_endpoint_does_not_crash(client):
    resp = client.get("/api/capture/interfaces")
    assert resp.status_code in (200, 500)


def test_public_ip_device_flagged_external_but_shown_by_default_and_hidable_on_request(client, tmp_path):
    """Some LANs (mis)assign public IP ranges to real local gear, so a
    public-looking IP alone is no longer grounds to hide a device from
    Inventory -- it's shown by default, just flagged via is_external. That
    flag combines the IP-range hint with mac presence: 8.8.8.8 here is only
    ever a flow *destination*, so its mac is never learned (see
    inventory_service.get_or_create_device) and it comes out external,
    while the real LAN sender does not. hide_external opts back into the
    old exclude-from-Inventory behavior; Flows/Vulnerabilities are
    unaffected either way."""
    syn = Ether() / IP(src="10.0.3.5", dst="8.8.8.8", ttl=64) / TCP(sport=41000, dport=23, flags="S", window=1024)
    pcap_path = tmp_path / "public.pcap"
    wrpcap(str(pcap_path), [syn])
    with open(pcap_path, "rb") as f:
        client.post("/api/capture/pcap", files={"file": ("public.pcap", f, "application/vnd.tcpdump.pcap")})

    devices = client.get("/api/inventory/devices").json()
    assert {d["ip"] for d in devices} == {"10.0.3.5", "8.8.8.8"}
    lan_device = next(d for d in devices if d["ip"] == "10.0.3.5")
    public_device = next(d for d in devices if d["ip"] == "8.8.8.8")
    assert lan_device["is_external"] is False
    assert public_device["is_external"] is True

    hidden = client.get("/api/inventory/devices?hide_external=true").json()
    assert {d["ip"] for d in hidden} == {"10.0.3.5"}

    flows = client.get("/api/inventory/flows").json()
    assert len(flows) == 1
    assert {flows[0]["device_a_ip"], flows[0]["device_b_ip"]} == {"10.0.3.5", "8.8.8.8"}

    scan_findings = client.post("/api/vuln/scan", json={"use_nvd": False}).json()
    assert any(f["device_id"] == public_device["id"] and "telnet" in f["title"].lower() for f in scan_findings)


def test_wipe_database_clears_capture_data_but_keeps_users(client, tmp_path):
    syn = Ether() / IP(src="10.6.0.5", dst="10.6.0.60", ttl=64) / TCP(sport=41000, dport=502, flags="S", window=1024)
    pcap_path = tmp_path / "wipe.pcap"
    wrpcap(str(pcap_path), [syn])
    with open(pcap_path, "rb") as f:
        client.post("/api/capture/pcap", files={"file": ("wipe.pcap", f, "application/vnd.tcpdump.pcap")})

    client.post("/api/vuln/scan", json={"use_nvd": False})
    assert len(client.get("/api/inventory/devices").json()) == 2
    assert len(client.get("/api/capture/sessions").json()) == 1
    assert len(client.get("/api/vuln/findings").json()) >= 1

    resp = client.delete("/api/capture/wipe")
    assert resp.status_code == 200
    counts = resp.json()
    assert counts["devices"] == 2
    assert counts["sessions"] == 1
    assert counts["findings"] >= 1

    assert client.get("/api/inventory/devices").json() == []
    assert client.get("/api/inventory/flows").json() == []
    assert client.get("/api/vuln/findings").json() == []
    assert client.get("/api/capture/sessions").json() == []

    # users are never touched by a data wipe
    assert client.get("/api/auth/me").status_code == 200
    assert {u["username"] for u in client.get("/api/users").json()} == {"admin"}


def test_wipe_database_requires_admin_role(client, make_client):
    client.post("/api/users", json={"username": "viewer_wipe", "password": "secret1", "role": "viewer"})
    viewer = make_client("viewer_wipe", "secret1")
    assert viewer.delete("/api/capture/wipe").status_code == 403
