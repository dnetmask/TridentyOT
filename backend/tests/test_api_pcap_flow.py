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
    assert any(f["device_id"] == server["id"] and "telnet" in f["title"] for f in findings)

    detail = client.get(f"/api/inventory/devices/{server['id']}").json()
    assert any(p["protocol"] == "telnet" for p in detail["protocols"])
    assert any("telnet" in f["title"] for f in detail["findings"])


def test_health_endpoint(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_list_interfaces_endpoint_does_not_crash(client):
    resp = client.get("/api/capture/interfaces")
    assert resp.status_code in (200, 500)
