"""End-to-end coverage for asset identification sources beyond plain
TCP/IP traffic: CDP/LLDP self-announcements from switches (pure L2, no IP
layer) and NBNS/SMB NetBIOS self-announcements, all uploaded as a single
.pcap and verified through the real API surface."""

from scapy.contrib.cdp import CDPMsgDeviceID, CDPv2_HDR
from scapy.contrib.lldp import (
    LLDPDUChassisID,
    LLDPDUEndOfLLDPDU,
    LLDPDUPortID,
    LLDPDUSystemName,
    LLDPDUTimeToLive,
)
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import LLC, SNAP, Ether
from scapy.layers.netbios import NBNSHeader, NBNSRegistrationRequest
from scapy.utils import wrpcap


def test_pcap_with_cdp_lldp_and_nbns_identifies_all_assets(client, tmp_path):
    # A PLC talking Modbus, so there's an ordinary IP-based device too.
    modbus_syn = Ether() / IP(src="10.20.1.10", dst="10.20.2.30", ttl=64) / TCP(
        sport=41000, dport=502, flags="S", window=1024
    )

    # The same engineering workstation also broadcasts its own NetBIOS name.
    nbns_registration = (
        Ether()
        / IP(src="10.20.1.10", dst="10.20.1.255")
        / UDP(sport=137, dport=137)
        / NBNSHeader(OPCODE=0x5, NM_FLAGS=0x11)
        / NBNSRegistrationRequest(QUESTION_NAME="ENGWORKSTATION", SUFFIX="workstation", NB_ADDRESS="10.20.1.10")
    )

    # A switch that never sends any IP traffic on this segment, only CDP.
    cdp_announcement = (
        Ether(src="aa:bb:cc:00:11:22", dst="01:00:0c:cc:cc:cc")
        / LLC()
        / SNAP(OUI=0xC, code=0x2000)
        / CDPv2_HDR(msg=[CDPMsgDeviceID(val=b"core-switch-01.plant.local")])
    )

    # A second switch identified only via LLDP.
    lldp_announcement = (
        Ether(src="10:22:33:44:55:66", dst="01:80:c2:00:00:0e", type=0x88CC)
        / LLDPDUChassisID(subtype=4, id=b"\x10\x22\x33\x44\x55\x66")
        / LLDPDUPortID(subtype=1, id=b"Gi0/1")
        / LLDPDUTimeToLive(ttl=120)
        / LLDPDUSystemName(system_name=b"access-switch-02")
        / LLDPDUEndOfLLDPDU()
    )

    pcap_path = tmp_path / "discovery.pcap"
    wrpcap(str(pcap_path), [modbus_syn, nbns_registration, cdp_announcement, lldp_announcement])

    with open(pcap_path, "rb") as f:
        resp = client.post(
            "/api/capture/pcap",
            files={"file": ("discovery.pcap", f, "application/vnd.tcpdump.pcap")},
        )
    assert resp.status_code == 200
    session_after = client.get(f"/api/capture/sessions/{resp.json()['id']}").json()
    assert session_after["status"] == "completed"
    assert session_after["packet_count"] == 4

    devices = client.get("/api/inventory/devices").json()
    # workstation, PLC, broadcast destination (10.20.1.255), and the two
    # switches identified purely through CDP/LLDP.
    assert len(devices) == 5

    workstation = next(d for d in devices if d["ip"] == "10.20.1.10")
    assert workstation["hostname"] == "ENGWORKSTATION"
    assert workstation["display_name"] == "ENGWORKSTATION"

    core_switch = next(d for d in devices if d["mac"] == "aa:bb:cc:00:11:22")
    assert core_switch["ip"] is None
    assert core_switch["hostname"] == "core-switch-01.plant.local"
    assert core_switch["os_guess"] == "Network appliance (router/switch/firewall)"
    assert core_switch["os_confidence"] == 1.0

    access_switch = next(d for d in devices if d["mac"] == "10:22:33:44:55:66")
    assert access_switch["ip"] is None
    assert access_switch["hostname"] == "access-switch-02"
    assert access_switch["os_guess"] == "Network appliance (router/switch/firewall)"
