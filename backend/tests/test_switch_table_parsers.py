"""Tests for app/switch_table_parsers.py -- see that module's docstring for
why Cisco is tested against real, well-documented CLI output while Siemens
Scalance is explicitly best-effort.
"""

from app.switch_table_parsers import parse_switch_table

CISCO_MAC_TABLE = """
          Mac Address Table
-------------------------------------------

Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
   1    0011.2233.4455    DYNAMIC     Gi0/1
   1    0011.2233.4466    DYNAMIC     Gi0/2
   1    0011.2233.4477    DYNAMIC     Gi0/2
 All    ffff.ffff.ffff    STATIC      CPU
"""

CISCO_ARP = """
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  192.168.1.1             -   0011.2233.4400  ARPA   Vlan1
Internet  192.168.1.10           23   0011.2233.4455  ARPA   Vlan1
"""

CISCO_CDP_DETAIL = """-------------------------
Device ID: switch-core.example.com
Entry address(es):
  IP address: 192.168.1.1
Platform: cisco WS-C3560,  Capabilities: Switch IGMP
Interface: GigabitEthernet0/1,  Port ID (outgoing port): GigabitEthernet0/24
Holdtime : 154 sec

-------------------------
"""

CISCO_LLDP_DETAIL = """------------------------------------------------
Local Intf: Gi0/1
Chassis id: 0011.2233.4400
Port id: Gi0/24
Port Description: GigabitEthernet0/24
System Name: switch-core.example.com

Management Addresses:
    IP: 192.168.1.1

------------------------------------------------
"""

SCALANCE_MAC_TABLE = """MAC Address        VLAN  Port
-----------------  ----  ------
00-1B-1B-11-22-33   1    P0.1
00-1B-1B-11-22-44   1    P0.2
"""

SCALANCE_ARP = """IP Address       MAC Address         Interface
192.168.1.1      00-1B-1B-11-22-00    VLAN1
"""

SCALANCE_LLDP = """Local Port  Chassis ID          Port ID   System Name
P0.1        00-1B-1B-11-22-00   P0.24     scalance-core
"""


def test_cisco_mac_table_drops_cpu_row_and_normalizes_mac():
    entries = parse_switch_table("cisco", "mac_table", CISCO_MAC_TABLE)
    assert entries == [
        {"mac": "00:11:22:33:44:55", "interface_name": "Gi0/1", "vlan": "1"},
        {"mac": "00:11:22:33:44:66", "interface_name": "Gi0/2", "vlan": "1"},
        {"mac": "00:11:22:33:44:77", "interface_name": "Gi0/2", "vlan": "1"},
    ]


def test_cisco_arp_extracts_ip_mac_pairs():
    entries = parse_switch_table("cisco", "arp", CISCO_ARP)
    assert entries == [
        {"ip": "192.168.1.1", "mac": "00:11:22:33:44:00"},
        {"ip": "192.168.1.10", "mac": "00:11:22:33:44:55"},
    ]


def test_cisco_neighbors_parses_cdp_detail():
    entries = parse_switch_table("cisco", "neighbors", CISCO_CDP_DETAIL)
    assert entries == [
        {
            "protocol": "cdp",
            "local_port": "GigabitEthernet0/1",
            "remote_device_name": "switch-core.example.com",
            "remote_port": "GigabitEthernet0/24",
            "remote_mgmt_ip": "192.168.1.1",
            "remote_platform": "cisco WS-C3560",
        }
    ]


def test_cisco_neighbors_parses_lldp_detail():
    entries = parse_switch_table("cisco", "neighbors", CISCO_LLDP_DETAIL)
    assert entries == [
        {
            "protocol": "lldp",
            "local_port": "Gi0/1",
            "remote_device_name": "switch-core.example.com",
            "remote_port": "Gi0/24",
            "remote_mgmt_ip": "192.168.1.1",
            "remote_platform": None,
        }
    ]


def test_cisco_neighbors_returns_empty_for_unrecognized_text():
    assert parse_switch_table("cisco", "neighbors", "not a cdp or lldp dump") == []


def test_scalance_mac_table_best_effort():
    entries = parse_switch_table("siemens_scalance", "mac_table", SCALANCE_MAC_TABLE)
    assert entries == [
        {"mac": "00:1b:1b:11:22:33", "interface_name": "P0.1", "vlan": "1"},
        {"mac": "00:1b:1b:11:22:44", "interface_name": "P0.2", "vlan": "1"},
    ]


def test_scalance_mac_table_skips_unrecognized_line_instead_of_crashing():
    """Regression test: _MAC_RE.search() can find a MAC substring inside a
    whitespace-separated column that isn't itself a bare MAC (e.g. a
    "MAC-Address:"-style label glued to the value, common in real switch
    CLI dumps) -- that line has no column matched by _MAC_RE.fullmatch(),
    which used to make the mac_idx lookup raise StopIteration and crash the
    whole import with an opaque 500 instead of just skipping the one
    unrecognized line."""
    raw = "MAC-Address:00-1B-1B-11-22-33 VLAN:1 Port:P0.1\n00-1B-1B-11-22-44   1    P0.2"
    entries = parse_switch_table("siemens_scalance", "mac_table", raw)
    assert entries == [{"mac": "00:1b:1b:11:22:44", "interface_name": "P0.2", "vlan": "1"}]


def test_scalance_arp_best_effort():
    entries = parse_switch_table("siemens_scalance", "arp", SCALANCE_ARP)
    assert entries == [{"ip": "192.168.1.1", "mac": "00:1b:1b:11:22:00"}]


def test_scalance_neighbors_best_effort_skips_header_row():
    entries = parse_switch_table("siemens_scalance", "neighbors", SCALANCE_LLDP)
    assert entries == [
        {
            "protocol": "lldp",
            "local_port": "P0.1",
            "remote_device_name": "scalance-core",
            "remote_port": "P0.24",
            "remote_mgmt_ip": None,
            "remote_platform": None,
        }
    ]


def test_unknown_vendor_table_type_raises():
    import pytest

    with pytest.raises(ValueError):
        parse_switch_table("juniper", "mac_table", "irrelevant")
