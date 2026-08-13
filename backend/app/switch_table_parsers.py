"""Parses raw text pasted/uploaded from a switch's CLI (or, for Scalance,
its web-export) into the plain dicts app/topology_from_switch.py's
apply_*() functions expect -- see SwitchMacTableEntry/SwitchArpEntry/
SwitchNeighborEntry in app/models.py for the exact fields each table_type
produces.

Cisco parsers are based on the real, well-documented IOS CLI output of
`show mac address-table`, `show arp`, `show cdp neighbors detail` and
`show lldp neighbors detail`. Siemens Scalance parsers are BEST-EFFORT:
there's no verified real-device sample to calibrate against yet, only the
commonly documented CLI table shape for the X-200/X-300 CLI. Expect to
adjust these once someone pastes real Scalance output -- that's exactly
why every SwitchTableImport keeps raw_text, so a fixed parser can be
re-run against it without asking the user to paste it again.

Adding a new vendor is: write up to 3 functions (mac_table/arp/neighbors)
and register them in _PARSERS below -- nothing else changes.
"""

import re

_MAC_RE = re.compile(r"([0-9a-fA-F]{2}[:.\-]){5}[0-9a-fA-F]{2}|([0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}")


def _normalize_mac(raw: str) -> str:
    """Cisco writes MACs as "0011.2233.4455", Scalance commonly as
    "00-1B-1B-11-22-33" -- neither matches how this app stores MACs
    elsewhere (lowercase, colon-separated, e.g. "aa:bb:cc:dd:ee:ff",
    scapy's own default format), so every parser below normalizes through
    this before the entry ever reaches apply_*() -- otherwise a switch's
    own MAC table would never match a Device row for the same physical
    NIC."""
    hexdigits = re.sub(r"[^0-9a-fA-F]", "", raw).lower()
    return ":".join(hexdigits[i : i + 2] for i in range(0, len(hexdigits), 2))


def _lines(raw_text: str) -> list[str]:
    return [line.rstrip() for line in raw_text.splitlines()]


# ---------------------------------------------------------------------
# Cisco
# ---------------------------------------------------------------------

# "   1    0011.2233.4455    DYNAMIC     Gi0/1" -- vlan, mac, type, port(s).
# CPU/control-plane rows (a switch's own MACs on its own management/BPDU
# path, not a real downstream link) are dropped, same reasoning as never
# treating a switch's own address as if it were on some interface.
_CISCO_MAC_ROW_RE = re.compile(
    r"^\s*(?P<vlan>\S+)\s+(?P<mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+(?P<type>\S+)\s+(?P<port>\S+)\s*$"
)


def _parse_cisco_mac_table(raw_text: str) -> list[dict]:
    entries = []
    for line in _lines(raw_text):
        m = _CISCO_MAC_ROW_RE.match(line)
        if not m or m.group("port").upper() == "CPU":
            continue
        entries.append(
            {"mac": _normalize_mac(m.group("mac")), "interface_name": m.group("port"), "vlan": m.group("vlan")}
        )
    return entries


# "Internet  192.168.1.10           23   0011.2233.4455  ARPA   Vlan1"
_CISCO_ARP_ROW_RE = re.compile(
    r"^\s*Internet\s+(?P<ip>\S+)\s+\S+\s+(?P<mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+\S+\s+\S+\s*$"
)


def _parse_cisco_arp(raw_text: str) -> list[dict]:
    entries = []
    for line in _lines(raw_text):
        m = _CISCO_ARP_ROW_RE.match(line)
        if not m:
            continue
        entries.append({"ip": m.group("ip"), "mac": _normalize_mac(m.group("mac"))})
    return entries


def _parse_cisco_neighbors(raw_text: str) -> list[dict]:
    """Handles BOTH `show cdp neighbors detail` and `show lldp neighbors
    detail` -- the two block shapes are distinct enough ("Device ID:" vs
    "Local Intf:") to tell apart from the same paste box, so the frontend
    doesn't need a separate CDP-vs-LLDP choice for Cisco."""
    if "Device ID:" in raw_text:
        return _parse_cisco_cdp_detail(raw_text)
    if "Local Intf:" in raw_text:
        return _parse_cisco_lldp_detail(raw_text)
    return []


def _parse_cisco_cdp_detail(raw_text: str) -> list[dict]:
    entries = []
    for block in re.split(r"^-+\s*$", raw_text, flags=re.MULTILINE):
        device_id = re.search(r"Device ID:\s*(\S+)", block)
        if not device_id:
            continue
        ip = re.search(r"IP address:\s*(\S+)", block)
        iface = re.search(r"Interface:\s*([^,]+),\s*Port ID \(outgoing port\):\s*(\S+)", block)
        platform = re.search(r"Platform:\s*([^,]+),", block)
        entries.append(
            {
                "protocol": "cdp",
                "local_port": iface.group(1).strip() if iface else "",
                "remote_device_name": device_id.group(1),
                "remote_port": iface.group(2).strip() if iface else None,
                "remote_mgmt_ip": ip.group(1) if ip else None,
                "remote_platform": platform.group(1).strip() if platform else None,
            }
        )
    return [e for e in entries if e["local_port"]]


def _parse_cisco_lldp_detail(raw_text: str) -> list[dict]:
    entries = []
    for block in re.split(r"^-+\s*$", raw_text, flags=re.MULTILINE):
        local_intf = re.search(r"Local Intf:\s*(\S+)", block)
        if not local_intf:
            continue
        system_name = re.search(r"System Name:\s*(\S+)", block)
        chassis_id = re.search(r"Chassis id:\s*(\S+)", block)
        port_id = re.search(r"Port id:\s*(\S+)", block)
        mgmt_ip = re.search(r"IP:\s*(\S+)", block)
        entries.append(
            {
                "protocol": "lldp",
                "local_port": local_intf.group(1),
                # System Name isn't always advertised -- Chassis id is the
                # one field every LLDP neighbor always carries.
                "remote_device_name": (system_name.group(1) if system_name else None)
                or (chassis_id.group(1) if chassis_id else "unknown"),
                "remote_port": port_id.group(1) if port_id else None,
                "remote_mgmt_ip": mgmt_ip.group(1) if mgmt_ip else None,
                "remote_platform": None,
            }
        )
    return entries


# ---------------------------------------------------------------------
# Siemens Scalance -- BEST EFFORT, see module docstring.
# ---------------------------------------------------------------------


def _parse_scalance_mac_table(raw_text: str) -> list[dict]:
    """Expected shape (Scalance X-200/X-300 CLI, dash-separated MACs,
    module.port naming e.g. "P0.1"):
        MAC Address        VLAN  Port
        00-1B-1B-11-22-33   1    P0.1
    Tolerant of extra/missing columns: any line containing a MAC-looking
    token is treated as a data row, split on whitespace, with the MAC's
    own position used to locate the rest -- real header/separator lines
    never contain something that looks like a MAC address."""
    entries = []
    for line in _lines(raw_text):
        mac_match = _MAC_RE.search(line)
        if not mac_match:
            continue
        cols = line.split()
        mac_idx = next(i for i, c in enumerate(cols) if _MAC_RE.fullmatch(c))
        vlan = cols[mac_idx + 1] if mac_idx + 1 < len(cols) else None
        port = cols[mac_idx + 2] if mac_idx + 2 < len(cols) else (cols[mac_idx - 1] if mac_idx > 0 else None)
        if not port:
            continue
        entries.append({"mac": _normalize_mac(mac_match.group()), "interface_name": port, "vlan": vlan})
    return entries


def _parse_scalance_arp(raw_text: str) -> list[dict]:
    """Expected shape: "IP Address   MAC Address   Interface", one entry
    per line with an IP followed by a MAC token -- see
    _parse_scalance_mac_table's docstring for the same tolerant approach."""
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    entries = []
    for line in _lines(raw_text):
        mac_match = _MAC_RE.search(line)
        ip_match = ip_re.search(line)
        if not mac_match or not ip_match:
            continue
        entries.append({"ip": ip_match.group(), "mac": _normalize_mac(mac_match.group())})
    return entries


def _parse_scalance_neighbors(raw_text: str) -> list[dict]:
    """Scalance switches speak LLDP, not CDP (that's a Cisco-proprietary
    protocol) -- every entry from this parser is protocol="lldp". Expected
    shape: "Local Port  Chassis ID  Port ID  System Name", one neighbor per
    line."""
    entries = []
    for line in _lines(raw_text):
        mac_match = _MAC_RE.search(line)
        cols = line.split()
        # Every real data row has a Chassis ID (a MAC) -- a header/separator
        # line never does, which is what tells the two apart here.
        if not cols or not mac_match:
            continue
        local_port = cols[0]
        # Best-effort positional guess: chassis id (a MAC), then port id,
        # then whatever's left is the system name -- real device output
        # will need this recalibrated once seen.
        after_chassis = line[mac_match.end() :].split()
        remote_port = after_chassis[0] if after_chassis else None
        remote_device_name = " ".join(after_chassis[1:]) or None
        if not remote_device_name:
            continue
        entries.append(
            {
                "protocol": "lldp",
                "local_port": local_port,
                "remote_device_name": remote_device_name,
                "remote_port": remote_port,
                "remote_mgmt_ip": None,
                "remote_platform": None,
            }
        )
    return entries


_PARSERS = {
    ("cisco", "mac_table"): _parse_cisco_mac_table,
    ("cisco", "arp"): _parse_cisco_arp,
    ("cisco", "neighbors"): _parse_cisco_neighbors,
    ("siemens_scalance", "mac_table"): _parse_scalance_mac_table,
    ("siemens_scalance", "arp"): _parse_scalance_arp,
    ("siemens_scalance", "neighbors"): _parse_scalance_neighbors,
}


def parse_switch_table(vendor: str, table_type: str, raw_text: str) -> list[dict]:
    parser = _PARSERS.get((vendor, table_type))
    if parser is None:
        raise ValueError(f"No parser for vendor={vendor!r} table_type={table_type!r}")
    return parser(raw_text)
