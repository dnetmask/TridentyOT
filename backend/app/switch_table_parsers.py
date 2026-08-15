"""Parses raw text pasted/uploaded from a switch's CLI (or, for Scalance,
its web-export) into the plain dicts app/topology_from_switch.py's
apply_*() functions expect -- see SwitchMacTableEntry/SwitchArpEntry/
SwitchNeighborEntry in app/models.py for the exact fields each table_type
produces.

Cisco parsers are based on the real, well-documented IOS CLI output of
`show mac address-table`, `show arp`, `show cdp neighbors detail` and
`show lldp neighbors detail`. Siemens Scalance's mac_table/arp parsers are
still BEST-EFFORT (no verified real-device sample yet, only the commonly
documented CLI table shape for the X-200/X-300 CLI); its neighbors parser
(_parse_scalance_neighbors) IS calibrated against real output, both
`show lldp neighbors brief` and `show lldp neighbors detail`. Expect to
keep adjusting the best-effort ones
once someone pastes real Scalance output for them too -- that's exactly
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
        # The MAC found by _MAC_RE.search() above can span (or sit inside) a
        # whitespace-separated token without being an exact match for it --
        # e.g. a "MAC-Address:00-1B-1B-11-22-33" column glued to its label --
        # in which case no column fullmatch()es and this row can't be
        # positionally decoded. Skip it rather than crash the whole import
        # over one unrecognized line.
        mac_idx = next((i for i, c in enumerate(cols) if _MAC_RE.fullmatch(c)), None)
        if mac_idx is None:
            continue
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


_COLUMN_DASH_RE = re.compile(r"-{2,}")
_SEPARATOR_ROW_RE = re.compile(r"^[-\s]+$")


def _find_column_spans(lines: list[str]) -> tuple[int, list[tuple[int, int | None]]] | None:
    """Locates a "----   ----   ----" separator row (the kind under a
    fixed-width CLI table header) and returns its line index plus each
    column's (start, end-exclusive) character span, derived from where
    each run of dashes *starts* -- not from the header text above it,
    which is free to mix tabs and spaces inconsistently (real Scalance
    output does exactly that). Slicing later rows by these positions,
    instead of line.split(), is what survives a value that itself
    contains a space (e.g. a System Name of "OT18 SW01 SALA SERVIDORES",
    seen in real output)."""
    for i, line in enumerate(lines):
        if not _SEPARATOR_ROW_RE.match(line):
            continue
        starts = [m.start() for m in _COLUMN_DASH_RE.finditer(line)]
        if len(starts) < 2:
            continue
        spans = [(start, starts[j + 1] if j + 1 < len(starts) else None) for j, start in enumerate(starts)]
        return i, spans
    return None


def _slice_by_spans(line: str, spans: list[tuple[int, int | None]]) -> list[str]:
    return [(line[start:end] if end is not None else line[start:]).strip() for start, end in spans]


def _parse_scalance_neighbors_brief(lines: list[str]) -> list[dict]:
    """Calibrated against real Scalance CLI output ("show lldp neighbors
    brief"): a "System Name / Device ID / Local Intf" header, a dashed
    separator row, then one neighbor per line -- see _find_column_spans
    for why parsing anchors on the separator row instead of the header.
    Device ID is inconsistently a MAC or a truncated hostname in real
    output, with no reliable shape to key off, so it isn't mapped to any
    field; this "brief" table also has no remote-port column at all (only
    "show lldp neighbors detail", see _parse_scalance_neighbors_detail,
    carries one -- same detail-vs-brief distinction as Cisco's own two
    neighbor parsers)."""
    found = _find_column_spans(lines)
    if found is None:
        return []
    separator_idx, spans = found
    if len(spans) < 3:
        return []
    entries = []
    for line in lines[separator_idx + 1 :]:
        if not line.strip():
            continue
        system_name, _device_id, local_intf = _slice_by_spans(line, spans[:3])
        if not system_name or not local_intf:
            continue
        entries.append(
            {
                "protocol": "lldp",
                "local_port": local_intf,
                "remote_device_name": system_name,
                "remote_port": None,
                "remote_mgmt_ip": None,
                "remote_platform": None,
            }
        )
    return entries


_SCALANCE_DETAIL_MARKER_RE = re.compile(r"^\s*Local Intf\s*:", re.IGNORECASE)
_SCALANCE_DETAIL_FIELD_RE = re.compile(r"^\s*(?P<key>[A-Za-z ]+?)\s*:\s*(?P<value>.*?)\s*$")
_SCALANCE_DETAIL_SEPARATOR_RE = re.compile(r"^=+$")


def _parse_scalance_neighbors_detail(lines: list[str]) -> list[dict]:
    """Calibrated against real Scalance CLI output ("show lldp neighbors
    detail"): "===...===" separated blocks of "Label  : value" lines
    (Local Intf, System Name, Device ID, Hold-time, Capability, Port Id).
    Unlike "brief", this DOES carry the remote port (Port Id); still no
    management IP field at all, unlike Cisco's own detail output. A
    console pager's "--More--"/ANSI-garbled lines (seen in real captures,
    including one where the ANSI code swallows the separator itself) never
    match the field regex -- they're silently skipped, same as any other
    unrecognized line -- and the final block still gets flushed via the
    unconditional call after the loop even when its trailing separator
    line was garbled that way."""
    entries: list[dict] = []
    current: dict[str, str] = {}

    def _flush():
        local_intf = current.get("local intf")
        system_name = current.get("system name")
        if local_intf and system_name:
            entries.append(
                {
                    "protocol": "lldp",
                    "local_port": local_intf,
                    "remote_device_name": system_name,
                    "remote_port": current.get("port id"),
                    "remote_mgmt_ip": None,
                    "remote_platform": None,
                }
            )

    for line in lines:
        if _SCALANCE_DETAIL_SEPARATOR_RE.match(line.strip()):
            _flush()
            current = {}
            continue
        m = _SCALANCE_DETAIL_FIELD_RE.match(line)
        if not m:
            continue
        current[m.group("key").strip().lower()] = m.group("value").strip()
    _flush()
    return entries


def _parse_scalance_neighbors(raw_text: str) -> list[dict]:
    """Dispatches to whichever real Scalance neighbor shape this is --
    "show lldp neighbors detail" (per-neighbor blocks, checked first since
    it's unambiguous) or "...brief" (a single dashed-separator table) --
    same detail-vs-brief split as Cisco's own _parse_cisco_neighbors."""
    lines = _lines(raw_text)
    if any(_SCALANCE_DETAIL_MARKER_RE.match(line) for line in lines):
        return _parse_scalance_neighbors_detail(lines)
    return _parse_scalance_neighbors_brief(lines)


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
