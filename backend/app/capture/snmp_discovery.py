"""Active discovery via a light SNMP sweep -- GETs a handful of well-known
MIB-II OIDs (sysDescr, sysObjectID, sysName) from every host in a target
range over UDP/161, using scapy's own SNMP/ASN.1 layer (scapy>=2.6 is
already a dependency for the rest of this app) rather than adding a
separate SNMP library or shelling out to net-snmp's snmpget/snmpwalk
binaries the way nmap_discovery.py shells out to the real `nmap` binary.

Only SNMPv1/v2c (community-string auth) is supported -- SNMPv3's
user-based security model needs a real engine/session handshake that
scapy's SNMP layer doesn't implement, and building that here would go
well past "light discovery", the same reasoning nmap_discovery.py gives
for leaving out NSE scripts.

Same no-fixed-duration/live-progress/stop UX as nmap_discovery.py:
SnmpScanManager (mirrors NmapScanManager) runs a background thread that
sweeps the target range in chunks -- scapy's sr() sends a whole chunk at
once and waits out one shared timeout window, rather than one blocking
round trip per host, since SNMP has no per-host progress signal to parse
the way nmap's own verbose stdout output has. Progress here is simply "how
many of the target's addresses have had a chunk sent and timed out for".
CaptureSession.bytes_processed/total_bytes/packet_count update after every
chunk, and POST /api/discovery/snmp/stop/{id} stops the sweep before its
next chunk starts (there's no live subprocess here to terminate the way
nmap has, so -- like nmap's own stop -- this is best-effort and can take
up to one chunk's timeout to actually take effect).

Most addresses in a sweep won't answer at all -- SNMP is opt-in and often
disabled by default on a given device -- so a mostly-silent /24 is the
expected outcome, not a failure.

Feeds each responding host through the same Device/DeviceProtocol
machinery every other capture source uses (get_or_create_device/
upsert_protocol/apply_os_guess/apply_hostname_hints/apply_identity_hints/
apply_device_type_guess), same as nmap_discovery.py's own _ingest_nmap_host.

_SnmpWalkWorker (bottom of this module) is a second, unrelated feature that
happens to share this file for the SNMP plumbing: unlike the sweep above
(one GET per host, hundreds of hosts), it walks a handful of *tables* --
BRIDGE-MIB's MAC-address-to-port table, IP-MIB's ARP table, LLDP-MIB's
neighbor table -- on a short, explicit list of switches, and turns the
result into real topology data via app/topology_from_switch.py. See that
module and app/models.py's SwitchTableImport for why: a switch's own
tables are real evidence of physical wiring, unlike Flow. CDP (Cisco's own
proprietary neighbor protocol) is deliberately NOT walked via SNMP here --
CDP-MIB's cache-table address encoding needs more calibration against a
real device than there's been a chance to do; a Cisco switch's CDP
neighbors still come in fine through the manual `show cdp neighbors
detail` paste (app/switch_table_parsers.py) instead.
"""

import datetime
import ipaddress
import json
import threading
from typing import Any

from scapy.asn1.asn1 import ASN1_NULL, ASN1_OID
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.snmp import SNMP, SNMPget, SNMPnext, SNMPresponse, SNMPvarbind
from scapy.sendrecv import sr
from sqlalchemy.orm import Session

from app.db import session_scope
from app.fingerprint.identity_detect import IdentityHint
from app.fingerprint.os_fingerprint import OsGuess
from app.fingerprint.protocol_detect import classify
from app.i18n import bilingual, encode_i18n
from app.inventory.inventory_service import (
    IngestCache,
    apply_device_type_guess,
    apply_flow_link_candidates,
    apply_gateway_detection,
    apply_hostname_hints,
    apply_identity_hints,
    apply_os_guess,
    apply_segment_classification,
    get_or_create_device,
    upsert_protocol,
)
from app.models import (
    Device,
    SwitchArpEntry,
    SwitchMacTableEntry,
    SwitchNeighborEntry,
    SwitchTableImport,
)
from app.models import CaptureSession
from app.topology_from_switch import apply_arp_table, apply_mac_table, apply_neighbor_table

_SNMP_PORT = 161

# MIB-II OIDs this "light" sweep asks for -- a single GET request per host,
# never a walk: sysDescr (free-text self-description), sysObjectID
# (numeric, registry-assigned enterprise OID -- see the "never guess a
# vendor name from a numeric id" rule identity_detect.py already applies
# to CIP's and BACnet's own vendorId, same reasoning here), and sysName (a
# self-reported hostname).
_OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
_OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
_OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
_OIDS = [_OID_SYS_DESCR, _OID_SYS_OBJECT_ID, _OID_SYS_NAME]

# How many addresses to probe in one sr() call -- a whole chunk shares one
# timeout window, so this bounds both how long a single round can block
# for (see _PER_CHUNK_TIMEOUT_SECONDS) and how often progress updates and
# a pending .stop() are actually checked.
_CHUNK_SIZE = 256
_PER_CHUNK_TIMEOUT_SECONDS = 2.0

# A sanity ceiling on top of whatever ipaddress.ip_network expands to --
# not a "light scan" duration limit (this scan has none, same as nmap's),
# just a guard against something like a /8 turning into tens of millions
# of in-memory IP strings.
_MAX_TARGETS = 65536


def expand_targets(target: str) -> list[str]:
    """A single host or a CIDR network, same target syntax as nmap's own
    (see nmap_discovery.py's _estimate_target_count) -- but unlike that
    one, this actually needs the full address list, not just a count, so
    there's no comma-list/hostname fallback here: an invalid target simply
    raises ValueError, which routes_discovery.py turns into a 400 before
    ever creating a CaptureSession for it."""
    network = ipaddress.ip_network(target, strict=False)
    addresses = (
        [str(network.network_address)] if network.num_addresses == 1 else [str(addr) for addr in network.hosts()]
    )
    if len(addresses) > _MAX_TARGETS:
        raise ValueError(f"target expands to {len(addresses)} addresses, over the {_MAX_TARGETS} limit")
    return addresses


def _decode_value(value: Any) -> str | None:
    if value is None or isinstance(value, ASN1_NULL):
        return None
    raw = getattr(value, "val", value)
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="ignore")
    text = str(raw).strip()
    return text or None


def _build_request(ip: str, sport: int, community: str, version: str) -> "IP":
    varbinds = [SNMPvarbind(oid=ASN1_OID(oid)) for oid in _OIDS]
    return (
        IP(dst=ip)
        / UDP(sport=sport, dport=_SNMP_PORT)
        / SNMP(version=version, community=community, PDU=SNMPget(varbindlist=varbinds))
    )


def _parse_response(sent: Any, received: Any) -> dict[str, Any] | None:
    """None means "not a real SNMP reply" -- a closed UDP/161 port on the
    target commonly earns an ICMP port-unreachable instead of silence
    (this is *especially* true scanning loopback addresses, which is why
    the test suite exercises this path directly), and scapy's sr() treats
    that ICMP error as a matched "answer" to the original packet. The
    ICMP payload actually carries the *original request* right back (an
    SNMPget, not an SNMPresponse) -- haslayer(SNMP) alone is True for it
    too, so the PDU's own type, not just its presence, is what actually
    tells a real reply apart from our own echoed-back request. Without
    this check, every closed-but-reachable host on the sweep would get
    inventoried as a live SNMP responder off the back of an error message
    that says the exact opposite."""
    if not received.haslayer(SNMP) or not isinstance(received[SNMP].PDU, SNMPresponse):
        return None
    values: dict[str, str | None] = dict.fromkeys(_OIDS)
    for varbind in received[SNMP].PDU.varbindlist:
        oid = varbind.oid.val
        if oid in values:
            values[oid] = _decode_value(varbind.value)
    return {
        "ip": sent[IP].dst,
        # Only present when the reply was captured with its Ethernet
        # framing intact -- on some interfaces/socket types (loopback,
        # certain L3 raw sockets) it isn't, in which case this is None
        # rather than a guess (same "MAC only from a real sender frame"
        # rule the rest of this app follows).
        "mac": received[Ether].src if received.haslayer(Ether) else None,
        "sys_descr": values[_OID_SYS_DESCR],
        "sys_object_id": values[_OID_SYS_OBJECT_ID],
        "sys_name": values[_OID_SYS_NAME],
    }


def _ingest_snmp_host(
    session: Session, host: dict[str, Any], organization_id: int, capture_session_id: int, cache: IngestCache
) -> None:
    device = get_or_create_device(
        session, ip=host["ip"], mac=host["mac"], organization_id=organization_id,
        capture_session_id=capture_session_id, cache=cache,
    )
    if device is None:
        return

    proto_info = classify(_SNMP_PORT)
    upsert_protocol(
        session, device, proto_info, _SNMP_PORT, "udp", "server",
        banner=host["sys_descr"], capture_session_id=capture_session_id, cache=cache,
    )

    if host["sys_descr"]:
        # Self-reported, but free text rather than a fixed enum (unlike
        # CDP/LLDP's _CDP_LLDP_GUESS, which gets 1.0) -- confident enough
        # to beat a passive TCP-fingerprint guess, not so confident that a
        # future, more specific signal could never outrank it.
        apply_os_guess(
            device,
            OsGuess(
                os_family="snmp",
                label=host["sys_descr"][:200],
                confidence=0.7,
                signature_name="snmp:sysDescr",
                initial_ttl_guess=0,
                hop_estimate=0,
            ),
        )

    if host["ip"] and host["sys_name"]:
        apply_hostname_hints(session, [(host["ip"], host["sys_name"])], organization_id)

    if host["sys_object_id"]:
        # A numeric, registry-assigned enterprise OID -- never translated
        # into a vendor/model name (see the module docstring), only kept
        # as evidence text for a human to look up, and only when nothing
        # else has already filled device_type_evidence in.
        apply_identity_hints(
            session,
            device,
            [
                IdentityHint(
                    evidence=encode_i18n(
                        bilingual(
                            es=f'SNMP sysObjectID: "{host["sys_object_id"]}"',
                            en=f'SNMP sysObjectID: "{host["sys_object_id"]}"',
                        )
                    )
                )
            ],
        )

    apply_device_type_guess(session, device)


class _SnmpScanWorker:
    def __init__(
        self, capture_session_id: int, targets: list[str], community: str, version: str, interface: str | None
    ) -> None:
        self.capture_session_id = capture_session_id
        self.targets = targets
        self.community = community
        self.version = version
        self.interface = interface
        self._stop_requested = False
        self._thread = threading.Thread(
            target=self._run, name=f"snmp-scan-{capture_session_id}", daemon=True
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop_requested = True

    def _run(self) -> None:
        with session_scope() as db:
            capture_session = db.get(CaptureSession, self.capture_session_id)
            if capture_session is None:
                return
            capture_session.total_bytes = len(self.targets)
            db.commit()

        scanned_so_far = 0
        hosts_found: dict[str, dict[str, Any]] = {}
        sr_kwargs: dict[str, Any] = {"timeout": _PER_CHUNK_TIMEOUT_SECONDS, "verbose": 0}
        if self.interface:
            sr_kwargs["iface"] = self.interface

        try:
            for chunk_start in range(0, len(self.targets), _CHUNK_SIZE):
                if self._stop_requested:
                    self._finish("stopped", hosts_found)
                    return
                chunk = self.targets[chunk_start : chunk_start + _CHUNK_SIZE]
                packets = [
                    _build_request(ip, 40000 + i, self.community, self.version) for i, ip in enumerate(chunk)
                ]
                answered, _unanswered = sr(packets, **sr_kwargs)
                for sent, received in answered:
                    host = _parse_response(sent, received)
                    if host is not None:
                        hosts_found[host["ip"]] = host
                scanned_so_far += len(chunk)
                self._commit_progress(scanned_so_far, hosts_found)
        except Exception as exc:
            self._finish("error", hosts_found, str(exc))
            return

        self._finish("completed", hosts_found)

    def _commit_progress(self, scanned_so_far: int, hosts_found: dict[str, dict[str, Any]]) -> None:
        with session_scope() as db:
            capture_session = db.get(CaptureSession, self.capture_session_id)
            if capture_session is None or capture_session.status != "running":
                return
            capture_session.bytes_processed = min(scanned_so_far, len(self.targets))
            if hosts_found:
                cache = IngestCache()
                for host in hosts_found.values():
                    _ingest_snmp_host(db, host, capture_session.organization_id, capture_session.id, cache)
                apply_gateway_detection(db, capture_session.organization_id)
                apply_segment_classification(db, capture_session.organization_id)
                apply_flow_link_candidates(db, capture_session.organization_id)
                capture_session.packet_count = len(hosts_found)
            db.commit()

    def _finish(self, status: str, hosts_found: dict[str, dict[str, Any]], error_message: str | None = None) -> None:
        with session_scope() as db:
            capture_session = db.get(CaptureSession, self.capture_session_id)
            if capture_session is None:
                return
            try:
                if hosts_found:
                    cache = IngestCache()
                    for host in hosts_found.values():
                        _ingest_snmp_host(db, host, capture_session.organization_id, capture_session.id, cache)
                    apply_gateway_detection(db, capture_session.organization_id)
                    apply_segment_classification(db, capture_session.organization_id)
                    apply_flow_link_candidates(db, capture_session.organization_id)
                    capture_session.packet_count = len(hosts_found)
                if status == "completed":
                    capture_session.bytes_processed = capture_session.total_bytes
                capture_session.status = status
                if error_message:
                    capture_session.error_message = error_message
            except Exception as exc:
                db.rollback()
                capture_session.status = "error"
                capture_session.error_message = str(exc)
            finally:
                capture_session.ended_at = datetime.datetime.now(datetime.timezone.utc)
                db.commit()


class SnmpScanManager:
    def __init__(self) -> None:
        self._workers: dict[int, _SnmpScanWorker] = {}
        self._lock = threading.Lock()

    def start(
        self,
        capture_session_id: int,
        targets: list[str],
        community: str,
        version: str,
        interface: str | None = None,
    ) -> None:
        worker = _SnmpScanWorker(capture_session_id, targets, community, version, interface)
        with self._lock:
            self._workers[capture_session_id] = worker
        worker.start()

    def stop(self, capture_session_id: int) -> bool:
        with self._lock:
            worker = self._workers.pop(capture_session_id, None)
        if worker is None:
            return False
        worker.stop()
        return True

    def stop_all(self) -> None:
        with self._lock:
            session_ids = list(self._workers.keys())
        for session_id in session_ids:
            self.stop(session_id)


snmp_scan_manager = SnmpScanManager()


# ---------------------------------------------------------------------
# Table walks -- see the module docstring's second half for what these
# are for and why CDP isn't among them.
# ---------------------------------------------------------------------

# BRIDGE-MIB: dot1dTpFdbPort is indexed BY the learned MAC address itself
# -- the 6 OID sub-identifiers after this base ARE the MAC, one byte each
# (see _mac_from_bytes) -- and its value is the bridge port number the
# switch learned that MAC on. dot1dBasePortIfIndex then maps that bridge
# port number to a real ifIndex, and ifDescr turns the ifIndex into a name
# a human recognizes (e.g. "GigabitEthernet0/3"): three walks, joined
# locally, because no single one of them hands back a readable name.
_OID_DOT1D_TP_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
_OID_DOT1D_BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
_OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"

# IP-MIB: ipNetToMediaPhysAddress is indexed by (ifIndex, 4 IP octets) --
# the remote IP is embedded in the OID index the same way the MAC is for
# the BRIDGE-MIB table above, so this alone gives a full (ip, mac) pair
# with no second walk needed.
_OID_IP_NET_TO_MEDIA_PHYS_ADDRESS = "1.3.6.1.2.1.4.22.1.2"

# LLDP-MIB (IEEE 802.1AB, not Cisco-specific -- covers both Cisco and
# Siemens Scalance as long as LLDP is enabled). lldpRemTable is indexed by
# (timeMark, localPortNum, remIndex); lldpLocPortDesc separately maps
# localPortNum to a readable local port name, the same "walk the index
# table, walk the name table, join locally" shape as BRIDGE-MIB above.
_OID_LLDP_REM_CHASSIS_ID = "1.0.8802.1.1.2.1.4.1.1.5"
_OID_LLDP_REM_PORT_ID = "1.0.8802.1.1.2.1.4.1.1.7"
_OID_LLDP_REM_SYS_NAME = "1.0.8802.1.1.2.1.4.1.1.9"
_OID_LLDP_LOC_PORT_DESC = "1.0.8802.1.1.2.1.3.7.1.4"

# A walk is one round trip per row -- a runaway/misbehaving agent that
# keeps answering with an ever-increasing OID inside the same subtree
# could otherwise loop forever; no real MIB table this app walks should
# ever come close to this many rows.
_MAX_WALK_ROWS = 4000

# Distinct from SwitchTableImport.vendor's "cisco"/"siemens_scalance" --
# those describe a *manually pasted CLI's* dialect (see
# app/switch_table_parsers.py), which a live SNMP walk has no concept of:
# the wire protocol is the same regardless of who made the switch.
_VENDOR_UNKNOWN = "unknown"


def _oid_suffix(oid: str, base_oid: str) -> list[int]:
    return [int(x) for x in oid[len(base_oid) + 1 :].split(".")]


def _mac_from_bytes(raw: Any) -> str | None:
    if not isinstance(raw, bytes) or len(raw) != 6:
        return None
    return ":".join(f"{b:02x}" for b in raw)


def _snmp_walk_subtree(
    ip: str, sport: int, community: str, version: str, base_oid: str, timeout: float | None = None
) -> list[tuple[str, Any]]:
    """GETNEXT, one row at a time -- scapy has no bulkwalk helper (see the
    sweep's own _build_request above), and GETNEXT works identically on
    v1/v2c, unlike GETBULK, which v1 doesn't support at all. Stops on the
    first non-answer, non-response, or an OID that's walked off
    `base_oid`'s own subtree (endOfMibView/noSuchObject both decode as
    ASN1_NULL, same as the plain GET path's own _decode_value).

    timeout resolves _PER_CHUNK_TIMEOUT_SECONDS at call time rather than
    as a bound default argument, same reason _run()'s own sr_kwargs does --
    a test monkeypatching that module constant (to make a "nobody answers"
    subtree fail fast) needs the lookup to happen now, not once at import
    time."""
    if timeout is None:
        timeout = _PER_CHUNK_TIMEOUT_SECONDS
    rows: list[tuple[str, Any]] = []
    current = base_oid
    for _ in range(_MAX_WALK_ROWS):
        packet = (
            IP(dst=ip)
            / UDP(sport=sport, dport=_SNMP_PORT)
            / SNMP(
                version=version, community=community, PDU=SNMPnext(varbindlist=[SNMPvarbind(oid=ASN1_OID(current))])
            )
        )
        answered, _unanswered = sr([packet], timeout=timeout, verbose=0)
        if not answered:
            break
        _sent, received = answered[0]
        if not received.haslayer(SNMP) or not isinstance(received[SNMP].PDU, SNMPresponse):
            break
        varbind = received[SNMP].PDU.varbindlist[0]
        oid = varbind.oid.val
        if oid == current or not (oid == base_oid or oid.startswith(base_oid + ".")):
            break  # off the subtree, or the agent isn't actually advancing
        value = varbind.value
        if not isinstance(value, ASN1_NULL):
            rows.append((oid, getattr(value, "val", value)))
        current = oid
    return rows


def walk_mac_table(ip: str, sport: int, community: str, version: str) -> list[dict]:
    fdb_rows = _snmp_walk_subtree(ip, sport, community, version, _OID_DOT1D_TP_FDB_PORT)
    macs_by_bridge_port: dict[int, list[str]] = {}
    for oid, value in fdb_rows:
        suffix = _oid_suffix(oid, _OID_DOT1D_TP_FDB_PORT)
        mac = _mac_from_bytes(bytes(suffix)) if len(suffix) == 6 else None
        try:
            bridge_port = int(value)
        except (TypeError, ValueError):
            bridge_port = 0
        if mac and bridge_port:
            macs_by_bridge_port.setdefault(bridge_port, []).append(mac)

    ifindex_by_bridge_port: dict[int, int] = {}
    for oid, value in _snmp_walk_subtree(ip, sport, community, version, _OID_DOT1D_BASE_PORT_IFINDEX):
        suffix = _oid_suffix(oid, _OID_DOT1D_BASE_PORT_IFINDEX)
        if len(suffix) == 1:
            try:
                ifindex_by_bridge_port[suffix[0]] = int(value)
            except (TypeError, ValueError):
                pass

    name_by_ifindex: dict[int, str] = {}
    for oid, value in _snmp_walk_subtree(ip, sport, community, version, _OID_IF_DESCR):
        suffix = _oid_suffix(oid, _OID_IF_DESCR)
        if len(suffix) == 1 and isinstance(value, bytes):
            name_by_ifindex[suffix[0]] = value.decode("utf-8", errors="ignore")

    entries = []
    for bridge_port, macs in macs_by_bridge_port.items():
        ifindex = ifindex_by_bridge_port.get(bridge_port)
        interface_name = name_by_ifindex.get(ifindex) if ifindex is not None else None
        for mac in macs:
            entries.append({"mac": mac, "interface_name": interface_name or f"port{bridge_port}", "vlan": None})
    return entries


def walk_arp_table(ip: str, sport: int, community: str, version: str) -> list[dict]:
    entries = []
    for oid, value in _snmp_walk_subtree(ip, sport, community, version, _OID_IP_NET_TO_MEDIA_PHYS_ADDRESS):
        suffix = _oid_suffix(oid, _OID_IP_NET_TO_MEDIA_PHYS_ADDRESS)
        mac = _mac_from_bytes(value)
        if len(suffix) != 5 or mac is None:
            continue
        entries.append({"ip": ".".join(str(x) for x in suffix[1:]), "mac": mac})
    return entries


def walk_neighbor_table(ip: str, sport: int, community: str, version: str) -> list[dict]:
    """LLDP only -- see the module docstring for why CDP-MIB isn't walked
    here (Cisco switches still come in via the manual paste instead)."""

    def _walk_column(base_oid: str) -> dict[tuple[int, ...], Any]:
        return {
            tuple(_oid_suffix(oid, base_oid)): value
            for oid, value in _snmp_walk_subtree(ip, sport, community, version, base_oid)
        }

    chassis_by_index = _walk_column(_OID_LLDP_REM_CHASSIS_ID)
    port_id_by_index = _walk_column(_OID_LLDP_REM_PORT_ID)
    sys_name_by_index = _walk_column(_OID_LLDP_REM_SYS_NAME)
    local_port_desc = {
        suffix[0]: (value.decode("utf-8", errors="ignore") if isinstance(value, bytes) else str(value))
        for suffix, value in _walk_column(_OID_LLDP_LOC_PORT_DESC).items()
        if len(suffix) == 1
    }

    entries = []
    for index in set(chassis_by_index) | set(port_id_by_index) | set(sys_name_by_index):
        if len(index) != 3:
            continue
        _time_mark, local_port_num, _rem_index = index
        sys_name = sys_name_by_index.get(index)
        chassis_id = chassis_by_index.get(index)
        port_id = port_id_by_index.get(index)

        remote_name = None
        if isinstance(sys_name, bytes) and sys_name:
            remote_name = sys_name.decode("utf-8", errors="ignore")
        elif isinstance(chassis_id, bytes) and chassis_id:
            remote_name = _mac_from_bytes(chassis_id) or chassis_id.hex()
        if not remote_name:
            continue

        entries.append(
            {
                "protocol": "lldp",
                "local_port": local_port_desc.get(local_port_num, f"port{local_port_num}"),
                "remote_device_name": remote_name,
                "remote_port": port_id.decode("utf-8", errors="ignore") if isinstance(port_id, bytes) else None,
                "remote_mgmt_ip": None,
                "remote_platform": None,
            }
        )
    return entries


def _resolve_switch_device(db: Session, organization_id: int, ip: str) -> Device:
    """The walk targets an IP directly (SnmpSwitchWalkRequest.targets),
    which may or may not already be a known Device -- if it isn't yet
    (e.g. a switch nobody's captured anything from before), one is
    created here with no capture_session_id, same pattern
    POST /api/inventory/devices uses for a manually-registered switch."""
    device = db.query(Device).filter(Device.organization_id == organization_id, Device.ip == ip).one_or_none()
    if device is not None:
        return device
    device = Device(organization_id=organization_id, ip=ip, custom_device_type="network_device")
    db.add(device)
    db.flush()
    return device


def _apply_walked_table(db: Session, switch: Device, table_type: str, rows: list[dict]) -> None:
    if not rows:
        return
    table_import = SwitchTableImport(
        organization_id=switch.organization_id,
        device_id=switch.id,
        table_type=table_type,
        source="snmp",
        vendor=_VENDOR_UNKNOWN,
    )
    db.add(table_import)
    db.flush()

    if table_type == "mac_table":
        entries = [SwitchMacTableEntry(switch_table_import_id=table_import.id, **row) for row in rows]
        db.add_all(entries)
        db.flush()
        result = apply_mac_table(db, switch, entries)
    elif table_type == "arp":
        entries = [SwitchArpEntry(switch_table_import_id=table_import.id, **row) for row in rows]
        db.add_all(entries)
        db.flush()
        result = apply_arp_table(db, switch.organization_id, entries)
    else:  # "neighbors"
        entries = [SwitchNeighborEntry(switch_table_import_id=table_import.id, **row) for row in rows]
        db.add_all(entries)
        db.flush()
        result = apply_neighbor_table(db, switch, entries)

    table_import.entries_parsed = len(rows)
    table_import.result_summary = json.dumps(result)


class _SnmpWalkWorker:
    """Unlike _SnmpScanWorker's "many hosts, one short exchange each", a
    table walk is "few hosts, many exchanges each" -- so this iterates
    targets one at a time (no chunking) and commits/reports progress after
    every switch finishes, not after every packet."""

    def __init__(self, capture_session_id: int, targets: list[str], community: str, version: str) -> None:
        self.capture_session_id = capture_session_id
        self.targets = targets
        self.community = community
        self.version = version
        self._stop_requested = False
        self._thread = threading.Thread(target=self._run, name=f"snmp-walk-{capture_session_id}", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop_requested = True

    def _run(self) -> None:
        with session_scope() as db:
            capture_session = db.get(CaptureSession, self.capture_session_id)
            if capture_session is None:
                return
            capture_session.total_bytes = len(self.targets)
            db.commit()

        switches_walked = 0
        try:
            for i, target_ip in enumerate(self.targets):
                if self._stop_requested:
                    self._finish("stopped", switches_walked)
                    return
                self._walk_one_switch(target_ip, 41000 + i)
                switches_walked += 1
                self._commit_progress(switches_walked)
        except Exception as exc:
            self._finish("error", switches_walked, str(exc))
            return

        self._finish("completed", switches_walked)

    def _walk_one_switch(self, ip: str, sport: int) -> None:
        with session_scope() as db:
            capture_session = db.get(CaptureSession, self.capture_session_id)
            if capture_session is None or capture_session.status != "running":
                return
            switch = _resolve_switch_device(db, capture_session.organization_id, ip)
            _apply_walked_table(db, switch, "mac_table", walk_mac_table(ip, sport, self.community, self.version))
            _apply_walked_table(db, switch, "arp", walk_arp_table(ip, sport, self.community, self.version))
            _apply_walked_table(
                db, switch, "neighbors", walk_neighbor_table(ip, sport, self.community, self.version)
            )
            db.commit()

    def _commit_progress(self, switches_walked: int) -> None:
        with session_scope() as db:
            capture_session = db.get(CaptureSession, self.capture_session_id)
            if capture_session is None or capture_session.status != "running":
                return
            capture_session.bytes_processed = min(switches_walked, len(self.targets))
            capture_session.packet_count = switches_walked
            db.commit()

    def _finish(self, status: str, switches_walked: int, error_message: str | None = None) -> None:
        with session_scope() as db:
            capture_session = db.get(CaptureSession, self.capture_session_id)
            if capture_session is None:
                return
            if status == "completed":
                capture_session.bytes_processed = capture_session.total_bytes
            capture_session.status = status
            if error_message:
                capture_session.error_message = error_message
            capture_session.ended_at = datetime.datetime.now(datetime.timezone.utc)
            db.commit()


class SnmpWalkManager:
    def __init__(self) -> None:
        self._workers: dict[int, _SnmpWalkWorker] = {}
        self._lock = threading.Lock()

    def start(self, capture_session_id: int, targets: list[str], community: str, version: str) -> None:
        worker = _SnmpWalkWorker(capture_session_id, targets, community, version)
        with self._lock:
            self._workers[capture_session_id] = worker
        worker.start()

    def stop(self, capture_session_id: int) -> bool:
        with self._lock:
            worker = self._workers.pop(capture_session_id, None)
        if worker is None:
            return False
        worker.stop()
        return True

    def stop_all(self) -> None:
        with self._lock:
            session_ids = list(self._workers.keys())
        for session_id in session_ids:
            self.stop(session_id)


snmp_walk_manager = SnmpWalkManager()
