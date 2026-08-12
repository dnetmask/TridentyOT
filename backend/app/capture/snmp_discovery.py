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
"""

import datetime
import ipaddress
import threading
from typing import Any

from scapy.asn1.asn1 import ASN1_NULL, ASN1_OID
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.snmp import SNMP, SNMPget, SNMPresponse, SNMPvarbind
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
    apply_gateway_detection,
    apply_hostname_hints,
    apply_identity_hints,
    apply_os_guess,
    get_or_create_device,
    upsert_protocol,
)
from app.models import CaptureSession

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
