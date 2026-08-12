"""Active discovery via a real `nmap` scan -- a light service/OS probe
(top-100 TCP ports, cheap version probes, one OS fingerprint pass), not a
full or aggressive scan and never an NSE script: those have documented
cases of putting a live PLC into a fault state, which is exactly the kind
of risk a "light discovery mode" is meant to avoid. See the investigation
this followed -- python-nmap adds nothing over shelling out to the real
`nmap` binary and parsing its own XML output directly, which is what this
does.

No fixed time limit: a scan runs until nmap finishes on its own or an
admin stops it (NmapScanManager.stop, mirroring live_capture.py's own
manager). Progress and results update live rather than only at the end:

  nmap's own stdout (line-buffered)   this module's worker thread
  "N hosts left" as each host's   ->  CaptureSession.bytes_processed
  SYN-scan phase completes            (of .total_bytes, the target's own
                                       address count -- reuses the same
                                       progress_percent property pcap
                                       uploads use, just for a different
                                       kind of "how far along" this time)

  nmap's own -oX file, growing    ->  re-parsed on the same tick and
  as each host's <host> block         re-ingested (idempotent -- see
  is written                          get_or_create_device/upsert_
                                       protocol), so CaptureSession.
                                       packet_count (repurposed here as
                                       "hosts identified so far") and
                                       Inventario climb during the scan,
                                       not just once it's done.

Stopping mid-scan (SIGTERM) leaves nmap's XML file without its closing
tags -- see _make_xml_parseable, which recovers every fully-written
<host> block and discards whatever host was still in progress, rather
than losing every result just because the very last one was incomplete.

Feeds each host nmap finds through the same Device/DeviceProtocol
machinery the passive engine uses (get_or_create_device/upsert_protocol/
apply_os_guess), so an open port and OS guess show up in Inventario/
Vulnerabilidades exactly like passively-observed ones -- attributed to
this scan's own CaptureSession (source_type="active_nmap") for the usual
Zona/Sitio scoping. Vulnerabilidades in particular is the actual point:
scan_device() already turns a DeviceProtocol.banner with a recognizable
product/version into an NVD lookup (see vuln/rules.extract_banner_
product_version) -- this is just a second, active way to fill that same
field, on top of whatever passive capture happened to observe.
"""

import datetime
import ipaddress
import logging
import re
import subprocess
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

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

logger = logging.getLogger(__name__)

# Deliberately fixed, not user-configurable, so this stays a "light" scan
# by construction rather than something that can accidentally be turned
# aggressive from the UI:
#   -F              fast mode -- ~100 common ports, not all 65535
#   -sV --version-light   cheap version probes (fewer/lighter than plain -sV)
#   -O              one OS fingerprint pass
#   -v              needed for the "N hosts left" progress lines this
#                   module parses -- without it nmap prints only the
#                   final per-host report, with no incremental signal.
# No NSE scripts, no UDP, no full port sweep.
_NMAP_ARGS = ["-T4", "-F", "-sV", "--version-light", "-O", "-v"]

_HOSTS_LEFT_RE = re.compile(r"\((\d+) hosts? left\)")

# How often (seconds) the worker re-checks the growing XML file and
# commits progress -- a real-time bound on freshness, not a packet-count
# one: nmap's own line cadence is unpredictable (long silent stretches
# during OS detection retries, then a burst of "hosts left" lines).
_PROGRESS_INTERVAL_SECONDS = 2.0


def _estimate_target_count(target: str) -> int:
    """How many addresses `target` covers, for the progress bar's
    denominator. Handles the common case (a single host or a CIDR network)
    exactly; anything nmap itself would treat as a host list (comma-
    separated, hyphenated ranges, a bare hostname) falls back to a rough
    comma-count rather than pretending to understand nmap's full target
    syntax -- an approximate progress bar beats none, but this is not a
    target-spec parser."""
    try:
        return ipaddress.ip_network(target, strict=False).num_addresses
    except ValueError:
        return max(1, target.count(",") + 1)


def _make_xml_parseable(xml_text: str) -> str:
    """A scan stopped mid-flight (or killed) leaves nmap's XML without its
    closing tags, and possibly with the last <host> block half-written --
    ElementTree refuses to parse that at all. Recovers every *complete*
    <host>...</host> block instead of losing all of them over one
    unfinished one."""
    if xml_text.rstrip().endswith("</nmaprun>"):
        return xml_text
    last_host_end = xml_text.rfind("</host>")
    if last_host_end == -1:
        return "<nmaprun>\n</nmaprun>"
    return xml_text[: last_host_end + len("</host>")] + "\n</nmaprun>"


def _parse_hosts(xml_text: str) -> list[dict[str, Any]]:
    root = ET.fromstring(xml_text)
    hosts = []
    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        if status_el is None or status_el.get("state") != "up":
            continue

        ip = mac = None
        for addr_el in host_el.findall("address"):
            addrtype = addr_el.get("addrtype")
            if addrtype in ("ipv4", "ipv6"):
                ip = addr_el.get("addr")
            elif addrtype == "mac":
                mac = addr_el.get("addr")

        ports = []
        for port_el in host_el.findall("ports/port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            service_el = port_el.find("service")
            ports.append(
                {
                    "port": int(port_el.get("portid")),
                    "protocol": port_el.get("protocol"),
                    "product": service_el.get("product") if service_el is not None else None,
                    "version": service_el.get("version") if service_el is not None else None,
                }
            )

        os_match = None
        osmatch_el = host_el.find("os/osmatch")
        if osmatch_el is not None:
            os_match = {"name": osmatch_el.get("name"), "accuracy": float(osmatch_el.get("accuracy", 0))}

        # nmap does a reverse-DNS (PTR) lookup by default (nothing in
        # _NMAP_ARGS disables it with -n) and reports whatever it resolved
        # here -- the same class of hint packet_processor.py's own DNS/mDNS
        # extraction feeds into apply_hostname_hints, so it goes through
        # that same multi-claimant-collision check rather than being
        # trusted outright.
        hostname_el = host_el.find("hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else None

        hosts.append({"ip": ip, "mac": mac, "ports": ports, "os_match": os_match, "hostname": hostname})
    return hosts


def _ingest_nmap_host(
    session: Session, host: dict[str, Any], organization_id: int, capture_session_id: int, cache: IngestCache
) -> None:
    device = get_or_create_device(
        session, ip=host["ip"], mac=host["mac"], organization_id=organization_id,
        capture_session_id=capture_session_id, cache=cache,
    )
    if device is None:
        return

    if host["os_match"]:
        guess = OsGuess(
            os_family="nmap",
            label=host["os_match"]["name"],
            confidence=min(host["os_match"]["accuracy"] / 100.0, 1.0),
            signature_name="nmap:" + host["os_match"]["name"],
            initial_ttl_guess=0,
            hop_estimate=0,
        )
        apply_os_guess(device, guess)

    if host["ip"] and host["hostname"]:
        apply_hostname_hints(session, [(host["ip"], host["hostname"])], organization_id)

    for port_info in host["ports"]:
        proto_info = classify(port_info["port"])
        product, version = port_info["product"], port_info["version"]
        banner = f"{product}/{version}" if product and version else product
        upsert_protocol(
            session, device, proto_info, port_info["port"], port_info["protocol"], "server",
            banner=banner, capture_session_id=capture_session_id, cache=cache,
        )
        # nmap's -sV already parsed the HTTP Server banner into `product`/
        # `version` directly -- no need to re-parse raw response bytes the
        # way the passive extract_http_identity does. Same "vendor := the
        # server banner text" convention that extractor uses for passively
        # observed HTTP traffic, so an HTTP(S) service found only via nmap
        # gets the same treatment as one found via passive capture.
        if proto_info.protocol in ("http", "http-alt", "https") and banner:
            apply_identity_hints(
                session,
                device,
                [
                    IdentityHint(
                        vendor=banner,
                        evidence=encode_i18n(
                            bilingual(
                                es=f'nmap -sV, puerto {port_info["port"]}: encabezado/banner de servicio "{banner}"',
                                en=f'nmap -sV, port {port_info["port"]}: service header/banner "{banner}"',
                            )
                        ),
                    )
                ],
            )

    apply_device_type_guess(session, device)


class _NmapScanWorker:
    def __init__(self, capture_session_id: int, target: str, interface: str | None = None) -> None:
        self.capture_session_id = capture_session_id
        self.target = target
        self.interface = interface
        self.total_targets = _estimate_target_count(target)
        self._xml_path = Path(tempfile.gettempdir()) / f"tridentyot-nmap-{capture_session_id}.xml"
        self._stop_requested = False
        self._process: subprocess.Popen | None = None
        self._thread = threading.Thread(
            target=self._run, name=f"nmap-scan-{capture_session_id}", daemon=True
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop_requested = True
        if self._process is not None and self._process.poll() is None:
            self._process.terminate()

    def _run(self) -> None:
        with session_scope() as db:
            capture_session = db.get(CaptureSession, self.capture_session_id)
            if capture_session is None:
                return
            capture_session.total_bytes = self.total_targets
            db.commit()

        if self._stop_requested:
            self._finish("stopped")
            return

        # -e <interface>: without this nmap picks whatever interface the
        # OS routing table would use, not the one the sensor is configured
        # with (Sensor.interface) -- on a host with more than one NIC (e.g.
        # a management NIC plus one on the OT segment) that can send the
        # scan out the wrong side, and it's also required for MAC/ARP
        # discovery to work at all: nmap only does that when the target is
        # layer-2 reachable from the interface it actually scans out of.
        args = list(_NMAP_ARGS)
        if self.interface:
            args += ["-e", self.interface]
        try:
            self._process = subprocess.Popen(
                ["nmap", *args, "-oX", str(self._xml_path), self.target],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
            )
        except Exception as exc:
            self._finish("error", str(exc))
            return

        scanned_so_far = 0
        last_progress_at = 0.0

        for line in self._process.stdout:
            match = _HOSTS_LEFT_RE.search(line)
            if match:
                scanned_so_far = max(scanned_so_far, self.total_targets - int(match.group(1)))
            now = time.monotonic()
            if now - last_progress_at >= _PROGRESS_INTERVAL_SECONDS:
                self._commit_progress(scanned_so_far)
                last_progress_at = now

        self._process.wait()
        self._commit_progress(scanned_so_far)
        self._finish("stopped" if self._stop_requested else "completed")

    def _read_hosts_so_far(self) -> list[dict[str, Any]]:
        if not self._xml_path.exists():
            return []
        try:
            xml_text = self._xml_path.read_text()
        except OSError:
            return []
        try:
            return _parse_hosts(_make_xml_parseable(xml_text))
        except ET.ParseError:
            logger.warning("nmap scan %d: XML not parseable yet, skipping this tick", self.capture_session_id)
            return []

    def _commit_progress(self, scanned_so_far: int) -> None:
        hosts = self._read_hosts_so_far()
        with session_scope() as db:
            capture_session = db.get(CaptureSession, self.capture_session_id)
            if capture_session is None or capture_session.status != "running":
                return
            capture_session.bytes_processed = min(scanned_so_far, self.total_targets)
            if hosts:
                cache = IngestCache()
                for host in hosts:
                    _ingest_nmap_host(db, host, capture_session.organization_id, capture_session.id, cache)
                apply_gateway_detection(db, capture_session.organization_id)
                capture_session.packet_count = len(hosts)
            db.commit()

    def _finish(self, status: str, error_message: str | None = None) -> None:
        with session_scope() as db:
            capture_session = db.get(CaptureSession, self.capture_session_id)
            if capture_session is None:
                return
            try:
                hosts = self._read_hosts_so_far()
                if hosts:
                    cache = IngestCache()
                    for host in hosts:
                        _ingest_nmap_host(db, host, capture_session.organization_id, capture_session.id, cache)
                    apply_gateway_detection(db, capture_session.organization_id)
                    capture_session.packet_count = len(hosts)
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
        self._xml_path.unlink(missing_ok=True)


class NmapScanManager:
    def __init__(self) -> None:
        self._workers: dict[int, _NmapScanWorker] = {}
        self._lock = threading.Lock()

    def start(self, capture_session_id: int, target: str, interface: str | None = None) -> None:
        worker = _NmapScanWorker(capture_session_id, target, interface)
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


nmap_scan_manager = NmapScanManager()
