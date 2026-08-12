"""Active discovery via a real `nmap` scan -- a light service/OS probe
(top-100 TCP ports, cheap version probes, one OS fingerprint pass), not a
full or aggressive scan and never an NSE script: those have documented
cases of putting a live PLC into a fault state, which is exactly the kind
of risk a "light discovery mode" is meant to avoid. See the investigation
this followed -- python-nmap adds nothing over shelling out to the real
`nmap` binary and parsing its own XML output (`-oX -`) directly, which is
what this does.

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
import subprocess
import xml.etree.ElementTree as ET
from typing import Any

from sqlalchemy.orm import Session

from app.fingerprint.os_fingerprint import OsGuess
from app.fingerprint.protocol_detect import classify
from app.inventory.inventory_service import (
    IngestCache,
    apply_device_type_guess,
    apply_gateway_detection,
    apply_os_guess,
    get_or_create_device,
    upsert_protocol,
)
from app.models import CaptureSession

MIN_SCAN_SECONDS = 10
MAX_SCAN_SECONDS = 300
DEFAULT_SCAN_SECONDS = 60

# Deliberately fixed, not user-configurable, so this stays a "light" scan
# by construction rather than something that can accidentally be turned
# aggressive from the UI:
#   -F              fast mode -- ~100 common ports, not all 65535
#   -sV --version-light   cheap version probes (fewer/lighter than plain -sV)
#   -O              one OS fingerprint pass
# No NSE scripts, no UDP, no full port sweep.
_NMAP_ARGS = ["-T4", "-F", "-sV", "--version-light", "-O"]

# nmap's own subprocess grace period beyond --host-timeout to finish
# writing its XML report before this hard-kills it.
_SUBPROCESS_GRACE_SECONDS = 15


def _run_nmap_xml(target: str, timeout_seconds: float) -> str:
    proc = subprocess.run(
        ["nmap", *_NMAP_ARGS, "--host-timeout", f"{int(timeout_seconds)}s", "-oX", "-", target],
        capture_output=True,
        text=True,
        timeout=timeout_seconds + _SUBPROCESS_GRACE_SECONDS,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"nmap exited with status {proc.returncode}")
    return proc.stdout


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

        hosts.append({"ip": ip, "mac": mac, "ports": ports, "os_match": os_match})
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

    for port_info in host["ports"]:
        proto_info = classify(port_info["port"])
        product, version = port_info["product"], port_info["version"]
        banner = f"{product}/{version}" if product and version else product
        upsert_protocol(
            session, device, proto_info, port_info["port"], port_info["protocol"], "server",
            banner=banner, capture_session_id=capture_session_id, cache=cache,
        )

    apply_device_type_guess(session, device)


def run_nmap_scan(
    db_session: Session, target: str, duration_seconds: float, capture_session: CaptureSession
) -> None:
    try:
        xml_text = _run_nmap_xml(target, duration_seconds)
        hosts = _parse_hosts(xml_text)

        cache = IngestCache()
        for host in hosts:
            _ingest_nmap_host(db_session, host, capture_session.organization_id, capture_session.id, cache)
        apply_gateway_detection(db_session, capture_session.organization_id)

        # packet_count doesn't literally apply to an nmap scan (there's no
        # raw-capture packet count in its XML report) -- repurposed here as
        # "hosts found up", the closest equivalent summary number the
        # shared Sesiones de captura table has a column for already.
        capture_session.packet_count = len(hosts)
        capture_session.status = "completed"
    except subprocess.TimeoutExpired:
        db_session.rollback()
        capture_session.status = "error"
        capture_session.error_message = (
            f"El escaneo no terminó dentro de los {int(duration_seconds)}s permitidos -- "
            "probá con un objetivo más chico (un host o una subred pequeña)."
        )
    except Exception as exc:
        # Mirrors process_pcap_file/run_profinet_dcp_scan's own handling --
        # a failed flush/commit can leave the session's transaction aborted
        # on Postgres, so any further statement (including the finally
        # block's own commit below) needs a rollback first.
        db_session.rollback()
        capture_session.status = "error"
        capture_session.error_message = str(exc)
    finally:
        capture_session.ended_at = datetime.datetime.now(datetime.timezone.utc)
        db_session.commit()
