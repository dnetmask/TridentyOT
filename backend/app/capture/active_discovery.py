"""Active discovery: unlike every other module under app/capture/, this one
transmits -- it doesn't just listen.

PROFINET DCP's "Identify All" service is the mechanism behind Siemens
PRONETA and TIA Portal's "accessible devices": a single Ethernet multicast
broadcast (no IP layer, no port scanning) that every PROFINET device on the
local segment answers with its own name/IP/MAC/vendor, even one that has no
IP configured yet. See scapy.contrib.pnio_dcp's own docstring, which
documents this exact frame shape.

The response side reuses process_packet()/ingest_packet_record() unchanged
-- packet_processor.py already recognizes a DCP Identify Response (that's
how passive capture extracts a PROFINET device's station name/reference
today), so a discovered device lands in Inventario exactly like a
passively-observed one, attributed to this scan's own CaptureSession
(source_type="active_pnio_dcp") for the usual Zona/Sitio scoping.
"""

import datetime
import time

from sqlalchemy.orm import Session

from app.capture.packet_processor import process_packet
from app.inventory.inventory_service import IngestCache, apply_gateway_detection, ingest_packet_record
from app.models import CaptureSession

try:
    from scapy.contrib.pnio import ProfinetIO
    from scapy.contrib.pnio_dcp import DCP_IDENTIFY_REQUEST_FRAME_ID, DCP_REQUEST, DCP_SERVICE_ID_IDENTIFY, ProfinetDCP
    from scapy.layers.l2 import Ether
    from scapy.sendrecv import AsyncSniffer, sendp
except ImportError:  # pragma: no cover - scapy always ships these contrib layers
    ProfinetIO = ProfinetDCP = Ether = AsyncSniffer = sendp = None
    DCP_IDENTIFY_REQUEST_FRAME_ID = DCP_REQUEST = DCP_SERVICE_ID_IDENTIFY = None

# The reserved multicast MAC every PROFINET DCP "Identify All" request goes
# to -- every PROFINET device on the segment is listening on it, the same
# way every device answers an ARP broadcast.
DCP_MULTICAST_MAC = "01:0e:cf:00:00:00"

# Scopes the sniff to PROFINET frames only (EtherType 0x8892) -- discovery
# doesn't care about anything else running on the segment, and this keeps a
# busy production line's ordinary IT/IP traffic from ever reaching this
# scan's ingest path.
PROFINET_BPF_FILTER = "ether proto 0x8892"

# How long to let the sniffer settle into its capture loop before
# transmitting -- without this, the request can go out (and come straight
# back, since a switch or the NIC itself may reflect a multicast frame
# quickly) before AsyncSniffer.start() has actually attached, silently
# losing the fastest replies.
_SNIFFER_WARMUP_SECONDS = 0.2

MIN_SCAN_SECONDS = 1
MAX_SCAN_SECONDS = 30
DEFAULT_SCAN_SECONDS = 5


def _send_identify_all(interface: str) -> None:
    frame = (
        Ether(dst=DCP_MULTICAST_MAC)
        / ProfinetIO(frameID=DCP_IDENTIFY_REQUEST_FRAME_ID)
        / ProfinetDCP(
            service_id=DCP_SERVICE_ID_IDENTIFY, service_type=DCP_REQUEST, option=255, sub_option=255, dcp_data_length=4
        )
    )
    sendp(frame, iface=interface, verbose=False)


def _is_identify_request(pkt) -> bool:
    # Our own broadcast (or another engineering tool's, if one happens to be
    # polling the same segment) carries no device self-description -- only
    # a Response has the Name-of-Station/Device-ID/IP blocks that actually
    # describe a device. Letting a request frame through would attribute an
    # empty, nameless "device" to whichever MAC sent it -- including this
    # server's own sensor NIC.
    return pkt.haslayer(ProfinetDCP) and pkt[ProfinetDCP].service_type == DCP_REQUEST


def run_profinet_dcp_scan(
    db_session: Session, interface: str, duration_seconds: float, capture_session: CaptureSession
) -> None:
    if ProfinetDCP is None:
        capture_session.status = "error"
        capture_session.error_message = "scapy.contrib.pnio_dcp is not available in this environment"
        capture_session.ended_at = datetime.datetime.now(datetime.timezone.utc)
        db_session.commit()
        return

    sniffer = AsyncSniffer(iface=interface, filter=PROFINET_BPF_FILTER, store=True)
    try:
        sniffer.start()
        time.sleep(_SNIFFER_WARMUP_SECONDS)
        _send_identify_all(interface)
        time.sleep(duration_seconds)
        packets = sniffer.stop()

        cache = IngestCache()
        count = 0
        for pkt in packets:
            count += 1
            if _is_identify_request(pkt):
                continue
            record = process_packet(pkt)
            if record is not None:
                ingest_packet_record(
                    db_session,
                    record,
                    organization_id=capture_session.organization_id,
                    capture_session_id=capture_session.id,
                    cache=cache,
                )
        apply_gateway_detection(db_session, capture_session.organization_id)
        capture_session.packet_count = count
        capture_session.status = "completed"
    except Exception as exc:
        # Mirrors process_pcap_file's own handling: a failed flush/commit
        # can leave the session's transaction aborted on Postgres, so any
        # further statement on it (including the finally block's own
        # commit below) would raise a *different* error instead unless
        # rolled back first -- without this, the capture session would
        # never actually reach status "error", freezing at "running"
        # forever from the UI's perspective.
        db_session.rollback()
        capture_session.status = "error"
        capture_session.error_message = str(exc)
    finally:
        capture_session.ended_at = datetime.datetime.now(datetime.timezone.utc)
        db_session.commit()
