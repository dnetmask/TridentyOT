from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.routes_capture import _get_own_session, _get_owned_sensor, _sensor_organization_id
from app.auth.deps import require_admin
from app.capture.active_discovery import run_profinet_dcp_scan
from app.capture.nmap_discovery import nmap_scan_manager
from app.db import get_db, session_scope
from app.i18n import message
from app.models import SENSOR_KIND_LIVE, CaptureSession, Sensor, User
from app.schemas import CaptureSessionOut, NmapScanRequest, ProfinetDcpScanRequest, capture_session_out

router = APIRouter(prefix="/api/discovery", tags=["discovery"])


def _resolve_live_sensor(db: Session, user: User, sensor_id: int) -> Sensor:
    """Active discovery always needs a real interface on this server to
    transmit/listen on -- an external Sensor (see SENSOR_KIND_EXTERNAL in
    models.py) has none, same constraint as starting a live capture."""
    sensor = _get_owned_sensor(db, user, sensor_id)
    if sensor.kind != SENSOR_KIND_LIVE:
        raise HTTPException(status_code=400, detail=message("discovery.sensor_must_be_live", user.locale))
    return sensor


def _run_profinet_dcp_background(capture_session_id: int, interface: str, duration_seconds: float) -> None:
    with session_scope() as db:
        capture_session = db.get(CaptureSession, capture_session_id)
        if capture_session is None:
            return
        run_profinet_dcp_scan(db, interface, duration_seconds, capture_session)


@router.post("/profinet-dcp", response_model=CaptureSessionOut)
def start_profinet_dcp_scan(
    payload: ProfinetDcpScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
):
    sensor = _resolve_live_sensor(db, user, payload.sensor_id)

    session_obj = CaptureSession(
        organization_id=_sensor_organization_id(db, sensor),
        sensor_id=sensor.id,
        name=f"discovery:profinet-dcp:{payload.interface}",
        source_type="active_pnio_dcp",
        source=payload.interface,
        status="running",
    )
    db.add(session_obj)
    db.commit()
    db.refresh(session_obj)

    background_tasks.add_task(
        _run_profinet_dcp_background, session_obj.id, payload.interface, payload.duration_seconds
    )
    return capture_session_out(session_obj, user.locale)


@router.post("/nmap", response_model=CaptureSessionOut)
def start_nmap_scan(
    payload: NmapScanRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
):
    sensor = _resolve_live_sensor(db, user, payload.sensor_id)

    session_obj = CaptureSession(
        organization_id=_sensor_organization_id(db, sensor),
        sensor_id=sensor.id,
        name=f"discovery:nmap:{payload.target}",
        source_type="active_nmap",
        source=payload.target,
        status="running",
    )
    db.add(session_obj)
    db.commit()
    db.refresh(session_obj)

    # No BackgroundTasks here, unlike PROFINET DCP: this scan has no fixed
    # end time and needs to be reachable afterwards for /nmap/stop/{id} --
    # nmap_scan_manager tracks the running subprocess by session id the
    # same way live_capture_manager tracks a running sniffer.
    nmap_scan_manager.start(session_obj.id, payload.target)
    return capture_session_out(session_obj, user.locale)


@router.post("/nmap/stop/{session_id}", response_model=CaptureSessionOut)
def stop_nmap_scan(session_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    session_obj = _get_own_session(db, user, session_id)
    if session_obj.source_type != "active_nmap":
        raise HTTPException(status_code=400, detail=message("discovery.not_an_nmap_session", user.locale))

    # Best-effort, same reasoning as live capture's own stop endpoint: if
    # this process isn't actually tracking a worker for it (e.g. the
    # server restarted since the scan started), there's nothing left to
    # terminate, but the row can still be reloaded to reflect whatever
    # mark_orphaned_live_sessions_stopped already did to it at startup.
    nmap_scan_manager.stop(session_id)
    db.refresh(session_obj)
    return capture_session_out(session_obj, user.locale)
