import datetime
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.auth.deps import get_current_user, is_super_admin, require_admin
from app.capture.live_capture import live_capture_manager
from app.capture.pcap_loader import process_pcap_file
from app.config import DATA_DIR, DEFAULT_LIVE_CAPTURE_FILTER
from app.db import get_db, session_scope
from app.i18n import message
from app.inventory.inventory_service import purge_capture_session, wipe_all_capture_data
from app.models import CaptureSession, Sensor, Site, User, Zone
from app.schemas import CaptureSessionOut, StartLiveCaptureRequest, capture_session_out

router = APIRouter(prefix="/api/capture", tags=["capture"])

UPLOAD_DIR = DATA_DIR / "uploads"


def _get_owned_sensor(db: Session, user: User, sensor_id: int) -> Sensor:
    """Mirrors routes_hierarchy._get_owned_zone -- a Sensor has no direct
    organization_id of its own, so ownership is checked by joining up
    through its Zone and Site."""
    query = db.query(Sensor).filter(Sensor.id == sensor_id)
    if not is_super_admin(user):
        query = (
            query.join(Zone, Sensor.zone_id == Zone.id)
            .join(Site, Zone.site_id == Site.id)
            .filter(Site.organization_id == user.organization_id)
        )
    sensor = query.one_or_none()
    if sensor is None:
        raise HTTPException(status_code=404, detail=message("sensors.not_found", user.locale))
    return sensor


def _resolve_capture_sensor(db: Session, user: User, sensor_id: int | None) -> Sensor:
    """sensor_id is optional: a caller with exactly one Sensor available
    (the common single-Sitio deployment) shouldn't have to pick, so this
    falls back to it automatically. Required (400, not a silent guess) once
    there's more than one to choose from, or none at all -- either way
    guessing would risk attributing the capture to the wrong Sitio, which
    is the whole point of tracking this in the first place."""
    if sensor_id is not None:
        return _get_owned_sensor(db, user, sensor_id)

    query = db.query(Sensor)
    if not is_super_admin(user):
        query = (
            query.join(Zone, Sensor.zone_id == Zone.id)
            .join(Site, Zone.site_id == Site.id)
            .filter(Site.organization_id == user.organization_id)
        )
    sensors = query.order_by(Sensor.id.asc()).limit(2).all()
    if len(sensors) == 1:
        return sensors[0]
    if not sensors:
        raise HTTPException(status_code=400, detail=message("capture.sensor_id_required_none", user.locale))
    raise HTTPException(status_code=400, detail=message("capture.sensor_id_required_ambiguous", user.locale))


def _sensor_organization_id(db: Session, sensor: Sensor) -> int | None:
    """The Sensor's own organization, via Zone -> Site -- not the caller's:
    a Super Admin capturing on a Sensor that belongs to some organization
    has none of their own (user.organization_id is None), so the
    CaptureSession must take its organization from the sensor it's
    actually attached to instead."""
    zone = db.get(Zone, sensor.zone_id)
    site = db.get(Site, zone.site_id)
    return site.organization_id


@router.get("/interfaces")
def list_interfaces(_user: User = Depends(get_current_user)):
    from scapy.all import get_if_list

    try:
        return {"interfaces": get_if_list()}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/sessions", response_model=list[CaptureSessionOut])
def list_sessions(
    zone_id: int | None = None,
    site_id: int | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = db.query(CaptureSession)
    if not is_super_admin(user):
        query = query.filter(CaptureSession.organization_id == user.organization_id)
    if zone_id is not None:
        query = query.join(Sensor, CaptureSession.sensor_id == Sensor.id).filter(Sensor.zone_id == zone_id)
    elif site_id is not None:
        query = (
            query.join(Sensor, CaptureSession.sensor_id == Sensor.id)
            .join(Zone, Sensor.zone_id == Zone.id)
            .filter(Zone.site_id == site_id)
        )
    sessions = query.order_by(CaptureSession.started_at.desc()).all()
    return [capture_session_out(s, user.locale) for s in sessions]


def _get_own_session(db: Session, user: User, session_id: int) -> CaptureSession:
    query = db.query(CaptureSession).filter(CaptureSession.id == session_id)
    if not is_super_admin(user):
        query = query.filter(CaptureSession.organization_id == user.organization_id)
    session_obj = query.one_or_none()
    if session_obj is None:
        raise HTTPException(status_code=404, detail=message("capture.session_not_found", user.locale))
    return session_obj


@router.get("/sessions/{session_id}", response_model=CaptureSessionOut)
def get_session(session_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return capture_session_out(_get_own_session(db, user, session_id), user.locale)


@router.post("/live/start", response_model=CaptureSessionOut)
def start_live_capture(
    payload: StartLiveCaptureRequest, db: Session = Depends(get_db), user: User = Depends(require_admin)
):
    sensor = _resolve_capture_sensor(db, user, payload.sensor_id)
    bpf_filter = payload.bpf_filter or DEFAULT_LIVE_CAPTURE_FILTER
    session_obj = CaptureSession(
        organization_id=_sensor_organization_id(db, sensor),
        sensor_id=sensor.id,
        name=payload.name or f"live:{payload.interface}",
        source_type="live",
        source=payload.interface,
        bpf_filter=bpf_filter,
        status="running",
    )
    db.add(session_obj)
    db.commit()
    db.refresh(session_obj)

    try:
        live_capture_manager.start(session_obj.id, payload.interface, bpf_filter)
    except RuntimeError as exc:
        session_obj.status = "error"
        session_obj.error_message = str(exc)
        session_obj.ended_at = datetime.datetime.now(datetime.timezone.utc)
        db.commit()
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return capture_session_out(session_obj, user.locale)


@router.post("/live/stop/{session_id}", response_model=CaptureSessionOut)
def stop_live_capture(session_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    session_obj = _get_own_session(db, user, session_id)
    if session_obj.source_type != "live":
        raise HTTPException(status_code=400, detail=message("capture.not_a_live_session", user.locale))

    # Best-effort: if this process is actually tracking a sniffer for it,
    # stop it. If not -- e.g. the server restarted since this session
    # started, so the in-memory tracking was lost while the DB still says
    # "running" -- there's no real sniffer left to stop anyway, but the
    # user still needs "Detener" to clear the stuck state, not 409 forever.
    live_capture_manager.stop(session_id)

    session_obj.status = "stopped"
    session_obj.ended_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()
    db.refresh(session_obj)
    return capture_session_out(session_obj, user.locale)


@router.delete("/sessions/{session_id}", status_code=204)
def delete_session(session_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    session_obj = _get_own_session(db, user, session_id)

    if session_obj.source_type == "live":
        live_capture_manager.stop(session_id)  # no-op if not actually tracked

    purge_capture_session(db, session_id)
    db.delete(session_obj)
    db.commit()
    return None


@router.delete("/wipe")
def wipe_database(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """Clears every capture session, device, protocol, flow, and
    vulnerability finding belonging to the caller's organization, so a
    completely blank capture can start -- user accounts are never touched
    by this."""
    live_capture_manager.stop_all()
    counts = wipe_all_capture_data(db, user.organization_id)
    db.commit()
    return counts


def _process_pcap_background(filepath: str, capture_session_id: int) -> None:
    with session_scope() as db:
        capture_session = db.get(CaptureSession, capture_session_id)
        if capture_session is None:
            return
        process_pcap_file(db, filepath, capture_session)


@router.post("/pcap", response_model=CaptureSessionOut)
async def upload_pcap(
    background_tasks: BackgroundTasks,
    file: UploadFile,
    sensor_id: int | None = Form(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
):
    sensor = _resolve_capture_sensor(db, user, sensor_id)

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    dest_path = UPLOAD_DIR / f"{uuid4().hex}_{file.filename}"
    content = await file.read()
    dest_path.write_bytes(content)

    session_obj = CaptureSession(
        organization_id=_sensor_organization_id(db, sensor),
        sensor_id=sensor.id,
        name=file.filename or "upload.pcap",
        source_type="pcap",
        source=file.filename or "upload.pcap",
        status="running",
    )
    db.add(session_obj)
    db.commit()
    db.refresh(session_obj)

    background_tasks.add_task(_process_pcap_background, str(dest_path), session_obj.id)
    return capture_session_out(session_obj, user.locale)
