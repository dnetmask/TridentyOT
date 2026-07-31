import datetime
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.capture.live_capture import live_capture_manager
from app.capture.pcap_loader import process_pcap_file
from app.config import DATA_DIR, DEFAULT_LIVE_CAPTURE_FILTER
from app.db import get_db, session_scope
from app.models import CaptureSession
from app.schemas import CaptureSessionOut, StartLiveCaptureRequest

router = APIRouter(prefix="/api/capture", tags=["capture"])

UPLOAD_DIR = DATA_DIR / "uploads"


@router.get("/interfaces")
def list_interfaces():
    from scapy.all import get_if_list

    try:
        return {"interfaces": get_if_list()}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/sessions", response_model=list[CaptureSessionOut])
def list_sessions(db: Session = Depends(get_db)):
    return db.query(CaptureSession).order_by(CaptureSession.started_at.desc()).all()


@router.get("/sessions/{session_id}", response_model=CaptureSessionOut)
def get_session(session_id: int, db: Session = Depends(get_db)):
    session_obj = db.get(CaptureSession, session_id)
    if session_obj is None:
        raise HTTPException(status_code=404, detail="Capture session not found")
    return session_obj


@router.post("/live/start", response_model=CaptureSessionOut)
def start_live_capture(payload: StartLiveCaptureRequest, db: Session = Depends(get_db)):
    bpf_filter = payload.bpf_filter or DEFAULT_LIVE_CAPTURE_FILTER
    session_obj = CaptureSession(
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

    return session_obj


@router.post("/live/stop/{session_id}", response_model=CaptureSessionOut)
def stop_live_capture(session_id: int, db: Session = Depends(get_db)):
    session_obj = db.get(CaptureSession, session_id)
    if session_obj is None:
        raise HTTPException(status_code=404, detail="Capture session not found")

    stopped = live_capture_manager.stop(session_id)
    if not stopped and session_obj.status == "running":
        raise HTTPException(status_code=409, detail="Session is not an active live capture")

    session_obj.status = "stopped"
    session_obj.ended_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()
    db.refresh(session_obj)
    return session_obj


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
    db: Session = Depends(get_db),
):
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    dest_path = UPLOAD_DIR / f"{uuid4().hex}_{file.filename}"
    content = await file.read()
    dest_path.write_bytes(content)

    session_obj = CaptureSession(
        name=file.filename or "upload.pcap",
        source_type="pcap",
        source=file.filename or "upload.pcap",
        status="running",
    )
    db.add(session_obj)
    db.commit()
    db.refresh(session_obj)

    background_tasks.add_task(_process_pcap_background, str(dest_path), session_obj.id)
    return session_obj
