from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, joinedload

from app.auth.deps import get_current_user, require_editor
from app.db import get_db
from app.models import Device, User, VulnerabilityFinding
from app.schemas import ScanRequest, VulnerabilityFindingOut
from app.vuln.engine import scan_all_devices, scan_device

router = APIRouter(prefix="/api/vuln", tags=["vulnerabilities"])


@router.get("/findings", response_model=list[VulnerabilityFindingOut])
def list_findings(
    severity: str | None = None,
    device_id: int | None = None,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    query = db.query(VulnerabilityFinding).options(joinedload(VulnerabilityFinding.device))
    if severity:
        query = query.filter(VulnerabilityFinding.severity == severity)
    if device_id:
        query = query.filter(VulnerabilityFinding.device_id == device_id)
    return query.order_by(VulnerabilityFinding.created_at.desc()).all()


@router.post("/scan", response_model=list[VulnerabilityFindingOut])
def trigger_scan(payload: ScanRequest, db: Session = Depends(get_db), _user: User = Depends(require_editor)):
    if payload.device_id is not None:
        device = db.get(Device, payload.device_id)
        if device is None:
            raise HTTPException(status_code=404, detail="Device not found")
        return scan_device(db, device, use_nvd=payload.use_nvd)
    return scan_all_devices(db, use_nvd=payload.use_nvd)
