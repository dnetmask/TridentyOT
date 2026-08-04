from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, joinedload

from app.auth.deps import get_current_user, is_super_admin, require_admin
from app.db import get_db
from app.i18n import message
from app.models import Device, User, VulnerabilityFinding
from app.schemas import ScanRequest, VulnerabilityFindingOut, vulnerability_finding_out
from app.vuln.engine import scan_all_devices, scan_device

router = APIRouter(prefix="/api/vuln", tags=["vulnerabilities"])


@router.get("/findings", response_model=list[VulnerabilityFindingOut])
def list_findings(
    severity: str | None = None,
    device_id: int | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = (
        db.query(VulnerabilityFinding)
        .join(Device, VulnerabilityFinding.device_id == Device.id)
        .options(joinedload(VulnerabilityFinding.device))
    )
    if not is_super_admin(user):
        query = query.filter(Device.organization_id == user.organization_id)
    if severity:
        query = query.filter(VulnerabilityFinding.severity == severity)
    if device_id:
        query = query.filter(VulnerabilityFinding.device_id == device_id)
    findings = query.order_by(VulnerabilityFinding.created_at.desc()).all()
    return [vulnerability_finding_out(f, user.locale) for f in findings]


@router.post("/scan", response_model=list[VulnerabilityFindingOut])
def trigger_scan(payload: ScanRequest, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    if payload.device_id is not None:
        device = (
            db.query(Device)
            .filter(Device.id == payload.device_id, Device.organization_id == user.organization_id)
            .one_or_none()
        )
        if device is None:
            raise HTTPException(status_code=404, detail=message("vuln.device_not_found", user.locale))
        findings = scan_device(db, device, use_nvd=payload.use_nvd)
    else:
        findings = scan_all_devices(db, user.organization_id, use_nvd=payload.use_nvd)
    return [vulnerability_finding_out(f, user.locale) for f in findings]
