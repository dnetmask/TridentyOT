from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, joinedload

from app.auth.deps import get_current_user, require_editor
from app.db import get_db
from app.fingerprint.ip_scope import is_lan_ip
from app.models import Device, DeviceProtocol, Flow, User
from app.schemas import DeviceDetailOut, DeviceOut, DeviceUpdateRequest, FlowOut

router = APIRouter(prefix="/api/inventory", tags=["inventory"])


@router.get("/devices", response_model=list[DeviceOut])
def list_devices(
    ot_only: bool = False,
    protocol: str | None = None,
    include_public: bool = False,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    query = db.query(Device).options(joinedload(Device.protocols))
    if ot_only:
        query = query.filter(Device.is_ot_suspected.is_(True))
    if protocol:
        query = query.join(DeviceProtocol).filter(DeviceProtocol.protocol == protocol)
    devices = query.order_by(Device.last_seen.desc()).all()

    # Inventory is meant to be *this network's* asset list. A device whose
    # only identity is a public-internet IP was never an asset here -- it's
    # something a real LAN device talked to, which still belongs in Flows
    # and in that device's own vulnerability findings, just not listed
    # alongside actual local hosts and switches.
    if not include_public:
        devices = [d for d in devices if is_lan_ip(d.ip)]
    return devices


@router.get("/devices/{device_id}", response_model=DeviceDetailOut)
def get_device(device_id: int, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    device = (
        db.query(Device)
        .options(joinedload(Device.protocols), joinedload(Device.findings))
        .filter(Device.id == device_id)
        .one_or_none()
    )
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@router.patch("/devices/{device_id}", response_model=DeviceDetailOut)
def update_device(
    device_id: int, payload: DeviceUpdateRequest, db: Session = Depends(get_db), _user: User = Depends(require_editor)
):
    device = (
        db.query(Device)
        .options(joinedload(Device.protocols), joinedload(Device.findings))
        .filter(Device.id == device_id)
        .one_or_none()
    )
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")

    updates = payload.model_dump(exclude_unset=True)
    if "custom_name" in updates:
        device.custom_name = updates["custom_name"] or None
    if "custom_vendor" in updates:
        device.custom_vendor = updates["custom_vendor"] or None

    db.commit()
    db.refresh(device)
    return device


@router.get("/flows", response_model=list[FlowOut])
def list_flows(
    device_id: int | None = None,
    category: str | None = None,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    query = db.query(Flow).options(
        joinedload(Flow.device_a), joinedload(Flow.device_b), joinedload(Flow.server_device)
    )
    if device_id:
        query = query.filter((Flow.device_a_id == device_id) | (Flow.device_b_id == device_id))
    if category:
        query = query.filter(Flow.category == category)
    return query.order_by(Flow.packet_count.desc()).all()
