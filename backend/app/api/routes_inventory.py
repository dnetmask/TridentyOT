from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, joinedload

from app.db import get_db
from app.models import Device, DeviceProtocol, Flow
from app.schemas import DeviceDetailOut, DeviceOut, DeviceUpdateRequest, FlowOut

router = APIRouter(prefix="/api/inventory", tags=["inventory"])


@router.get("/devices", response_model=list[DeviceOut])
def list_devices(ot_only: bool = False, protocol: str | None = None, db: Session = Depends(get_db)):
    query = db.query(Device).options(joinedload(Device.protocols))
    if ot_only:
        query = query.filter(Device.is_ot_suspected.is_(True))
    if protocol:
        query = query.join(DeviceProtocol).filter(DeviceProtocol.protocol == protocol)
    return query.order_by(Device.last_seen.desc()).all()


@router.get("/devices/{device_id}", response_model=DeviceDetailOut)
def get_device(device_id: int, db: Session = Depends(get_db)):
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
def update_device(device_id: int, payload: DeviceUpdateRequest, db: Session = Depends(get_db)):
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
def list_flows(device_id: int | None = None, category: str | None = None, db: Session = Depends(get_db)):
    query = db.query(Flow).options(
        joinedload(Flow.device_a), joinedload(Flow.device_b), joinedload(Flow.server_device)
    )
    if device_id:
        query = query.filter((Flow.device_a_id == device_id) | (Flow.device_b_id == device_id))
    if category:
        query = query.filter(Flow.category == category)
    return query.order_by(Flow.packet_count.desc()).all()
