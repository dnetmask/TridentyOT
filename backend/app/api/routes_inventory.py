from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, joinedload

from app.db import get_db
from app.models import Device, DeviceProtocol
from app.schemas import DeviceDetailOut, DeviceOut

router = APIRouter(prefix="/api/inventory", tags=["inventory"])


@router.get("/devices", response_model=list[DeviceOut])
def list_devices(ot_only: bool = False, protocol: str | None = None, db: Session = Depends(get_db)):
    query = db.query(Device)
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
