from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, joinedload

from app.auth.deps import get_current_user, require_editor
from app.db import get_db
from app.fingerprint.device_classifier import ROUTER_NAT
from app.fingerprint.ip_scope import is_lan_ip
from app.i18n import message
from app.models import Device, DeviceProtocol, Flow, User
from app.schemas import DeviceDetailOut, DeviceOut, DeviceUpdateRequest, FlowOut, device_detail_out, device_out

router = APIRouter(prefix="/api/inventory", tags=["inventory"])


@router.get("/devices", response_model=list[DeviceOut])
def list_devices(
    ot_only: bool = False,
    protocol: str | None = None,
    hide_external: bool = False,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = (
        db.query(Device)
        .options(joinedload(Device.protocols))
        .filter(Device.organization_id == user.organization_id)
    )
    if ot_only:
        query = query.filter(Device.is_ot_suspected.is_(True))
    if protocol:
        query = query.join(DeviceProtocol).filter(DeviceProtocol.protocol == protocol)
    devices = query.order_by(Device.last_seen.desc()).all()

    # Some LANs (mis)assign public IP ranges to real local devices, so a
    # public-looking IP alone is no longer grounds to hide something from
    # Inventory -- see Device.is_external for the combined mac+IP signal
    # that actually distinguishes "off-network" from "just a public range
    # in use here". Devices are shown by default; hide_external is opt-in.
    if hide_external:
        # A router/NAT gateway forwarding return traffic from the internet
        # is, by this app's own MAC-learning rule, the *sender* of those
        # frames on the LAN -- so its MAC ends up attached to every
        # distinct public IP it ever forwarded (see apply_gateway_detection).
        # Those duplicate rows are a forwarding artifact, not separate
        # assets, and get collapsed into the one row apply_gateway_detection
        # picked to represent the gateway (device_type_secondary ==
        # router_nat) -- but ONLY the public-IP duplicates. A *private*-IP
        # row sharing that same MAC (e.g. a real host on a different subnet,
        # reached through this gateway doing inter-VLAN routing) is a
        # genuine, distinct local asset, not a copy of the gateway itself --
        # never hide it just because it happens to share a MAC. Still real
        # rows either way, untouched in Flows/Vulnerabilidades.
        gateway_macs = {d.mac for d in devices if d.mac and d.display_device_type_secondary == ROUTER_NAT}
        if gateway_macs:
            devices = [
                d
                for d in devices
                if d.mac not in gateway_macs
                or d.display_device_type_secondary == ROUTER_NAT
                or is_lan_ip(d.ip)
            ]
        devices = [d for d in devices if not d.is_external]
    return [device_out(d, user.locale) for d in devices]


def _get_own_device(db: Session, user: User, device_id: int) -> Device:
    device = (
        db.query(Device)
        .options(joinedload(Device.protocols), joinedload(Device.findings))
        .filter(Device.id == device_id, Device.organization_id == user.organization_id)
        .one_or_none()
    )
    if device is None:
        raise HTTPException(status_code=404, detail=message("inventory.device_not_found", user.locale))
    return device


@router.get("/devices/{device_id}", response_model=DeviceDetailOut)
def get_device(device_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return device_detail_out(_get_own_device(db, user, device_id), user.locale)


@router.patch("/devices/{device_id}", response_model=DeviceDetailOut)
def update_device(
    device_id: int, payload: DeviceUpdateRequest, db: Session = Depends(get_db), user: User = Depends(require_editor)
):
    device = _get_own_device(db, user, device_id)

    updates = payload.model_dump(exclude_unset=True)
    if "custom_name" in updates:
        device.custom_name = updates["custom_name"] or None
    if "custom_vendor" in updates:
        device.custom_vendor = updates["custom_vendor"] or None
    if "custom_device_type" in updates:
        device.custom_device_type = updates["custom_device_type"] or None
    if "custom_device_type_secondary" in updates:
        device.custom_device_type_secondary = updates["custom_device_type_secondary"] or None

    db.commit()
    db.refresh(device)
    return device_detail_out(device, user.locale)


@router.get("/flows", response_model=list[FlowOut])
def list_flows(
    device_id: int | None = None,
    category: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = (
        db.query(Flow)
        .join(Device, Flow.device_a_id == Device.id)
        .filter(Device.organization_id == user.organization_id)
        .options(joinedload(Flow.device_a), joinedload(Flow.device_b), joinedload(Flow.server_device))
    )
    if device_id:
        query = query.filter((Flow.device_a_id == device_id) | (Flow.device_b_id == device_id))
    if category:
        query = query.filter(Flow.category == category)
    return query.order_by(Flow.packet_count.desc()).all()
