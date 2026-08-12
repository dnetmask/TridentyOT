"""Builds the network topology graph (GET /api/topology) and manages
human-asserted physical links (POST/PATCH/DELETE /api/topology/links) --
see app/models.py's NetworkLink docstring for the core design decision:
a NetworkLink is never inferred automatically, only entered by someone who
knows the real wiring. Everything auto-detected only ever produces
*suggested* edges, computed live from Flow on every request rather than
stored -- there's nothing to keep in sync, and a NetworkLink for the same
device pair always wins over one.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.routes_inventory import _filter_by_zone_or_site
from app.auth.deps import get_current_user, is_super_admin, require_admin
from app.db import get_db
from app.fingerprint.device_classifier import HMI, NETWORK_DEVICE, PLC, ROUTER_NAT, SERVER, WORKSTATION
from app.i18n import message
from app.models import CaptureSession, Device, Flow, NetworkLink, Sensor, User, Zone
from app.schemas import (
    NetworkLinkCreateRequest,
    NetworkLinkOut,
    NetworkLinkUpdateRequest,
    TopologyEdge,
    TopologyNode,
    TopologyOut,
)

router = APIRouter(prefix="/api/topology", tags=["topology"])

_ICON_BY_DEVICE_TYPE = {PLC: "plc", HMI: "hmi", SERVER: "server", WORKSTATION: "pc"}


def _icon_key(device: Device) -> str:
    device_type = device.display_device_type
    if device_type == NETWORK_DEVICE:
        return "router" if device.display_device_type_secondary == ROUTER_NAT else "switch"
    return _ICON_BY_DEVICE_TYPE.get(device_type, "other")


def _zone_by_capture_session_id(db: Session, devices: list[Device]) -> dict[int, tuple[int, str]]:
    """Bulk lookup, not one query per device: maps each distinct
    capture_session_id among `devices` to the Zona that first captured it
    (via Sensor -- same attribution CaptureSession.sensor_id already
    carries elsewhere). Computed unconditionally regardless of scope --
    it's one cheap query either way, and it's simpler than special-casing
    "only bother when the request spans more than one Zona". The frontend
    is the one that decides whether zone_id/zone_name are worth acting on
    (grouping devices into a per-Zona box only makes sense for a Sitio-wide
    view that actually spans more than one -- see TopologyNode's docstring)."""
    session_ids = {d.capture_session_id for d in devices if d.capture_session_id is not None}
    if not session_ids:
        return {}
    rows = (
        db.query(CaptureSession.id, Zone.id, Zone.name)
        .join(Sensor, CaptureSession.sensor_id == Sensor.id)
        .join(Zone, Sensor.zone_id == Zone.id)
        .filter(CaptureSession.id.in_(session_ids))
        .all()
    )
    return {row[0]: (row[1], row[2]) for row in rows}


def _node(device: Device, zone_by_session_id: dict[int, tuple[int, str]]) -> TopologyNode:
    zone_id, zone_name = zone_by_session_id.get(device.capture_session_id, (None, None))
    return TopologyNode(
        id=device.id,
        label=device.display_name or device.ip or device.mac or f"device-{device.id}",
        ip=device.ip,
        mac=device.mac,
        vendor=device.display_vendor,
        device_type=device.display_device_type,
        device_type_secondary=device.display_device_type_secondary,
        icon=_icon_key(device),
        is_ot_suspected=device.is_ot_suspected,
        is_external=device.is_external,
        zone_id=zone_id,
        zone_name=zone_name,
    )


def _manual_edge(link: NetworkLink) -> TopologyEdge:
    return TopologyEdge(
        source=link.device_a_id,
        target=link.device_b_id,
        kind=link.status,
        source_port=link.source_port,
        target_port=link.target_port,
        notes=link.notes,
        link_id=link.id,
    )


def _suggested_edge(device_a_id: int, device_b_id: int, flows: list[Flow]) -> TopologyEdge:
    protocols = sorted({f.protocol for f in flows})
    label = protocols[0] if len(protocols) == 1 else f"{len(protocols)} protocolos"
    return TopologyEdge(source=device_a_id, target=device_b_id, kind="suggested", label=label)


@router.get("", response_model=TopologyOut)
def get_topology(
    zone_id: int | None = None,
    site_id: int | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    device_query = db.query(Device)
    if not is_super_admin(user):
        device_query = device_query.filter(Device.organization_id == user.organization_id)
    device_query = _filter_by_zone_or_site(device_query, Device, zone_id, site_id)
    devices = device_query.all()
    device_ids = {d.id for d in devices}
    zone_by_session_id = _zone_by_capture_session_id(db, devices)
    nodes = [_node(d, zone_by_session_id) for d in devices]

    link_query = db.query(NetworkLink)
    if not is_super_admin(user):
        link_query = link_query.filter(NetworkLink.organization_id == user.organization_id)
    # A zone/site filter narrows *devices* shown, not NetworkLink rows
    # directly (the table has no capture_session_id to scope by the same
    # way -- a link is a standalone fact about two devices, not something
    # any one capture observed) -- dropping a link here because one of its
    # two devices fell outside the filter is the same "don't show an edge
    # to a node that isn't drawn" rule applied to suggested/Flow edges below.
    manual_links = [
        link for link in link_query.all() if link.device_a_id in device_ids and link.device_b_id in device_ids
    ]
    manual_pairs = {(link.device_a_id, link.device_b_id) for link in manual_links}
    edges = [_manual_edge(link) for link in manual_links]

    flows = (
        db.query(Flow)
        .filter(Flow.device_a_id.in_(device_ids), Flow.device_b_id.in_(device_ids))
        .all()
        if device_ids
        else []
    )
    flows_by_pair: dict[tuple[int, int], list[Flow]] = {}
    for flow in flows:
        flows_by_pair.setdefault((flow.device_a_id, flow.device_b_id), []).append(flow)
    for pair, pair_flows in flows_by_pair.items():
        # A real NetworkLink always outranks a Flow-derived suggestion for
        # the same two devices -- see NetworkLink's own docstring for why
        # (a human's claim about the wiring beats an inference from traffic).
        if pair in manual_pairs:
            continue
        edges.append(_suggested_edge(pair[0], pair[1], pair_flows))

    return TopologyOut(nodes=nodes, edges=edges)


def _get_owned_devices_pair(db: Session, user: User, device_a_id: int, device_b_id: int) -> tuple[Device, Device]:
    if device_a_id == device_b_id:
        raise HTTPException(status_code=400, detail=message("topology.cannot_link_device_to_itself", user.locale))
    query = db.query(Device).filter(Device.id.in_([device_a_id, device_b_id]))
    if not is_super_admin(user):
        query = query.filter(Device.organization_id == user.organization_id)
    devices = {d.id: d for d in query.all()}
    if device_a_id not in devices or device_b_id not in devices:
        raise HTTPException(status_code=404, detail=message("inventory.device_not_found", user.locale))
    device_a, device_b = devices[device_a_id], devices[device_b_id]
    if device_a.organization_id != device_b.organization_id:
        raise HTTPException(status_code=400, detail=message("topology.devices_required_same_org", user.locale))
    return device_a, device_b


def _get_owned_link(db: Session, user: User, link_id: int) -> NetworkLink:
    query = db.query(NetworkLink).filter(NetworkLink.id == link_id)
    if not is_super_admin(user):
        query = query.filter(NetworkLink.organization_id == user.organization_id)
    link = query.one_or_none()
    if link is None:
        raise HTTPException(status_code=404, detail=message("topology.link_not_found", user.locale))
    return link


@router.post("/links", response_model=NetworkLinkOut)
def create_network_link(
    payload: NetworkLinkCreateRequest, db: Session = Depends(get_db), user: User = Depends(require_admin)
):
    """Upsert by device pair, not a strict create: the unique constraint on
    (device_a_id, device_b_id) means a second POST for the same two
    devices updates the existing row instead of 409ing -- this is what
    lets the frontend's "confirmar" action on a Flow-suggested edge just
    POST the pair unconditionally, without first checking whether some
    earlier, weaker claim about it (e.g. status=uncertain) already exists."""
    device_a, device_b = _get_owned_devices_pair(db, user, payload.device_a_id, payload.device_b_id)
    # Normalized the same way Flow's own device_a/device_b are (lower id
    # first) so the unique constraint means the same thing regardless of
    # which node the user clicked first when drawing the link -- ports
    # are swapped along with the devices so source_port still refers to
    # whichever device ends up as device_a.
    if device_a.id > device_b.id:
        device_a, device_b = device_b, device_a
        source_port, target_port = payload.target_port, payload.source_port
    else:
        source_port, target_port = payload.source_port, payload.target_port

    existing = (
        db.query(NetworkLink)
        .filter(NetworkLink.device_a_id == device_a.id, NetworkLink.device_b_id == device_b.id)
        .one_or_none()
    )
    if existing is not None:
        link = existing
    else:
        link = NetworkLink(
            organization_id=device_a.organization_id,
            device_a_id=device_a.id,
            device_b_id=device_b.id,
            created_by_user_id=user.id,
        )
        db.add(link)
    link.source_port = source_port
    link.target_port = target_port
    link.status = payload.status
    link.notes = payload.notes
    db.commit()
    db.refresh(link)
    return link


@router.patch("/links/{link_id}", response_model=NetworkLinkOut)
def update_network_link(
    link_id: int,
    payload: NetworkLinkUpdateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
):
    link = _get_owned_link(db, user, link_id)
    link.source_port = payload.source_port
    link.target_port = payload.target_port
    link.status = payload.status
    link.notes = payload.notes
    db.commit()
    db.refresh(link)
    return link


@router.delete("/links/{link_id}", status_code=204)
def delete_network_link(link_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    link = _get_owned_link(db, user, link_id)
    db.delete(link)
    db.commit()
    return None
