"""Builds the network topology graph (GET /api/topology) and manages
human-asserted physical links (POST/PATCH/DELETE /api/topology/links) --
see app/models.py's NetworkLink docstring for the core design decision:
a NetworkLink is never inferred automatically, only entered by someone who
knows the real wiring.

Topology is deliberately NOT built from Flow: who-talked-to-whom is a
logical communication graph, not proof of a direct cable -- two devices can
chat right through several switches without being connected to each other.
Until there's a real source of physical adjacency (CDP/LLDP neighbor TLVs,
an SNMP walk of BRIDGE-MIB's MAC-to-port table, etc.), the only edges this
endpoint draws are the ones a human actually entered.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.routes_inventory import _filter_by_zone_or_site
from app.auth.deps import get_current_user, is_super_admin, require_admin
from app.db import get_db
from app.fingerprint.device_classifier import HMI, NETWORK_DEVICE, PLC, ROUTER_NAT, SERVER, WORKSTATION
from app.i18n import message
from app.models import (
    CANDIDATE_CONFIRMED,
    CANDIDATE_DISMISSED,
    CANDIDATE_PENDING,
    LINK_SOURCE_FLOW_CANDIDATE,
    CaptureSession,
    Device,
    FlowLinkCandidate,
    NetworkLink,
    Sensor,
    User,
    Zone,
)
from app.schemas import (
    FlowLinkCandidateOut,
    NetworkLinkCreateRequest,
    NetworkLinkOut,
    NetworkLinkUpdateRequest,
    TopologyEdge,
    TopologyNode,
    TopologyOut,
)
from app.topology_from_switch import upsert_link

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
        link_source=link.source,
        notes=link.notes,
        link_id=link.id,
    )


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
    # to a node that isn't drawn" rule that would apply to any other kind
    # of edge this endpoint might grow later.
    manual_links = [
        link for link in link_query.all() if link.device_a_id in device_ids and link.device_b_id in device_ids
    ]
    edges = [_manual_edge(link) for link in manual_links]

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
    (device_a_id, device_b_id) means a second POST for the same two devices
    updates the existing row instead of 409ing -- lets the frontend just
    POST a pair unconditionally to upgrade an existing weaker claim (e.g.
    status=uncertain) to confirmed, without checking first whether one
    already exists."""
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


def _get_owned_candidate(db: Session, user: User, candidate_id: int) -> FlowLinkCandidate:
    query = db.query(FlowLinkCandidate).filter(FlowLinkCandidate.id == candidate_id)
    if not is_super_admin(user):
        query = query.filter(FlowLinkCandidate.organization_id == user.organization_id)
    candidate = query.one_or_none()
    if candidate is None:
        raise HTTPException(status_code=404, detail=message("topology.link_candidate_not_found", user.locale))
    return candidate


@router.get("/link-candidates", response_model=list[FlowLinkCandidateOut])
def list_link_candidates(
    status: str | None = None,
    organization_id: int | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Fase 3 of the topology-accuracy roadmap -- see FlowLinkCandidate's
    docstring. Defaults to every status; pass status=pending to get just
    the review queue a UI would show."""
    query = db.query(FlowLinkCandidate)
    if is_super_admin(user):
        if organization_id is not None:
            query = query.filter(FlowLinkCandidate.organization_id == organization_id)
    else:
        query = query.filter(FlowLinkCandidate.organization_id == user.organization_id)
    if status is not None:
        query = query.filter(FlowLinkCandidate.status == status)
    return query.order_by(FlowLinkCandidate.confidence.desc()).all()


@router.post("/link-candidates/{candidate_id}/promote", response_model=NetworkLinkOut)
def promote_link_candidate(
    candidate_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)
):
    """The only way a FlowLinkCandidate ever becomes a real NetworkLink --
    always a human's explicit decision, never automatic (see
    FlowLinkCandidate's docstring on why: a Flow can always have a switch
    in the middle). Reuses topology_from_switch.upsert_link so a pre-
    existing *manual* link for this pair (asserted by a human through some
    other path in the meantime) still always wins -- that call returning
    False means nothing was promoted, surfaced as a 409 rather than
    silently marking this candidate confirmed for a link that didn't
    actually change."""
    candidate = _get_owned_candidate(db, user, candidate_id)
    if candidate.status != CANDIDATE_PENDING:
        raise HTTPException(status_code=409, detail=message("topology.link_candidate_already_resolved", user.locale))

    device_a = db.get(Device, candidate.device_a_id)
    device_b = db.get(Device, candidate.device_b_id)
    promoted = upsert_link(
        db,
        device_a,
        None,
        device_b,
        None,
        source=LINK_SOURCE_FLOW_CANDIDATE,
        notes="Promovido desde un candidato de enlace basado en Flow "
        "(ambos equipos confirmados por ARP en el mismo Sensor)",
    )
    if not promoted:
        raise HTTPException(status_code=409, detail=message("topology.link_candidate_already_resolved", user.locale))

    candidate.status = CANDIDATE_CONFIRMED
    db.commit()

    link = (
        db.query(NetworkLink)
        .filter(NetworkLink.device_a_id == candidate.device_a_id, NetworkLink.device_b_id == candidate.device_b_id)
        .one()
    )
    return link


@router.post("/link-candidates/{candidate_id}/dismiss", response_model=FlowLinkCandidateOut)
def dismiss_link_candidate(
    candidate_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)
):
    """A dismissed candidate is never resurrected by a later
    apply_flow_link_candidates pass -- a human's "no" is final, same
    principle as a manual NetworkLink always winning."""
    candidate = _get_owned_candidate(db, user, candidate_id)
    if candidate.status != CANDIDATE_PENDING:
        raise HTTPException(status_code=409, detail=message("topology.link_candidate_already_resolved", user.locale))
    candidate.status = CANDIDATE_DISMISSED
    db.commit()
    db.refresh(candidate)
    return candidate
