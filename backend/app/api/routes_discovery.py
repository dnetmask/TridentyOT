import json

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.routes_capture import _get_own_session, _get_owned_sensor, _sensor_organization_id
from app.api.routes_inventory import _get_own_device
from app.auth.deps import get_current_user, is_super_admin, require_admin
from app.capture.active_discovery import run_profinet_dcp_scan
from app.capture.nmap_discovery import nmap_scan_manager
from app.capture.snmp_discovery import expand_targets, snmp_scan_manager, snmp_walk_manager
from app.db import get_db, session_scope
from app.i18n import message
from app.models import (
    SENSOR_KIND_LIVE,
    CaptureSession,
    Device,
    Sensor,
    SwitchArpEntry,
    SwitchMacTableEntry,
    SwitchNeighborEntry,
    SwitchTableImport,
    User,
)
from app.schemas import (
    CaptureSessionOut,
    NmapScanRequest,
    ProfinetDcpScanRequest,
    SnmpScanRequest,
    SnmpSwitchWalkRequest,
    SwitchTableImportHistoryOut,
    SwitchTableImportOut,
    SwitchTableImportRequest,
    capture_session_out,
    switch_table_import_history_out,
)
from app.switch_table_parsers import parse_switch_table
from app.topology_from_switch import apply_arp_table, apply_mac_table, apply_neighbor_table

router = APIRouter(prefix="/api/discovery", tags=["discovery"])


def _resolve_live_sensor(db: Session, user: User, sensor_id: int) -> Sensor:
    """Active discovery always needs a real interface on this server to
    transmit/listen on -- an external Sensor (see SENSOR_KIND_EXTERNAL in
    models.py) has none, same constraint as starting a live capture."""
    sensor = _get_owned_sensor(db, user, sensor_id)
    if sensor.kind != SENSOR_KIND_LIVE:
        raise HTTPException(status_code=400, detail=message("discovery.sensor_must_be_live", user.locale))
    return sensor


def _run_profinet_dcp_background(capture_session_id: int, interface: str, duration_seconds: float) -> None:
    with session_scope() as db:
        capture_session = db.get(CaptureSession, capture_session_id)
        if capture_session is None:
            return
        run_profinet_dcp_scan(db, interface, duration_seconds, capture_session)


@router.post("/profinet-dcp", response_model=CaptureSessionOut)
def start_profinet_dcp_scan(
    payload: ProfinetDcpScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
):
    sensor = _resolve_live_sensor(db, user, payload.sensor_id)

    session_obj = CaptureSession(
        organization_id=_sensor_organization_id(db, sensor),
        sensor_id=sensor.id,
        name=f"discovery:profinet-dcp:{payload.interface}",
        source_type="active_pnio_dcp",
        source=payload.interface,
        status="running",
    )
    db.add(session_obj)
    db.commit()
    db.refresh(session_obj)

    background_tasks.add_task(
        _run_profinet_dcp_background, session_obj.id, payload.interface, payload.duration_seconds
    )
    return capture_session_out(session_obj, user.locale)


@router.post("/nmap", response_model=CaptureSessionOut)
def start_nmap_scan(
    payload: NmapScanRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
):
    sensor = _resolve_live_sensor(db, user, payload.sensor_id)

    session_obj = CaptureSession(
        organization_id=_sensor_organization_id(db, sensor),
        sensor_id=sensor.id,
        name=f"discovery:nmap:{payload.target}",
        source_type="active_nmap",
        source=payload.target,
        status="running",
    )
    db.add(session_obj)
    db.commit()
    db.refresh(session_obj)

    # No BackgroundTasks here, unlike PROFINET DCP: this scan has no fixed
    # end time and needs to be reachable afterwards for /nmap/stop/{id} --
    # nmap_scan_manager tracks the running subprocess by session id the
    # same way live_capture_manager tracks a running sniffer.
    #
    # sensor.interface (see Sensor model / PATCH /api/sensors/{id}) is the
    # whole point of letting a sensor's physical interface be edited: on a
    # host with more than one NIC, nmap must go out the one actually
    # connected to the OT segment being scanned, both to reach the right
    # network at all and because MAC/ARP discovery only works when the
    # target is layer-2 reachable from that interface.
    nmap_scan_manager.start(session_obj.id, payload.target, sensor.interface)
    return capture_session_out(session_obj, user.locale)


@router.post("/nmap/stop/{session_id}", response_model=CaptureSessionOut)
def stop_nmap_scan(session_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    session_obj = _get_own_session(db, user, session_id)
    if session_obj.source_type != "active_nmap":
        raise HTTPException(status_code=400, detail=message("discovery.not_an_nmap_session", user.locale))

    # Best-effort, same reasoning as live capture's own stop endpoint: if
    # this process isn't actually tracking a worker for it (e.g. the
    # server restarted since the scan started), there's nothing left to
    # terminate, but the row can still be reloaded to reflect whatever
    # mark_orphaned_live_sessions_stopped already did to it at startup.
    nmap_scan_manager.stop(session_id)
    db.refresh(session_obj)
    return capture_session_out(session_obj, user.locale)


@router.post("/snmp", response_model=CaptureSessionOut)
def start_snmp_scan(
    payload: SnmpScanRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
):
    sensor = _resolve_live_sensor(db, user, payload.sensor_id)

    # Validated (and the whole target range expanded to a concrete address
    # list) before the CaptureSession row is even created -- an invalid
    # CIDR or a target that's absurdly large (see snmp_discovery.
    # _MAX_TARGETS) should never leave behind a stray "running" session
    # that in fact never started.
    try:
        targets = expand_targets(payload.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    session_obj = CaptureSession(
        organization_id=_sensor_organization_id(db, sensor),
        sensor_id=sensor.id,
        name=f"discovery:snmp:{payload.target}",
        source_type="active_snmp",
        source=payload.target,
        status="running",
    )
    db.add(session_obj)
    db.commit()
    db.refresh(session_obj)

    # No BackgroundTasks here, same reasoning as nmap: no fixed end time,
    # and needs to stay reachable afterwards for /snmp/stop/{id}.
    snmp_scan_manager.start(session_obj.id, targets, payload.community, payload.version, sensor.interface)
    return capture_session_out(session_obj, user.locale)


@router.post("/snmp/stop/{session_id}", response_model=CaptureSessionOut)
def stop_snmp_scan(session_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    session_obj = _get_own_session(db, user, session_id)
    if session_obj.source_type != "active_snmp":
        raise HTTPException(status_code=400, detail=message("discovery.not_an_snmp_session", user.locale))

    snmp_scan_manager.stop(session_id)
    db.refresh(session_obj)
    return capture_session_out(session_obj, user.locale)


@router.post("/snmp/switch-walk", response_model=CaptureSessionOut)
def start_snmp_switch_walk(
    payload: SnmpSwitchWalkRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
):
    """Walks BRIDGE-MIB/IP-MIB/CDP-MIB/LLDP-MIB on each of `targets` (a
    short explicit list of switch IPs, never a CIDR -- see
    SnmpSwitchWalkRequest's docstring) and turns whatever it gets back into
    topology data via app/topology_from_switch.py, the same functions the
    manual import endpoint below calls. Progress is "switches walked so
    far" against len(targets), the same repurposing of
    CaptureSession.bytes_processed/total_bytes nmap already does for its
    own target count."""
    sensor = _resolve_live_sensor(db, user, payload.sensor_id)

    session_obj = CaptureSession(
        organization_id=_sensor_organization_id(db, sensor),
        sensor_id=sensor.id,
        name=f"discovery:snmp-switch-walk:{','.join(payload.targets)}",
        source_type="active_snmp_walk",
        source=",".join(payload.targets),
        status="running",
    )
    db.add(session_obj)
    db.commit()
    db.refresh(session_obj)

    snmp_walk_manager.start(session_obj.id, payload.targets, payload.community, payload.version)
    return capture_session_out(session_obj, user.locale)


@router.post("/snmp/switch-walk/stop/{session_id}", response_model=CaptureSessionOut)
def stop_snmp_switch_walk(session_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    session_obj = _get_own_session(db, user, session_id)
    if session_obj.source_type != "active_snmp_walk":
        raise HTTPException(status_code=400, detail=message("discovery.not_an_snmp_walk_session", user.locale))

    snmp_walk_manager.stop(session_id)
    db.refresh(session_obj)
    return capture_session_out(session_obj, user.locale)


@router.post("/switch-tables/import", response_model=SwitchTableImportOut)
def import_switch_table(
    payload: SwitchTableImportRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
):
    """The manual counterpart to the SNMP walk above -- same
    app/topology_from_switch.py apply_*() functions, fed by a human's
    paste instead of a live walk. See app/switch_table_parsers.py for what
    `vendor` selects."""
    switch = _get_own_device(db, user, payload.device_id)
    try:
        parsed_rows = parse_switch_table(payload.vendor, payload.table_type, payload.raw_text)
    except ValueError as exc:
        # Unknown vendor/table_type combination -- parse_switch_table's own
        # error already says exactly which, so it's safe to surface as-is.
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        # The per-vendor parsers are best-effort regexes over real-world CLI
        # paste, most of it never seen against a real device (see
        # switch_table_parsers.py's own docstring) -- an unrecognized line
        # shape should never bubble up as an opaque 500, only as "couldn't
        # parse this", so the user can fix the paste and retry.
        raise HTTPException(
            status_code=400, detail=message("discovery.switch_table_parse_failed", user.locale)
        ) from exc

    table_import = SwitchTableImport(
        organization_id=switch.organization_id,
        device_id=switch.id,
        table_type=payload.table_type,
        source="manual_paste",
        vendor=payload.vendor,
        raw_text=payload.raw_text,
        imported_by_user_id=user.id,
    )
    db.add(table_import)
    db.flush()  # need table_import.id before creating the child rows below

    result: dict = {}
    if payload.table_type == "mac_table":
        entries = [SwitchMacTableEntry(switch_table_import_id=table_import.id, **row) for row in parsed_rows]
        db.add_all(entries)
        db.flush()
        result = apply_mac_table(db, switch, entries)
    elif payload.table_type == "arp":
        entries = [SwitchArpEntry(switch_table_import_id=table_import.id, **row) for row in parsed_rows]
        db.add_all(entries)
        db.flush()
        result = apply_arp_table(db, switch.organization_id, entries)
    else:  # "neighbors"
        entries = [SwitchNeighborEntry(switch_table_import_id=table_import.id, **row) for row in parsed_rows]
        db.add_all(entries)
        db.flush()
        result = apply_neighbor_table(db, switch, entries)

    table_import.entries_parsed = len(parsed_rows)
    table_import.result_summary = json.dumps(result)
    db.commit()
    return SwitchTableImportOut(import_id=table_import.id, entries_parsed=len(parsed_rows), **result)


@router.get("/switch-tables/imports", response_model=list[SwitchTableImportHistoryOut])
def list_switch_table_imports(
    device_id: int | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """History for "Importar tabla manualmente" (and SNMP walks, same
    underlying SwitchTableImport row) -- see that model's own docstring on
    why result_summary is persisted instead of only ever existing in the
    single HTTP response the import itself returned."""
    query = db.query(SwitchTableImport)
    if not is_super_admin(user):
        query = query.filter(SwitchTableImport.organization_id == user.organization_id)
    if device_id is not None:
        query = query.filter(SwitchTableImport.device_id == device_id)
    imports = query.order_by(SwitchTableImport.created_at.desc()).all()

    # Bulk-resolved, not one query per row -- same reasoning as
    # routes_topology.py's _zone_by_capture_session_id.
    device_ids = {i.device_id for i in imports}
    devices_by_id = {d.id: d for d in db.query(Device).filter(Device.id.in_(device_ids)).all()} if device_ids else {}
    user_ids = {i.imported_by_user_id for i in imports if i.imported_by_user_id is not None}
    usernames_by_id = (
        {u.id: u.username for u in db.query(User).filter(User.id.in_(user_ids)).all()} if user_ids else {}
    )

    return [
        switch_table_import_history_out(
            i,
            device_name=(devices_by_id[i.device_id].display_name or f"device-{i.device_id}")
            if i.device_id in devices_by_id
            else f"device-{i.device_id}",
            imported_by=usernames_by_id.get(i.imported_by_user_id),
        )
        for i in imports
    ]
