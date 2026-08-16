"""Turns a switch's own reported tables (MAC address table, ARP table,
CDP/LLDP neighbors -- see app/models.py's SwitchMacTableEntry/
SwitchArpEntry/SwitchNeighborEntry) into real topology data: NetworkLink
rows for mac_table/neighbors, plain Device enrichment for arp.

Fed by two callers that both land here after parsing their own input into
the same child rows: a manual paste (app/switch_table_parsers.py, via
POST /api/discovery/switch-tables/import) and a live SNMP walk
(app/capture/snmp_discovery.py's _SnmpWalkWorker) -- neither one duplicates
this logic.
"""

from sqlalchemy.orm import Session

from app.fingerprint.device_classifier import NETWORK_DEVICE, SWITCH_L2, classify_device_type
from app.i18n import bilingual, encode_i18n
from app.models import LINK_CONFIRMED, LINK_SOURCE_CDP, LINK_SOURCE_LLDP, LINK_SOURCE_MAC_TABLE, LINK_SOURCE_MANUAL
from app.models import Device, NetworkLink, SwitchArpEntry, SwitchMacTableEntry, SwitchNeighborEntry

_NEIGHBOR_LINK_SOURCE = {"cdp": LINK_SOURCE_CDP, "lldp": LINK_SOURCE_LLDP}


def upsert_link(
    db: Session, device_x: Device, port_x: str | None, device_y: Device, port_y: str | None, *, source: str, notes: str
) -> bool:
    """Upserts a NetworkLink for (device_x, device_y), normalizing a/b by
    id the same way POST /api/topology/links does (see routes_topology.py's
    create_network_link) -- ports travel with whichever device they
    actually belong to across that swap. Returns False, doing nothing,
    when device_x/device_y are the same row (a switch never links to
    itself) or when a human's own NetworkLink already exists for this pair
    -- that always wins over anything derived here, per NetworkLink's own
    docstring."""
    if device_x.id == device_y.id:
        return False
    if device_x.id < device_y.id:
        device_a, port_a, device_b, port_b = device_x, port_x, device_y, port_y
    else:
        device_a, port_a, device_b, port_b = device_y, port_y, device_x, port_x

    existing = (
        db.query(NetworkLink)
        .filter(NetworkLink.device_a_id == device_a.id, NetworkLink.device_b_id == device_b.id)
        .one_or_none()
    )
    if existing is not None and existing.source == LINK_SOURCE_MANUAL:
        return False

    link = existing or NetworkLink(
        organization_id=device_a.organization_id, device_a_id=device_a.id, device_b_id=device_b.id
    )
    link.source_port = port_a
    link.target_port = port_b
    link.status = LINK_CONFIRMED
    link.source = source
    link.notes = notes
    if existing is None:
        db.add(link)
    return True


def apply_mac_table(db: Session, switch: Device, entries: list[SwitchMacTableEntry]) -> dict:
    """A port that shows exactly one MAC gets a NetworkLink to whatever
    Device owns that MAC (if it's in inventory at all -- an unknown MAC
    produces neither a Device nor a link, same "don't invent one" stance as
    neighbors below, but IS reported back as unmatched so a 0-link result
    doesn't read as "nothing happened" when the table was in fact read
    correctly). A port with more than one MAC is the classic switch-to-
    switch uplink signature -- reported as a suspected uplink instead of
    guessed at, since a MAC table alone can't say *which* other switch it
    goes to (that's what CDP/LLDP is for)."""
    by_interface: dict[str, set[str]] = {}
    for entry in entries:
        by_interface.setdefault(entry.interface_name, set()).add(entry.mac)

    links_created_or_updated = 0
    suspected_uplinks = []
    unmatched_macs = []
    for interface_name, macs in by_interface.items():
        if len(macs) > 1:
            suspected_uplinks.append({"interface": interface_name, "mac_count": len(macs)})
            continue
        (mac,) = macs
        other = (
            db.query(Device)
            .filter(Device.organization_id == switch.organization_id, Device.mac == mac)
            .one_or_none()
        )
        if other is None:
            unmatched_macs.append({"interface": interface_name, "mac": mac})
            continue
        if upsert_link(
            db, switch, interface_name, other, None,
            source=LINK_SOURCE_MAC_TABLE, notes="Detectado por tabla de direcciones MAC",
        ):
            links_created_or_updated += 1

    return {
        "links_created_or_updated": links_created_or_updated,
        "suspected_uplinks": suspected_uplinks,
        "unmatched_macs": unmatched_macs,
    }


def apply_arp_table(db: Session, organization_id: int, entries: list[SwitchArpEntry]) -> dict:
    """Never touches NetworkLink -- an ARP entry is an IP-to-MAC binding
    the switch happened to observe, not evidence of a physical link. Only
    ever fills a currently-empty Device.ip/mac (from whichever side of the
    pair we already know the device by); never overwrites a value that's
    already there, since that could just as easily be a stale ARP cache
    entry pointing at the wrong thing."""
    devices_enriched = 0
    for entry in entries:
        device = (
            db.query(Device)
            .filter(Device.organization_id == organization_id, Device.mac == entry.mac)
            .one_or_none()
        )
        if device is not None and not device.ip:
            device.ip = entry.ip
            devices_enriched += 1
            continue
        device = (
            db.query(Device)
            .filter(Device.organization_id == organization_id, Device.ip == entry.ip)
            .one_or_none()
        )
        if device is not None and not device.mac:
            device.mac = entry.mac
            devices_enriched += 1

    return {"devices_enriched": devices_enriched}


def apply_neighbor_table(db: Session, switch: Device, entries: list[SwitchNeighborEntry]) -> dict:
    """Each entry is the switch's own claim about its direct neighbor --
    the strongest signal this app has for a real link, since it names both
    the local and the remote port directly instead of inferring anything
    (unlike a MAC table's multi-MAC uplink, which is genuinely ambiguous
    about *which* other switch it goes to). That's strong enough evidence
    to act on without a human confirming it first: a neighbor that can't
    be matched to an existing Device (by name/hostname or its reported
    management IP) gets auto-created -- inheriting the switch's own
    capture_session_id so it shows up in the same Zona/Sitio-scoped views
    the switch itself does -- and linked immediately, instead of only
    being reported for the user to create manually and reimport.

    Being on a switch's neighbor table only proves *a link to this port*,
    not that the neighbor is itself a switch/router -- CDP/LLDP is spoken
    by end devices too (a PC, a PLC's engineering port, an IP phone, ...),
    and entry.remote_platform (the neighbor's own self-reported product
    string, e.g. a CDP Platform TLV) is exactly the kind of evidence
    classify_device_type already knows how to read. network_device is
    only the fallback when that evidence doesn't say otherwise -- still
    the common case for an unresolved neighbor on an uplink port, but at
    a deliberately lower confidence than a real match, so a later, better-
    evidenced guess (apply_device_type_guess, once real traffic from this
    MAC is seen) can still override it.
    """
    links_created_or_updated = 0
    devices_created = []
    for entry in entries:
        query = db.query(Device).filter(Device.organization_id == switch.organization_id, Device.id != switch.id)
        candidates = [
            d
            for d in query.all()
            if (d.custom_name and d.custom_name.lower() == entry.remote_device_name.lower())
            or (d.hostname and d.hostname.lower() == entry.remote_device_name.lower())
            or (entry.remote_mgmt_ip and d.ip == entry.remote_mgmt_ip)
        ]
        other = candidates[0] if candidates else None
        if other is None:
            guess = classify_device_type(
                vendor=None,
                hostname=entry.remote_device_name,
                model=entry.remote_platform,
                os_signature=None,
                has_ot_server_protocol=False,
                server_protocol_count=0,
            )
            if guess.confidence > 0:
                device_type = guess.device_type
                device_type_secondary = guess.device_type_secondary or (SWITCH_L2 if device_type == NETWORK_DEVICE else None)
                device_type_confidence = guess.confidence
                evidence_items = list(guess.evidence)
            else:
                device_type = NETWORK_DEVICE
                device_type_secondary = SWITCH_L2
                device_type_confidence = 0.5
                evidence_items = []
            evidence_items.append(
                bilingual(
                    es=f"Creado automáticamente: vecino {entry.protocol.upper()} de "
                    f"{switch.display_name or f'device-{switch.id}'} ({entry.local_port or '?'})",
                    en=f"Auto-created: {entry.protocol.upper()} neighbor of "
                    f"{switch.display_name or f'device-{switch.id}'} ({entry.local_port or '?'})",
                )
            )
            other = Device(
                organization_id=switch.organization_id,
                capture_session_id=switch.capture_session_id,
                custom_name=entry.remote_device_name,
                ip=entry.remote_mgmt_ip,
                model=entry.remote_platform,
                device_type=device_type,
                device_type_secondary=device_type_secondary,
                device_type_confidence=device_type_confidence,
                device_type_evidence=encode_i18n(*evidence_items),
            )
            db.add(other)
            db.flush()  # need other.id before it can be a NetworkLink endpoint below
            devices_created.append({"id": other.id, "name": entry.remote_device_name})
        source = _NEIGHBOR_LINK_SOURCE[entry.protocol]
        notes = f"Detectado vía {entry.protocol.upper()}"
        if upsert_link(db, switch, entry.local_port, other, entry.remote_port, source=source, notes=notes):
            links_created_or_updated += 1

    return {"links_created_or_updated": links_created_or_updated, "devices_created": devices_created}
