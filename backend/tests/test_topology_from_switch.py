"""Tests for app/topology_from_switch.py -- the shared logic behind both
the manual table import (POST /api/discovery/switch-tables/import) and the
SNMP walk (_SnmpWalkWorker), applying parsed switch-table rows onto
NetworkLink/Device. See that module's docstring and app/models.py's
SwitchMacTableEntry/SwitchArpEntry/SwitchNeighborEntry.
"""

from app.models import (
    LINK_SOURCE_CDP,
    LINK_SOURCE_MAC_TABLE,
    LINK_SOURCE_MANUAL,
    NetworkLink,
    SwitchArpEntry,
    SwitchMacTableEntry,
    SwitchNeighborEntry,
)
from app.topology_from_switch import apply_arp_table, apply_mac_table, apply_neighbor_table


def _make_device(db_session, org_id, **overrides):
    from app.models import Device

    defaults = dict(organization_id=org_id, ip=None, mac=None)
    defaults.update(overrides)
    device = Device(**defaults)
    db_session.add(device)
    db_session.commit()
    db_session.refresh(device)
    return device


def test_apply_mac_table_creates_link_for_single_mac_port(db_session, org_id):
    switch = _make_device(db_session, org_id, custom_name="switch-1")
    plc = _make_device(db_session, org_id, mac="00:11:22:33:44:55", ip="10.0.1.10")

    entries = [SwitchMacTableEntry(switch_table_import_id=0, mac="00:11:22:33:44:55", interface_name="Gi0/1")]
    result = apply_mac_table(db_session, switch, entries)
    db_session.commit()

    assert result["links_created_or_updated"] == 1
    assert result["suspected_uplinks"] == []
    link = db_session.query(NetworkLink).one()
    assert {link.device_a_id, link.device_b_id} == {switch.id, plc.id}
    assert link.source == LINK_SOURCE_MAC_TABLE
    # Whichever side is device_a gets the switch's port; the other side
    # (the device with no known port on the switch's own MAC table) is None.
    if link.device_a_id == switch.id:
        assert link.source_port == "Gi0/1" and link.target_port is None
    else:
        assert link.target_port == "Gi0/1" and link.source_port is None


def test_apply_mac_table_flags_multi_mac_port_as_suspected_uplink_without_a_link(db_session, org_id):
    switch = _make_device(db_session, org_id, custom_name="switch-1")
    _make_device(db_session, org_id, mac="00:11:22:33:44:55")
    _make_device(db_session, org_id, mac="00:11:22:33:44:66")

    entries = [
        SwitchMacTableEntry(switch_table_import_id=0, mac="00:11:22:33:44:55", interface_name="Gi0/2"),
        SwitchMacTableEntry(switch_table_import_id=0, mac="00:11:22:33:44:66", interface_name="Gi0/2"),
    ]
    result = apply_mac_table(db_session, switch, entries)

    assert result["links_created_or_updated"] == 0
    assert result["suspected_uplinks"] == [{"interface": "Gi0/2", "mac_count": 2}]
    assert db_session.query(NetworkLink).count() == 0


def test_apply_mac_table_reports_unknown_mac_without_a_link(db_session, org_id):
    """An unmatched MAC creates neither a Device nor a link (same "don't
    invent one" stance as an unresolved neighbor), but must still be
    reported back -- otherwise a real, correctly-parsed table with every
    port pointing at gear that isn't in inventory yet reads as "0 links,
    nothing happened" instead of "read fine, nothing to match against"."""
    switch = _make_device(db_session, org_id, custom_name="switch-1")
    entries = [SwitchMacTableEntry(switch_table_import_id=0, mac="aa:bb:cc:dd:ee:ff", interface_name="Gi0/3")]
    result = apply_mac_table(db_session, switch, entries)

    assert result["links_created_or_updated"] == 0
    assert result["unmatched_macs"] == [{"interface": "Gi0/3", "mac": "aa:bb:cc:dd:ee:ff"}]
    assert db_session.query(NetworkLink).count() == 0


def test_apply_mac_table_never_overwrites_a_manual_link(db_session, org_id):
    switch = _make_device(db_session, org_id, custom_name="switch-1")
    plc = _make_device(db_session, org_id, mac="00:11:22:33:44:55")
    a, b = sorted((switch, plc), key=lambda d: d.id)
    manual_link = NetworkLink(
        organization_id=org_id, device_a_id=a.id, device_b_id=b.id,
        source=LINK_SOURCE_MANUAL, source_port="manual-port",
    )
    db_session.add(manual_link)
    db_session.commit()

    entries = [SwitchMacTableEntry(switch_table_import_id=0, mac="00:11:22:33:44:55", interface_name="Gi0/9")]
    result = apply_mac_table(db_session, switch, entries)
    db_session.commit()

    assert result["links_created_or_updated"] == 0
    link = db_session.query(NetworkLink).one()
    assert link.source == LINK_SOURCE_MANUAL
    assert link.source_port == "manual-port"


def test_apply_arp_table_fills_empty_ip_but_never_overwrites(db_session, org_id):
    from app.models import Device

    device_no_ip = _make_device(db_session, org_id, mac="00:11:22:33:44:55")
    device_has_ip = _make_device(db_session, org_id, mac="00:11:22:33:44:66", ip="10.0.0.9")

    entries = [
        SwitchArpEntry(switch_table_import_id=0, ip="10.0.1.10", mac="00:11:22:33:44:55"),
        SwitchArpEntry(switch_table_import_id=0, ip="10.0.1.20", mac="00:11:22:33:44:66"),
    ]
    result = apply_arp_table(db_session, org_id, entries)
    db_session.commit()

    assert result["devices_enriched"] == 1
    db_session.refresh(device_no_ip)
    db_session.refresh(device_has_ip)
    assert device_no_ip.ip == "10.0.1.10"
    assert device_has_ip.ip == "10.0.0.9"  # untouched


def test_apply_arp_table_fills_empty_mac_from_ip_match(db_session, org_id):
    device = _make_device(db_session, org_id, ip="10.0.1.30")
    entries = [SwitchArpEntry(switch_table_import_id=0, ip="10.0.1.30", mac="00:11:22:33:44:77")]
    result = apply_arp_table(db_session, org_id, entries)
    db_session.commit()

    assert result["devices_enriched"] == 1
    db_session.refresh(device)
    assert device.mac == "00:11:22:33:44:77"


def test_apply_neighbor_table_creates_link_with_both_ports_for_known_neighbor(db_session, org_id):
    switch_a = _make_device(db_session, org_id, custom_name="switch-a")
    switch_b = _make_device(db_session, org_id, custom_name="switch-b")

    entries = [
        SwitchNeighborEntry(
            switch_table_import_id=0, protocol="cdp", local_port="Gi0/1",
            remote_device_name="switch-b", remote_port="Gi0/24", remote_mgmt_ip=None, remote_platform=None,
        )
    ]
    result = apply_neighbor_table(db_session, switch_a, entries)
    db_session.commit()

    assert result["links_created_or_updated"] == 1
    assert result["unresolved_neighbors"] == []
    link = db_session.query(NetworkLink).one()
    assert link.source == LINK_SOURCE_CDP
    assert {link.device_a_id, link.device_b_id} == {switch_a.id, switch_b.id}
    ports = {link.source_port, link.target_port}
    assert ports == {"Gi0/1", "Gi0/24"}


def test_apply_neighbor_table_matches_by_management_ip(db_session, org_id):
    switch_a = _make_device(db_session, org_id, custom_name="switch-a")
    switch_b = _make_device(db_session, org_id, ip="192.168.1.1")

    entries = [
        SwitchNeighborEntry(
            switch_table_import_id=0, protocol="lldp", local_port="Gi0/1",
            remote_device_name="unrecognized-name", remote_port="Gi0/2",
            remote_mgmt_ip="192.168.1.1", remote_platform=None,
        )
    ]
    result = apply_neighbor_table(db_session, switch_a, entries)
    db_session.commit()

    assert result["links_created_or_updated"] == 1
    link = db_session.query(NetworkLink).one()
    assert switch_b.id in (link.device_a_id, link.device_b_id)


def test_apply_neighbor_table_reports_unresolved_neighbor_without_creating_device(db_session, org_id):
    from app.models import Device

    switch = _make_device(db_session, org_id, custom_name="switch-a")
    before_count = db_session.query(Device).count()

    entries = [
        SwitchNeighborEntry(
            switch_table_import_id=0, protocol="lldp", local_port="Gi0/1",
            remote_device_name="mystery-switch", remote_port="Gi0/2",
            remote_mgmt_ip=None, remote_platform=None,
        )
    ]
    result = apply_neighbor_table(db_session, switch, entries)

    assert result["links_created_or_updated"] == 0
    assert result["unresolved_neighbors"] == [
        {
            "remote_device_name": "mystery-switch",
            "local_port": "Gi0/1",
            "remote_port": "Gi0/2",
            "remote_mgmt_ip": None,
            "remote_platform": None,
        }
    ]
    assert db_session.query(Device).count() == before_count
