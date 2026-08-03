from app.models import Device, DeviceProtocol
from app.vuln.rules import extract_banner_product_version, run_local_rules


def test_insecure_it_protocol_rule_fires_for_telnet(db_session):
    device = Device(ip="10.0.0.9")
    db_session.add(device)
    db_session.flush()
    db_session.add(
        DeviceProtocol(
            device_id=device.id, protocol="telnet", port=23, transport="tcp", role="server", category="IT"
        )
    )
    db_session.flush()
    db_session.refresh(device)

    findings = run_local_rules(device)
    assert any(f["rule_id"] == "insecure-protocol:telnet" and f["severity"] == "high" for f in findings)


def test_no_finding_for_ssh(db_session):
    device = Device(ip="10.0.0.11")
    db_session.add(device)
    db_session.flush()
    db_session.add(
        DeviceProtocol(device_id=device.id, protocol="ssh", port=22, transport="tcp", role="server", category="IT")
    )
    db_session.flush()
    db_session.refresh(device)

    findings = run_local_rules(device)
    assert findings == []


def test_ot_protocol_rule_fires_for_modbus(db_session):
    device = Device(ip="10.0.0.10", is_ot_suspected=True)
    db_session.add(device)
    db_session.flush()
    db_session.add(
        DeviceProtocol(device_id=device.id, protocol="modbus", port=502, transport="tcp", role="server", category="OT")
    )
    db_session.flush()
    db_session.refresh(device)

    findings = run_local_rules(device)
    assert any(f["rule_id"] == "ot-protocol-exposure:modbus" and f["severity"] == "high" for f in findings)


def test_ot_protocol_rule_fires_for_profinet_with_no_port(db_session):
    """PROFINET (pnio_ps/pn-dcp/pn-alarm) runs raw over Ethernet -- no port
    at all, unlike every other OT protocol here -- so the rule's title/
    evidence must degrade gracefully instead of literally saying "puerto
    None"."""
    device = Device(mac="00:1b:1b:aa:bb:cc", is_ot_suspected=True)
    db_session.add(device)
    db_session.flush()
    db_session.add(
        DeviceProtocol(
            device_id=device.id, protocol="pnio_ps", port=None, transport="profinet", role="server", category="OT"
        )
    )
    db_session.flush()
    db_session.refresh(device)

    findings = run_local_rules(device)
    finding = next(f for f in findings if f["rule_id"] == "ot-protocol-exposure:pnio_ps")
    assert finding["severity"] == "high"
    assert "None" not in finding["title"]
    assert "None" not in finding["evidence"]


def test_embedded_ot_stack_note(db_session):
    device = Device(ip="10.0.0.12", is_ot_suspected=True, os_signature="embedded_ot", os_guess="Embedded stack / RTOS", os_confidence=0.8)
    db_session.add(device)
    db_session.flush()
    db_session.refresh(device)

    findings = run_local_rules(device)
    assert any(f["rule_id"] == "embedded-ot-stack" for f in findings)


def test_extract_banner_product_version():
    assert extract_banner_product_version("SSH-2.0-OpenSSH_7.2") == ("OpenSSH", "7.2")
    assert extract_banner_product_version("220 (vsFTPd 2.3.4)") == ("vsftpd", "2.3.4")
    assert extract_banner_product_version("just some random text") is None
