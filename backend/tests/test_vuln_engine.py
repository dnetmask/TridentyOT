from app.models import Device, DeviceProtocol, VulnerabilityFinding
from app.vuln import engine as vuln_engine


def test_scan_device_persists_rule_and_nvd_findings_without_duplicating(db_session, monkeypatch):
    device = Device(ip="10.0.0.77")
    db_session.add(device)
    db_session.flush()
    db_session.add(
        DeviceProtocol(
            device_id=device.id,
            protocol="ftp",
            port=21,
            transport="tcp",
            role="server",
            category="IT",
            banner="220 (vsFTPd 2.3.4)",
        )
    )
    db_session.commit()
    db_session.refresh(device)

    monkeypatch.setattr(
        vuln_engine,
        "search_nvd",
        lambda db, keyword, max_results=5: [
            {"cve_id": "CVE-2011-2523", "description": "backdoor", "cvss_score": 10.0, "severity": "critical"}
        ],
    )

    findings_first = vuln_engine.scan_device(db_session, device, use_nvd=True)
    assert len(findings_first) == 2  # insecure-protocol rule + 1 NVD CVE
    assert any(f.source == "rule" for f in findings_first)
    assert any(f.source == "nvd" and f.cve_id == "CVE-2011-2523" for f in findings_first)

    count_after_first = db_session.query(VulnerabilityFinding).filter(VulnerabilityFinding.device_id == device.id).count()
    assert count_after_first == 2

    vuln_engine.scan_device(db_session, device, use_nvd=True)
    count_after_second = db_session.query(VulnerabilityFinding).filter(VulnerabilityFinding.device_id == device.id).count()
    assert count_after_second == 2  # re-scanning updates in place, does not duplicate


def test_scan_device_without_nvd_only_runs_local_rules(db_session, monkeypatch):
    device = Device(ip="10.0.0.78")
    db_session.add(device)
    db_session.flush()
    db_session.add(
        DeviceProtocol(device_id=device.id, protocol="telnet", port=23, transport="tcp", role="server", category="IT")
    )
    db_session.commit()
    db_session.refresh(device)

    def fail_if_called(*args, **kwargs):
        raise AssertionError("search_nvd should not be called when use_nvd=False")

    monkeypatch.setattr(vuln_engine, "search_nvd", fail_if_called)

    findings = vuln_engine.scan_device(db_session, device, use_nvd=False)
    assert len(findings) == 1
    assert findings[0].source == "rule"
