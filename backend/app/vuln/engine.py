from sqlalchemy.orm import Session

from app.models import Device, VulnerabilityFinding
from app.vuln.nvd_client import search_nvd
from app.vuln.rules import extract_banner_product_version, run_local_rules


def _persist_finding(
    db_session: Session,
    device: Device,
    source: str,
    title: str,
    description: str,
    severity: str,
    rule_id: str | None = None,
    cve_id: str | None = None,
    cvss_score: float | None = None,
    evidence: str | None = None,
) -> VulnerabilityFinding:
    existing = (
        db_session.query(VulnerabilityFinding)
        .filter(
            VulnerabilityFinding.device_id == device.id,
            VulnerabilityFinding.rule_id == rule_id,
            VulnerabilityFinding.cve_id == cve_id,
        )
        .one_or_none()
    )
    if existing is not None:
        existing.title = title
        existing.description = description
        existing.severity = severity
        existing.cvss_score = cvss_score
        existing.evidence = evidence
        return existing

    finding = VulnerabilityFinding(
        device_id=device.id,
        source=source,
        rule_id=rule_id,
        cve_id=cve_id,
        title=title,
        description=description,
        severity=severity,
        cvss_score=cvss_score,
        evidence=evidence,
    )
    db_session.add(finding)
    db_session.flush()
    return finding


def scan_device(db_session: Session, device: Device, use_nvd: bool = True) -> list[VulnerabilityFinding]:
    findings: list[VulnerabilityFinding] = []

    for rule_finding in run_local_rules(device):
        findings.append(
            _persist_finding(
                db_session,
                device,
                source="rule",
                rule_id=rule_finding["rule_id"],
                title=rule_finding["title"],
                description=rule_finding["description"],
                severity=rule_finding["severity"],
                evidence=rule_finding.get("evidence"),
            )
        )

    if use_nvd:
        keywords: set[str] = set()
        for proto in device.protocols:
            product_version = extract_banner_product_version(proto.banner or "")
            if product_version:
                keywords.add(f"{product_version[0]} {product_version[1]}")

        for keyword in keywords:
            for cve in search_nvd(db_session, keyword):
                findings.append(
                    _persist_finding(
                        db_session,
                        device,
                        source="nvd",
                        cve_id=cve["cve_id"],
                        title=f"{cve['cve_id']} podría afectar a {keyword}",
                        description=cve["description"] or f"Ver detalles en NVD para {cve['cve_id']}.",
                        severity=cve["severity"],
                        cvss_score=cve["cvss_score"],
                        evidence=f"Coincidencia por palabra clave de banner de servicio: '{keyword}'",
                    )
                )

    db_session.commit()
    return findings


def scan_all_devices(db_session: Session, use_nvd: bool = True) -> list[VulnerabilityFinding]:
    findings: list[VulnerabilityFinding] = []
    for device in db_session.query(Device).all():
        findings.extend(scan_device(db_session, device, use_nvd=use_nvd))
    return findings
