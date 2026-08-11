from sqlalchemy.orm import Session

from app.i18n import bilingual, encode_i18n
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
                # cve["description"] is NVD's own English CVE text, passed
                # through as plain (non-i18n-encoded) text -- see
                # app.i18n.render_i18n's legacy/third-party fallback --
                # since translating arbitrary third-party vulnerability
                # descriptions is out of scope.
                description = cve["description"] or encode_i18n(
                    bilingual(
                        es=f"Ver detalles en NVD para {cve['cve_id']}.",
                        en=f"See NVD for details on {cve['cve_id']}.",
                    )
                )
                findings.append(
                    _persist_finding(
                        db_session,
                        device,
                        source="nvd",
                        cve_id=cve["cve_id"],
                        title=encode_i18n(
                            bilingual(
                                es=f"{cve['cve_id']} podría afectar a {keyword}",
                                en=f"{cve['cve_id']} may affect {keyword}",
                            )
                        ),
                        description=description,
                        severity=cve["severity"],
                        cvss_score=cve["cvss_score"],
                        evidence=encode_i18n(
                            bilingual(
                                es=f"Coincidencia por palabra clave de banner de servicio: '{keyword}'",
                                en=f"Match by service banner keyword: '{keyword}'",
                            )
                        ),
                    )
                )

    db_session.commit()
    return findings


def scan_all_devices(db_session: Session, organization_id: int, use_nvd: bool = True) -> list[VulnerabilityFinding]:
    findings: list[VulnerabilityFinding] = []
    for device in db_session.query(Device).filter(Device.organization_id == organization_id).all():
        findings.extend(scan_device(db_session, device, use_nvd=use_nvd))
    return findings
