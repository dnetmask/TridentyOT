"""Local, offline vulnerability rules derived from the observed protocol
mix and passive OS fingerprint of a device. These never require network
access, unlike the NVD-backed stage in engine.py.
"""

import re

from app.fingerprint.protocol_detect import INSECURE_PROTOCOL_NAMES, OT_PROTOCOLS
from app.models import Device

# Severity overrides for specific insecure IT protocols; anything insecure
# but not listed here defaults to "medium".
_IT_SEVERITY_OVERRIDES = {
    "telnet": "high",
    "ftp": "high",
    "ftp-data": "high",
    "tftp": "high",
    "rsh-syslog": "high",
    "rlogin": "high",
    "rexec": "high",
    "vnc": "high",
    "snmp": "medium",
    "snmp-trap": "medium",
    "http": "medium",
    "http-alt": "medium",
    "smb": "medium",
    "ldap": "medium",
    "mqtt": "medium",
    "nfs": "medium",
    "netbios-ns": "low",
    "netbios-dgm": "low",
    "netbios-ssn": "medium",
    "rpcbind": "low",
    "msrpc": "low",
}

_IT_DESCRIPTIONS = {
    "telnet": "Telnet transmite credenciales y comandos en texto claro y no ofrece autenticación fuerte.",
    "ftp": "FTP transmite credenciales y datos en texto claro.",
    "ftp-data": "Canal de datos FTP en texto claro asociado a un servicio FTP.",
    "tftp": "TFTP no tiene autenticación y transmite datos en texto claro; común en actualización de firmware OT, pero de alto riesgo si es accesible externamente.",
    "rsh-syslog": "rsh no cifra ni autentica de forma robusta la sesión remota.",
    "rlogin": "rlogin transmite credenciales en texto claro y confía en el host de origen.",
    "rexec": "rexec transmite usuario/contraseña en texto claro.",
    "vnc": "VNC frecuentemente se despliega con autenticación débil o sin cifrado de la sesión.",
    "snmp": "SNMP (v1/v2c, indistinguible por puerto) usa community strings en texto claro; usar SNMPv3.",
    "snmp-trap": "Traps SNMP en texto claro pueden revelar información operativa.",
    "http": "HTTP transmite datos, y a menudo credenciales, sin cifrar.",
    "http-alt": "Servicio HTTP en puerto alternativo sin cifrado detectado.",
    "smb": "SMB expuesto; verificar que SMBv1 esté deshabilitado (EternalBlue/WannaCry) y que no sea accesible fuera del segmento de confianza.",
    "ldap": "LDAP sin StartTLS/LDAPS transmite consultas y credenciales en texto claro.",
    "mqtt": "MQTT sin TLS y frecuentemente sin autenticación de cliente.",
    "nfs": "NFS clásico (v2/v3) depende del control de acceso por IP y no cifra el tráfico.",
    "netbios-ns": "Servicio NetBIOS heredado, superficie de ataque adicional en la red.",
    "netbios-dgm": "Servicio NetBIOS heredado, superficie de ataque adicional en la red.",
    "netbios-ssn": "Sesión NetBIOS heredada, frecuentemente ligada a SMBv1.",
    "rpcbind": "rpcbind/portmapper expone servicios RPC, históricamente usado en ataques de amplificación y enumeración.",
    "msrpc": "MSRPC expuesto en red; superficie relevante para movimiento lateral en Windows.",
}

_OT_DESCRIPTION_TEMPLATE = (
    "El protocolo OT/ICS '{protocol}' fue observado en este dispositivo. Este protocolo, "
    "como la mayoría del tráfico de control industrial tradicional, típicamente no incluye "
    "autenticación ni cifrado, por lo que cualquier host con acceso de red a este puerto puede "
    "leer o enviar comandos de control. Se recomienda segmentación de red estricta (VLAN/firewall "
    "dedicados), monitoreo pasivo y, si el fabricante lo soporta, habilitar las variantes seguras "
    "del protocolo (p. ej. DNP3 Secure Authentication, TLS para Modbus/TCP)."
)


def rule_insecure_it_protocols(device: Device) -> list[dict]:
    findings = []
    for proto in device.protocols:
        if proto.role != "server":
            continue
        if proto.protocol in OT_PROTOCOLS:
            continue
        if proto.protocol not in INSECURE_PROTOCOL_NAMES:
            continue
        severity = _IT_SEVERITY_OVERRIDES.get(proto.protocol, "medium")
        description = _IT_DESCRIPTIONS.get(
            proto.protocol, f"Protocolo '{proto.protocol}' considerado inseguro por diseño."
        )
        findings.append(
            {
                "rule_id": f"insecure-protocol:{proto.protocol}",
                "title": f"Protocolo inseguro detectado: {proto.protocol} (puerto {proto.port})",
                "description": description,
                "severity": severity,
                "evidence": f"Servicio '{proto.protocol}' visto en {proto.transport}/{proto.port}, "
                f"{proto.packet_count} paquete(s), banner: {proto.banner or 'n/d'}",
            }
        )
    return findings


def rule_unauthenticated_ot_protocols(device: Device) -> list[dict]:
    findings = []
    for proto in device.protocols:
        if proto.role != "server" or proto.protocol not in OT_PROTOCOLS:
            continue
        # PROFINET (pnio_ps/pn-dcp/pn-alarm) has no port at all -- it runs
        # raw over Ethernet, not IP/UDP -- so proto.port is None for it,
        # unlike every port-based OT protocol above.
        port_label = proto.port if proto.port is not None else "N/D"
        findings.append(
            {
                "rule_id": f"ot-protocol-exposure:{proto.protocol}",
                "title": f"Protocolo OT sin autenticación/cifrado expuesto: {proto.protocol} (puerto {port_label})",
                "description": _OT_DESCRIPTION_TEMPLATE.format(protocol=proto.protocol),
                "severity": "high",
                "evidence": f"Servicio OT '{proto.protocol}' visto en {proto.transport}/{port_label}, "
                f"{proto.packet_count} paquete(s).",
            }
        )
    return findings


def rule_embedded_ot_device(device: Device) -> list[dict]:
    if device.os_signature != "embedded_ot" or not device.is_ot_suspected:
        return []
    return [
        {
            "rule_id": "embedded-ot-stack",
            "title": "Dispositivo con pila de red embebida (posible PLC/RTU/sensor OT)",
            "description": (
                "El fingerprint pasivo TCP (TTL, ventana, opciones) es compatible con una pila de red "
                "embebida/RTOS típica de PLCs, RTUs u otros dispositivos de campo OT, en lugar de un SO "
                "de propósito general. Verificar el firmware del fabricante, aplicar parches disponibles "
                "y confirmar que el dispositivo esté en un segmento de red aislado de IT."
            ),
            "severity": "info",
            "evidence": f"Fingerprint OS: {device.os_guess} (confianza {device.os_confidence})",
        }
    ]


RULES = (rule_insecure_it_protocols, rule_unauthenticated_ot_protocols, rule_embedded_ot_device)


def run_local_rules(device: Device) -> list[dict]:
    findings: list[dict] = []
    for rule in RULES:
        findings.extend(rule(device))
    return findings


_BANNER_PATTERNS = [
    (re.compile(r"OpenSSH[_/]?(?P<ver>[\d.]+p?\d*)", re.IGNORECASE), "OpenSSH"),
    (re.compile(r"vsftpd\s*(?P<ver>[\d.]+)", re.IGNORECASE), "vsftpd"),
    (re.compile(r"ProFTPD\s*(?P<ver>[\d.]+)", re.IGNORECASE), "ProFTPD"),
    (re.compile(r"Apache/(?P<ver>[\d.]+)", re.IGNORECASE), "Apache httpd"),
    (re.compile(r"nginx/(?P<ver>[\d.]+)", re.IGNORECASE), "nginx"),
    (re.compile(r"Microsoft-IIS/(?P<ver>[\d.]+)", re.IGNORECASE), "Microsoft IIS"),
]


def extract_banner_product_version(banner: str) -> tuple[str, str] | None:
    """Best-effort product/version extraction from a captured service banner,
    used to build NVD keyword searches. Returns None when no known pattern matches."""
    if not banner:
        return None
    for pattern, product in _BANNER_PATTERNS:
        match = pattern.search(banner)
        if match:
            version = match.groupdict().get("ver")
            if version:
                return product, version
    return None
