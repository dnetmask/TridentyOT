"""Local, offline vulnerability rules derived from the observed protocol
mix and passive OS fingerprint of a device. These never require network
access, unlike the NVD-backed stage in engine.py.
"""

import re

from app.fingerprint.protocol_detect import INSECURE_PROTOCOL_NAMES, OT_PROTOCOLS
from app.i18n import bilingual, encode_i18n
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
    "telnet": bilingual(
        es="Telnet transmite credenciales y comandos en texto claro y no ofrece autenticación fuerte.",
        en="Telnet transmits credentials and commands in cleartext and offers no strong authentication.",
    ),
    "ftp": bilingual(
        es="FTP transmite credenciales y datos en texto claro.",
        en="FTP transmits credentials and data in cleartext.",
    ),
    "ftp-data": bilingual(
        es="Canal de datos FTP en texto claro asociado a un servicio FTP.",
        en="Cleartext FTP data channel associated with an FTP service.",
    ),
    "tftp": bilingual(
        es="TFTP no tiene autenticación y transmite datos en texto claro; común en actualización de firmware OT, "
        "pero de alto riesgo si es accesible externamente.",
        en="TFTP has no authentication and transmits data in cleartext; common for OT firmware updates, but "
        "high risk if reachable from outside its intended segment.",
    ),
    "rsh-syslog": bilingual(
        es="rsh no cifra ni autentica de forma robusta la sesión remota.",
        en="rsh neither encrypts nor robustly authenticates the remote session.",
    ),
    "rlogin": bilingual(
        es="rlogin transmite credenciales en texto claro y confía en el host de origen.",
        en="rlogin transmits credentials in cleartext and trusts the originating host.",
    ),
    "rexec": bilingual(
        es="rexec transmite usuario/contraseña en texto claro.",
        en="rexec transmits username/password in cleartext.",
    ),
    "vnc": bilingual(
        es="VNC frecuentemente se despliega con autenticación débil o sin cifrado de la sesión.",
        en="VNC is frequently deployed with weak authentication or no session encryption.",
    ),
    "snmp": bilingual(
        es="SNMP (v1/v2c, indistinguible por puerto) usa community strings en texto claro; usar SNMPv3.",
        en="SNMP (v1/v2c, indistinguishable by port alone) uses cleartext community strings; use SNMPv3 instead.",
    ),
    "snmp-trap": bilingual(
        es="Traps SNMP en texto claro pueden revelar información operativa.",
        en="Cleartext SNMP traps can leak operational information.",
    ),
    "http": bilingual(
        es="HTTP transmite datos, y a menudo credenciales, sin cifrar.",
        en="HTTP transmits data -- often credentials -- unencrypted.",
    ),
    "http-alt": bilingual(
        es="Servicio HTTP en puerto alternativo sin cifrado detectado.",
        en="HTTP service detected on an alternate port, unencrypted.",
    ),
    "smb": bilingual(
        es="SMB expuesto; verificar que SMBv1 esté deshabilitado (EternalBlue/WannaCry) y que no sea accesible "
        "fuera del segmento de confianza.",
        en="SMB exposed; verify SMBv1 is disabled (EternalBlue/WannaCry) and that it isn't reachable from "
        "outside the trusted segment.",
    ),
    "ldap": bilingual(
        es="LDAP sin StartTLS/LDAPS transmite consultas y credenciales en texto claro.",
        en="LDAP without StartTLS/LDAPS transmits queries and credentials in cleartext.",
    ),
    "mqtt": bilingual(
        es="MQTT sin TLS y frecuentemente sin autenticación de cliente.",
        en="MQTT without TLS and frequently without client authentication.",
    ),
    "nfs": bilingual(
        es="NFS clásico (v2/v3) depende del control de acceso por IP y no cifra el tráfico.",
        en="Classic NFS (v2/v3) relies on IP-based access control and doesn't encrypt traffic.",
    ),
    "netbios-ns": bilingual(
        es="Servicio NetBIOS heredado, superficie de ataque adicional en la red.",
        en="Legacy NetBIOS service, additional attack surface on the network.",
    ),
    "netbios-dgm": bilingual(
        es="Servicio NetBIOS heredado, superficie de ataque adicional en la red.",
        en="Legacy NetBIOS service, additional attack surface on the network.",
    ),
    "netbios-ssn": bilingual(
        es="Sesión NetBIOS heredada, frecuentemente ligada a SMBv1.",
        en="Legacy NetBIOS session, frequently tied to SMBv1.",
    ),
    "rpcbind": bilingual(
        es="rpcbind/portmapper expone servicios RPC, históricamente usado en ataques de amplificación y "
        "enumeración.",
        en="rpcbind/portmapper exposes RPC services, historically used in amplification and enumeration attacks.",
    ),
    "msrpc": bilingual(
        es="MSRPC expuesto en red; superficie relevante para movimiento lateral en Windows.",
        en="MSRPC exposed on the network; relevant surface for lateral movement on Windows.",
    ),
}

_OT_DESCRIPTION_TEMPLATE_ES = (
    "El protocolo OT/ICS '{protocol}' fue observado en este dispositivo. Este protocolo, "
    "como la mayoría del tráfico de control industrial tradicional, típicamente no incluye "
    "autenticación ni cifrado, por lo que cualquier host con acceso de red a este puerto puede "
    "leer o enviar comandos de control. Se recomienda segmentación de red estricta (VLAN/firewall "
    "dedicados), monitoreo pasivo y, si el fabricante lo soporta, habilitar las variantes seguras "
    "del protocolo (p. ej. DNP3 Secure Authentication, TLS para Modbus/TCP)."
)
_OT_DESCRIPTION_TEMPLATE_EN = (
    "The OT/ICS protocol '{protocol}' was observed on this device. Like most traditional industrial "
    "control traffic, this protocol typically includes neither authentication nor encryption, so any "
    "host with network access to this port can read or send control commands. Strict network "
    "segmentation (dedicated VLAN/firewall), passive monitoring, and -- where the vendor supports it -- "
    "enabling the protocol's secure variant (e.g. DNP3 Secure Authentication, TLS for Modbus/TCP) are "
    "recommended."
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
            proto.protocol,
            bilingual(
                es=f"Protocolo '{proto.protocol}' considerado inseguro por diseño.",
                en=f"Protocol '{proto.protocol}' is considered insecure by design.",
            ),
        )
        findings.append(
            {
                "rule_id": f"insecure-protocol:{proto.protocol}",
                "title": encode_i18n(
                    bilingual(
                        es=f"Protocolo inseguro detectado: {proto.protocol} (puerto {proto.port})",
                        en=f"Insecure protocol detected: {proto.protocol} (port {proto.port})",
                    )
                ),
                "description": encode_i18n(description),
                "severity": severity,
                "evidence": encode_i18n(
                    bilingual(
                        es=f"Servicio '{proto.protocol}' visto en {proto.transport}/{proto.port}, "
                        f"{proto.packet_count} paquete(s), banner: {proto.banner or 'n/d'}",
                        en=f"Service '{proto.protocol}' seen on {proto.transport}/{proto.port}, "
                        f"{proto.packet_count} packet(s), banner: {proto.banner or 'n/a'}",
                    )
                ),
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
                "title": encode_i18n(
                    bilingual(
                        es=f"Protocolo OT sin autenticación/cifrado expuesto: {proto.protocol} (puerto {port_label})",
                        en=f"Unauthenticated/unencrypted OT protocol exposed: {proto.protocol} (port {port_label})",
                    )
                ),
                "description": encode_i18n(
                    bilingual(
                        es=_OT_DESCRIPTION_TEMPLATE_ES.format(protocol=proto.protocol),
                        en=_OT_DESCRIPTION_TEMPLATE_EN.format(protocol=proto.protocol),
                    )
                ),
                "severity": "high",
                "evidence": encode_i18n(
                    bilingual(
                        es=f"Servicio OT '{proto.protocol}' visto en {proto.transport}/{port_label}, "
                        f"{proto.packet_count} paquete(s).",
                        en=f"OT service '{proto.protocol}' seen on {proto.transport}/{port_label}, "
                        f"{proto.packet_count} packet(s).",
                    )
                ),
            }
        )
    return findings


def rule_embedded_ot_device(device: Device) -> list[dict]:
    if device.os_signature != "embedded_ot" or not device.is_ot_suspected:
        return []
    return [
        {
            "rule_id": "embedded-ot-stack",
            "title": encode_i18n(
                bilingual(
                    es="Dispositivo con pila de red embebida (posible PLC/RTU/sensor OT)",
                    en="Device with an embedded network stack (possible PLC/RTU/OT sensor)",
                )
            ),
            "description": encode_i18n(
                bilingual(
                    es="El fingerprint pasivo TCP (TTL, ventana, opciones) es compatible con una pila de red "
                    "embebida/RTOS típica de PLCs, RTUs u otros dispositivos de campo OT, en lugar de un SO "
                    "de propósito general. Verificar el firmware del fabricante, aplicar parches disponibles "
                    "y confirmar que el dispositivo esté en un segmento de red aislado de IT.",
                    en="The passive TCP fingerprint (TTL, window, options) is consistent with an "
                    "embedded/RTOS network stack typical of PLCs, RTUs, or other OT field devices, rather "
                    "than a general-purpose OS. Verify the vendor's firmware, apply available patches, and "
                    "confirm the device sits on a network segment isolated from IT.",
                )
            ),
            "severity": "info",
            "evidence": encode_i18n(
                bilingual(
                    es=f"Fingerprint OS: {device.os_guess} (confianza {device.os_confidence})",
                    en=f"OS fingerprint: {device.os_guess} (confidence {device.os_confidence})",
                )
            ),
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
