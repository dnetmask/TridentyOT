from app.fingerprint.device_classifier import (
    HMI,
    NETWORK_DEVICE,
    OTHER,
    PLC,
    SERVER,
    WORKSTATION,
    classify_device_type,
)


def test_ot_server_protocol_is_near_certain_plc():
    guess = classify_device_type(
        vendor=None,
        hostname=None,
        os_signature=None,
        has_ot_server_protocol=True,
        server_protocol_count=1,
    )
    assert guess.device_type == PLC
    assert guess.confidence >= 0.7
    assert "protocolo industrial" in guess.evidence[0]


def test_cdp_lldp_announcement_is_near_certain_network_device():
    guess = classify_device_type(
        vendor="Cisco Systems, Inc",
        hostname=None,
        os_signature="cdp_lldp_announcement",
        has_ot_server_protocol=False,
        server_protocol_count=0,
    )
    assert guess.device_type == NETWORK_DEVICE
    assert guess.confidence >= 0.7


def test_industrial_vendor_alone_suggests_plc_moderate_confidence():
    guess = classify_device_type(
        vendor="Siemens AG",
        hostname=None,
        os_signature=None,
        has_ot_server_protocol=False,
        server_protocol_count=0,
    )
    assert guess.device_type == PLC
    assert 0 < guess.confidence < 0.7


def test_hostname_keyword_outweighs_a_conflicting_vendor_hint():
    """A Siemens-made industrial PC named "...-PC" is a workstation, not a
    PLC, despite the vendor -- the site's own naming is more specific
    evidence about *role* than "who made the NIC" is."""
    guess = classify_device_type(
        vendor="Siemens Ag",
        hostname="PAW036-PC",
        os_signature=None,
        has_ot_server_protocol=False,
        server_protocol_count=0,
    )
    assert guess.device_type == WORKSTATION


def test_hmi_hostname_alone_suggests_hmi_not_plc():
    guess = classify_device_type(
        vendor=None,
        hostname="K787395-HMI01",
        os_signature="windows",
        has_ot_server_protocol=False,
        server_protocol_count=0,
    )
    assert guess.device_type == HMI
    assert 'Nombre sugiere HMI ("K787395-HMI01")' in guess.evidence


def test_ot_protocol_from_windows_or_linux_is_hmi_not_plc():
    """A PLC is an embedded controller -- it wouldn't fingerprint as a real
    Windows/Linux TCP/IP stack. Serving Modbus/S7comm *from* one is SCADA/
    HMI software or engineering tooling, not the controller itself."""
    for os_sig in ("windows", "linux"):
        guess = classify_device_type(
            vendor=None,
            hostname=None,
            os_signature=os_sig,
            has_ot_server_protocol=True,
            server_protocol_count=1,
        )
        assert guess.device_type == HMI, os_sig
        assert guess.confidence >= 0.7


def test_ot_protocol_from_macos_or_unknown_os_stays_plc():
    """The HMI carve-out is specifically for windows/linux -- an OT
    protocol server with any other (or no) OS signature is still called a
    PLC, matching the original, broader rule."""
    for os_sig in (None, "bsd_macos", "embedded_ot"):
        guess = classify_device_type(
            vendor=None,
            hostname=None,
            os_signature=os_sig,
            has_ot_server_protocol=True,
            server_protocol_count=1,
        )
        assert guess.device_type == PLC, os_sig


def test_hmi_hostname_and_ot_protocol_on_linux_agree_and_saturate_confidence():
    """Hostname keyword and the OT-protocol-on-a-real-OS rule both point at
    HMI here -- combined evidence should saturate confidence to 1.0."""
    guess = classify_device_type(
        vendor=None,
        hostname="K787395-HMI01",
        os_signature="linux",
        has_ot_server_protocol=True,
        server_protocol_count=1,
    )
    assert guess.device_type == HMI
    assert guess.confidence == 1.0


def test_many_server_protocols_on_windows_suggests_server():
    guess = classify_device_type(
        vendor="Dell Inc.",
        hostname=None,
        os_signature="windows",
        has_ot_server_protocol=False,
        server_protocol_count=5,
    )
    assert guess.device_type == SERVER


def test_client_only_windows_host_suggests_workstation():
    guess = classify_device_type(
        vendor=None,
        hostname=None,
        os_signature="windows",
        has_ot_server_protocol=False,
        server_protocol_count=0,
    )
    assert guess.device_type == WORKSTATION


def test_no_evidence_at_all_returns_other_with_zero_confidence():
    guess = classify_device_type(
        vendor=None,
        hostname=None,
        os_signature=None,
        has_ot_server_protocol=False,
        server_protocol_count=0,
    )
    assert guess.device_type == OTHER
    assert guess.confidence == 0.0
    assert guess.evidence == []


def test_embedded_stack_without_other_evidence_leans_plc():
    guess = classify_device_type(
        vendor=None,
        hostname=None,
        os_signature="embedded_ot",
        has_ot_server_protocol=False,
        server_protocol_count=0,
    )
    assert guess.device_type == PLC
    assert guess.confidence < 0.5
