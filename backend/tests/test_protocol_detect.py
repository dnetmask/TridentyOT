from app.fingerprint.protocol_detect import (
    INSECURE_PROTOCOL_NAMES,
    OT_PROTOCOLS,
    classify,
    detect_by_payload,
    detect_by_port,
)


def test_modbus_port_is_ot():
    info = detect_by_port(502)
    assert info.protocol == "modbus"
    assert info.category == "OT"
    assert "modbus" in OT_PROTOCOLS


def test_dnp3_and_s7comm_are_ot():
    assert detect_by_port(20000).protocol == "dnp3"
    assert detect_by_port(102).protocol == "s7comm"


def test_telnet_is_flagged_insecure():
    info = detect_by_port(23)
    assert info.insecure is True
    assert "telnet" in INSECURE_PROTOCOL_NAMES


def test_ssh_is_not_flagged_insecure():
    info = detect_by_port(22)
    assert info.insecure is False


def test_http_payload_overrides_unknown_port():
    info = detect_by_payload(b"GET / HTTP/1.1\r\nHost: example\r\n\r\n")
    assert info.protocol == "http"


def test_ssh_banner_detection():
    info = detect_by_payload(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu\r\n")
    assert info.protocol == "ssh"


def test_classify_unknown_port():
    info = classify(59999)
    assert info.protocol == "unknown"


def test_classify_prefers_payload_over_port():
    # Port 8080 is normally http-alt, but a raw TLS record on it should win.
    tls_record = bytes([0x16, 0x03, 0x01, 0x00, 0x05]) + b"hello"
    info = classify(8080, payload=tls_record)
    assert info.protocol == "tls"
