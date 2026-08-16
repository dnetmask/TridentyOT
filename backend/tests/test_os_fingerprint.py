from app.fingerprint.os_fingerprint import TcpSignature, fingerprint_tcp_syn, guess_initial_ttl


def test_guess_initial_ttl_rounds_up_to_common_values():
    assert guess_initial_ttl(60) == 64
    assert guess_initial_ttl(120) == 128
    assert guess_initial_ttl(250) == 255
    assert guess_initial_ttl(30) == 32


def test_fingerprint_windows_like_signature():
    sig = TcpSignature(
        ttl=126, window=64240, mss=1460, has_sack=True, has_timestamp=False, has_wscale=True, df=True
    )
    guess = fingerprint_tcp_syn(sig)
    assert guess.os_family == "Windows"
    assert guess.confidence > 0.5
    assert guess.hop_estimate == 2


def test_fingerprint_linux_like_signature():
    sig = TcpSignature(
        ttl=63, window=29200, mss=1460, has_sack=True, has_timestamp=True, has_wscale=True, df=True
    )
    guess = fingerprint_tcp_syn(sig)
    assert guess.os_family == "Linux"


def test_fingerprint_embedded_ot_like_signature():
    sig = TcpSignature(
        ttl=64, window=1024, mss=536, has_sack=False, has_timestamp=False, has_wscale=False, df=False
    )
    guess = fingerprint_tcp_syn(sig)
    assert guess.os_family == "Embedded/OT"


def test_fingerprint_network_device_like_signature():
    sig = TcpSignature(
        ttl=255, window=4128, mss=536, has_sack=False, has_timestamp=False, has_wscale=False, df=False
    )
    guess = fingerprint_tcp_syn(sig)
    assert guess.os_family == "Network device"


def test_fingerprint_linux_embedded_signature_distinct_from_full_linux():
    """A kernel built without CONFIG_TCP_TIMESTAMPS (common on embedded/
    constrained Linux -- SOHO routers, IP cameras, OT peripherals) still
    negotiates SACK but never timestamp/wscale, and uses a much smaller
    window than a full desktop/server kernel -- should not be confused
    with either plain "Linux" (which expects all three options) or
    "Embedded/OT" (which expects none of them)."""
    sig = TcpSignature(
        ttl=63, window=8192, mss=1460, has_sack=True, has_timestamp=False, has_wscale=False, df=True
    )
    guess = fingerprint_tcp_syn(sig)
    assert guess.os_family == "Linux"
    assert guess.signature_name == "linux_embedded"


def test_fingerprint_embedded_windows_like_signature_not_confused_with_windows():
    """A legacy OT/HMI device with a Windows-shaped TTL (128) but no TCP
    options at all and a tiny window should not be classified as plain
    "Windows" just because the TTL happens to match."""
    sig = TcpSignature(
        ttl=126, window=512, mss=536, has_sack=False, has_timestamp=False, has_wscale=False, df=False
    )
    guess = fingerprint_tcp_syn(sig)
    assert guess.os_family == "Embedded/OT"
    assert guess.signature_name == "embedded_windows_like"
