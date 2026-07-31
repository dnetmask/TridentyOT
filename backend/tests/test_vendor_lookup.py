from app.fingerprint.vendor_lookup import lookup_vendor


def test_lookup_known_prefix_is_case_and_separator_insensitive():
    assert lookup_vendor("00:1B:1B:aa:bb:cc") == "Siemens AG"
    assert lookup_vendor("00-1b-1b-aa-bb-cc") == "Siemens AG"
    assert lookup_vendor("001b1baabbcc") == "Siemens AG"


def test_lookup_unknown_prefix_returns_none_without_guessing():
    assert lookup_vendor("ff:ee:dd:00:00:00") is None


def test_lookup_handles_missing_or_malformed_input():
    assert lookup_vendor(None) is None
    assert lookup_vendor("") is None
    assert lookup_vendor("not-a-mac") is None
