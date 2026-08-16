from app.fingerprint.dhcp_fingerprint import fingerprint_dhcp_options

_WINDOWS_OPTIONS = [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]


def test_exact_match_identifies_os_family():
    guess = fingerprint_dhcp_options(_WINDOWS_OPTIONS)
    assert guess is not None
    assert guess.os_family == "Windows"
    assert guess.signature_name == "dhcp:windows"


def test_prefix_match_scores_lower_than_exact_match():
    exact = fingerprint_dhcp_options(_WINDOWS_OPTIONS)
    prefix = fingerprint_dhcp_options(_WINDOWS_OPTIONS + [33])
    assert prefix is not None
    assert prefix.os_family == "Windows"
    assert prefix.confidence < exact.confidence


def test_short_generic_signature_scores_lower_than_a_distinctive_one():
    """An exact match on a long, distinctive option list (Windows here) is
    much stronger evidence than an exact match on a short, generic one
    (many unrelated minimal DHCP clients converge on the same handful of
    common option numbers by coincidence)."""
    windows_guess = fingerprint_dhcp_options(_WINDOWS_OPTIONS)
    embedded_guess = fingerprint_dhcp_options([1, 3, 6, 15])
    assert embedded_guess is not None
    assert embedded_guess.os_family == "Embedded/OT"
    assert embedded_guess.confidence < windows_guess.confidence


def test_unrecognized_sequence_returns_none_rather_than_a_forced_guess():
    assert fingerprint_dhcp_options([250, 251, 253]) is None


def test_empty_or_missing_list_returns_none():
    assert fingerprint_dhcp_options([]) is None
    assert fingerprint_dhcp_options(None) is None


def test_ttl_fields_are_neutral_placeholders_not_real_hop_data():
    """DHCP option 55 says nothing about TTL/hop count -- these two OsGuess
    fields exist only for the TCP/IP fingerprint's use and are always zero
    here, same convention as nmap_discovery.py's OsGuess construction."""
    guess = fingerprint_dhcp_options(_WINDOWS_OPTIONS)
    assert guess.initial_ttl_guess == 0
    assert guess.hop_estimate == 0
