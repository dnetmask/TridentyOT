"""Passive OS/stack fingerprinting from a DHCP client's own Parameter
Request List (option 55) -- RFC 2132's "the client is asking the server for
exactly these configuration options, in exactly this order" field.

Which options a DHCP client requests, and in what order, is baked into that
OS's DHCP client implementation and rarely changes across most of that
build's lifetime, making it a reasonably stable per-OS-family fingerprint --
the same idea Fingerbank/Satori-style tools are built around, and
complementary to the TCP/IP stack fingerprint in os_fingerprint.py: a device
might never send a TCP SYN this sensor happens to observe, but nearly every
device on a LAN performs DHCP at least once.

The signature table below is a small, hand-curated seed of commonly
documented per-OS option-55 sequences -- not a full Fingerbank/Satori
database (this project has no verified, licensable copy of one; a fetch
attempt during development came back empty/404). Exact option lists vary by
OS version and DHCP client build, so treat this exactly like the Cisco/
Siemens Scalance switch-CLI parsers started out: a best-effort seed, meant
to be corrected and extended once tested against this deployment's own real
captured DHCP traffic, not a finished reference database.
"""

from app.fingerprint.os_fingerprint import OsGuess

_SIGNATURES = [
    {
        "name": "windows",
        "os_family": "Windows",
        "label": "Windows (DHCP client)",
        "options": (1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252),
    },
    {
        "name": "linux_dhclient",
        "os_family": "Linux",
        "label": "Linux (ISC dhclient)",
        "options": (1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42),
    },
    {
        "name": "apple",
        "os_family": "macOS/iOS",
        "label": "macOS / iOS (DHCP client)",
        "options": (1, 3, 6, 15, 119, 95, 252, 44, 46),
    },
    {
        "name": "android",
        "os_family": "Android",
        "label": "Android (DHCP client)",
        "options": (1, 3, 6, 15, 26, 28, 51, 58, 59),
    },
    {
        "name": "embedded_minimal",
        "os_family": "Embedded/OT",
        "label": "Embedded stack / RTOS (minimal DHCP client, possible OT-ICS device)",
        "options": (1, 3, 6, 15),
    },
]

# A signature this short is only ever weak evidence, exact match or not --
# plenty of unrelated minimal DHCP clients converge on the same handful of
# common option numbers by coincidence, not because they share an OS family.
# Confidence is scaled down for any signature shorter than this.
_DISTINCTIVE_LENGTH = 8
_EXACT_MATCH_BASE_CONFIDENCE = 0.75
_PREFIX_MATCH_BASE_CONFIDENCE = 0.45


def _specificity(options: tuple[int, ...]) -> float:
    return min(len(options) / _DISTINCTIVE_LENGTH, 1.0)


def fingerprint_dhcp_options(param_req_list: list[int] | None) -> OsGuess | None:
    """Matches an observed DHCP option 55 (ordered) against the seed table
    above. Returns None rather than forcing a guess when nothing matches
    with any real confidence -- unlike fingerprint_tcp_syn, which always
    picks the least-bad of a handful of broad TCP/IP stack families, this
    table is sparse enough that "no real match" is a common, honest outcome
    that shouldn't be dressed up as a low-confidence family guess.
    """
    if not param_req_list:
        return None
    observed = tuple(param_req_list)

    best_match = None
    best_confidence = 0.0
    for candidate in _SIGNATURES:
        options = candidate["options"]
        specificity = _specificity(options)
        if observed == options:
            confidence = _EXACT_MATCH_BASE_CONFIDENCE * specificity
        elif len(observed) > len(options) and observed[: len(options)] == options:
            # The client requested everything the seed signature does, plus
            # a couple of extra options tacked on the end -- e.g. a newer OS
            # build. Deliberately one-directional: the reverse (observed is
            # a strict prefix of a longer, more distinctive signature) is
            # NOT treated as a match -- matching only the first few, most
            # common entries of a long signature says nothing about whether
            # the client would have gone on to request that signature's
            # more distinctive later options, so it's not meaningfully
            # better evidence than no match at all.
            confidence = _PREFIX_MATCH_BASE_CONFIDENCE * specificity
        else:
            continue
        if confidence > best_confidence:
            best_confidence = confidence
            best_match = candidate

    if best_match is None:
        return None

    return OsGuess(
        os_family=best_match["os_family"],
        label=best_match["label"],
        confidence=round(best_confidence, 2),
        signature_name=f"dhcp:{best_match['name']}",
        initial_ttl_guess=0,
        hop_estimate=0,
    )
