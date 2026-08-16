"""Passive OS fingerprinting from TCP SYN characteristics.

This is a lightweight, p0f-inspired heuristic: it looks only at values that
are visible on the wire from a single SYN (or SYN-ACK) packet -- the
initial TTL, the advertised window size, and which TCP options are present
-- and scores them against a small table of common OS signatures. It will
never be as precise as an active fingerprinting tool (nmap -O) or a full
p0f signature database, but it needs no interaction with the host and is
safe to run purely passively against OT/ICS networks.
"""

from dataclasses import dataclass, field

# Common initial TTL values used by real-world stacks. Observed TTL is
# almost always lower than this due to router hops, so we recover the
# likely original value by rounding up to the nearest of these.
COMMON_INITIAL_TTLS = (32, 64, 128, 255)


@dataclass
class TcpSignature:
    ttl: int
    window: int
    mss: int | None
    has_sack: bool
    has_timestamp: bool
    has_wscale: bool
    df: bool
    option_order: tuple[str, ...] = field(default_factory=tuple)


@dataclass
class OsGuess:
    os_family: str
    label: str
    confidence: float  # 0.0 - 1.0
    signature_name: str
    initial_ttl_guess: int
    hop_estimate: int


_SIGNATURES = [
    {
        "name": "windows",
        "os_family": "Windows",
        "label": "Windows (7/8/10/11 family)",
        "ttl": 128,
        "window_min": 8192,
        "window_max": 65535,
        "has_wscale": True,
        "has_sack": True,
        "has_timestamp": False,
    },
    {
        "name": "linux",
        "os_family": "Linux",
        "label": "Linux (modern kernel)",
        "ttl": 64,
        "window_min": 5000,
        "window_max": 65535,
        "has_wscale": True,
        "has_sack": True,
        "has_timestamp": True,
    },
    {
        "name": "linux_embedded",
        "os_family": "Linux",
        "label": "Linux (embedded/constrained kernel, no timestamps)",
        # A real, well-documented p0f-era category: kernels built without
        # CONFIG_TCP_TIMESTAMPS (common on older or memory-constrained
        # embedded Linux -- SOHO routers, IP cameras, many "smart" OT
        # peripherals) still negotiate SACK but never send a timestamp or
        # window scale option, and default to a much smaller window than a
        # full desktop/server kernel. Distinct from embedded_ot below,
        # which assumes no TCP options survive at all.
        "ttl": 64,
        "window_min": 4096,
        "window_max": 16384,
        "has_wscale": False,
        "has_sack": True,
        "has_timestamp": False,
    },
    {
        "name": "bsd_macos",
        "os_family": "macOS/BSD",
        "label": "macOS / BSD family",
        "ttl": 64,
        "window_min": 65535,
        "window_max": 65535,
        "has_wscale": True,
        "has_sack": True,
        "has_timestamp": True,
    },
    {
        "name": "network_device",
        "os_family": "Network device",
        "label": "Network appliance (router/switch/firewall)",
        "ttl": 255,
        "window_min": 1024,
        "window_max": 16384,
        "has_wscale": False,
        "has_sack": False,
        "has_timestamp": False,
    },
    {
        "name": "embedded_ot",
        "os_family": "Embedded/OT",
        "label": "Embedded stack / RTOS (possible OT-ICS device)",
        "ttl": 64,
        "window_min": 0,
        "window_max": 4096,
        "has_wscale": False,
        "has_sack": False,
        "has_timestamp": False,
    },
    {
        "name": "embedded_windows_like",
        "os_family": "Embedded/OT",
        "label": "Embedded stack / RTOS (Windows-like TTL, possible legacy OT/HMI device)",
        # Some older/legacy industrial HMIs and thin clients (Windows
        # CE/embedded-derived stacks, some ICS vendor RTOS builds) default
        # to a TTL of 128 the same as desktop Windows, but negotiate no TCP
        # options at all and use a tiny window -- without this entry, the
        # scorer's biggest single signal (TTL) alone was enough to
        # misclassify one of these as plain "Windows".
        "ttl": 128,
        "window_min": 0,
        "window_max": 4096,
        "has_wscale": False,
        "has_sack": False,
        "has_timestamp": False,
    },
]


def guess_initial_ttl(observed_ttl: int) -> int:
    for candidate in COMMON_INITIAL_TTLS:
        if observed_ttl <= candidate:
            return candidate
    return observed_ttl


def _score_signature(sig: dict, initial_ttl: int, window: int, has_sack: bool,
                      has_timestamp: bool, has_wscale: bool) -> float:
    score = 0.0
    max_score = 4.0

    if initial_ttl == sig["ttl"]:
        score += 2.0  # TTL is the strongest single signal

    if sig["window_min"] <= window <= sig["window_max"]:
        score += 1.0

    bool_matches = sum(
        [
            has_sack == sig["has_sack"],
            has_timestamp == sig["has_timestamp"],
            has_wscale == sig["has_wscale"],
        ]
    )
    score += bool_matches / 3.0

    return score / max_score


def fingerprint_tcp_syn(sig: TcpSignature) -> OsGuess:
    initial_ttl = guess_initial_ttl(sig.ttl)
    hop_estimate = max(initial_ttl - sig.ttl, 0)

    best_match = None
    best_score = -1.0
    for candidate in _SIGNATURES:
        score = _score_signature(
            candidate, initial_ttl, sig.window, sig.has_sack, sig.has_timestamp, sig.has_wscale
        )
        if score > best_score:
            best_score = score
            best_match = candidate

    assert best_match is not None
    return OsGuess(
        os_family=best_match["os_family"],
        label=best_match["label"],
        confidence=round(best_score, 2),
        signature_name=best_match["name"],
        initial_ttl_guess=initial_ttl,
        hop_estimate=hop_estimate,
    )


def parse_tcp_options(options: list) -> dict:
    """Normalize scapy TCP.options (list of (name, value) tuples) into flags."""
    names = [opt[0] if isinstance(opt, tuple) else str(opt) for opt in options]
    mss = None
    for opt in options:
        if isinstance(opt, tuple) and opt[0] == "MSS":
            mss = opt[1]
    return {
        "mss": mss,
        "has_sack": "SAckOK" in names,
        "has_timestamp": "Timestamp" in names,
        "has_wscale": "WScale" in names,
        "option_order": tuple(names),
    }
