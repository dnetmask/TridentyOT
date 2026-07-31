"""MAC OUI -> vendor lookup.

Backed by the Wireshark `manuf` database (itself derived from the IEEE
public OUI registry), bundled at fingerprint/data/oui_manuf.tsv. Only the
standard 24-bit (/24, i.e. first 3 bytes) allocations are included -- the
smaller MA-M/MA-S sub-allocations are skipped, so a handful of newer or
small-block vendors won't resolve. When a MAC isn't found the lookup
returns None rather than guessing.
"""

from functools import lru_cache
from pathlib import Path

_DATA_PATH = Path(__file__).resolve().parent / "data" / "oui_manuf.tsv"


@lru_cache(maxsize=1)
def _load_table() -> dict[str, str]:
    table: dict[str, str] = {}
    if not _DATA_PATH.exists():
        return table
    with _DATA_PATH.open(encoding="utf-8") as f:
        for line in f:
            oui, _, vendor = line.rstrip("\n").partition("\t")
            if oui and vendor:
                table[oui] = vendor
    return table


def lookup_vendor(mac: str | None) -> str | None:
    if not mac:
        return None
    hexdigits = mac.replace(":", "").replace("-", "").upper()
    if len(hexdigits) < 6:
        return None
    return _load_table().get(hexdigits[:6])
