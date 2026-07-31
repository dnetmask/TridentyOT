import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("TRIDENTYOT_DATA_DIR", BASE_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = os.environ.get("TRIDENTYOT_DATABASE_URL", f"sqlite:///{DATA_DIR / 'tridentyot.db'}")

# NVD REST API (CVE search by keyword). Public rate limit without an API key
# is ~5 requests / 30s, so results are cached aggressively (see vuln/nvd_client.py).
NVD_API_BASE_URL = os.environ.get("NVD_API_BASE_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
NVD_API_KEY = os.environ.get("NVD_API_KEY")  # optional, raises rate limit to 50 req/30s
NVD_CACHE_TTL_SECONDS = int(os.environ.get("NVD_CACHE_TTL_SECONDS", 24 * 3600))
NVD_REQUEST_TIMEOUT_SECONDS = float(os.environ.get("NVD_REQUEST_TIMEOUT_SECONDS", 10))

# Default BPF filter used for live capture when none is supplied. Keeps the
# sensor focused on traffic relevant to inventory/fingerprinting.
DEFAULT_LIVE_CAPTURE_FILTER = os.environ.get("TRIDENTYOT_DEFAULT_FILTER", "ip or arp")
LIVE_CAPTURE_SNAPLEN = int(os.environ.get("TRIDENTYOT_SNAPLEN", 65535))

# How long a login session (bearer token) stays valid.
SESSION_LIFETIME_SECONDS = int(os.environ.get("TRIDENTYOT_SESSION_LIFETIME_SECONDS", 7 * 24 * 3600))

# Username/password for the account auto-created on first startup if no
# users exist yet. Change the password immediately after first login.
DEFAULT_ADMIN_USERNAME = os.environ.get("TRIDENTYOT_DEFAULT_ADMIN_USERNAME", "admin")
DEFAULT_ADMIN_PASSWORD = os.environ.get("TRIDENTYOT_DEFAULT_ADMIN_PASSWORD", "admin")
