import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("TRIDENTYOT_DATA_DIR", BASE_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Postgres is the primary target (multi-tenant central console and
# self-hosted deployments alike -- see docker-compose.yml's `db` service).
# TRIDENTYOT_DATABASE_URL can still point at sqlite:/// for local
# development or a lightweight single-sensor install without a separate DB
# server; every migration in db.py is written to work against both dialects.
_POSTGRES_HOST = os.environ.get("TRIDENTYOT_POSTGRES_HOST", "db")
_POSTGRES_PORT = os.environ.get("TRIDENTYOT_POSTGRES_PORT", "5432")
_POSTGRES_DB = os.environ.get("TRIDENTYOT_POSTGRES_DB", "tridentyot")
_POSTGRES_USER = os.environ.get("TRIDENTYOT_POSTGRES_USER", "tridentyot")
_POSTGRES_PASSWORD = os.environ.get("TRIDENTYOT_POSTGRES_PASSWORD", "tridentyot")
_DEFAULT_DATABASE_URL = (
    f"postgresql+psycopg://{_POSTGRES_USER}:{_POSTGRES_PASSWORD}@{_POSTGRES_HOST}:{_POSTGRES_PORT}/{_POSTGRES_DB}"
)

DATABASE_URL = os.environ.get("TRIDENTYOT_DATABASE_URL", _DEFAULT_DATABASE_URL)

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

# Bootstraps a Super Admin (the Netmask platform role -- no organization of
# its own, administers every organization) on first startup. There is no
# API path that can ever create a super_admin (see routes_organizations.py/
# routes_users.py's deliberate restriction to admin/viewer), so this is the
# only way one ever comes to exist.
#
# Defaults to username/password "TridentyOTroot" -- every fresh deployment,
# including a self-hosted single-client install, starts with this account
# and lands on "create your first organization" on first login (see
# db.py's _ensure_default_organization_and_backfill: no default
# Organization/admin get auto-created once a Super Admin is configured,
# central-console or not). Change the password immediately after first
# login, same as DEFAULT_ADMIN_PASSWORD above.
#
# To opt out entirely and go back to the old single-tenant bootstrap (a
# ready-to-use "Default Organization" + admin/admin, no Super Admin at
# all), set TRIDENTYOT_SUPER_ADMIN_USERNAME to an empty string.
SUPER_ADMIN_USERNAME = os.environ.get("TRIDENTYOT_SUPER_ADMIN_USERNAME", "TridentyOTroot")
SUPER_ADMIN_PASSWORD = os.environ.get("TRIDENTYOT_SUPER_ADMIN_PASSWORD", "TridentyOTroot")
