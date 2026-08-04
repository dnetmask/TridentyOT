from app.auth import ROLE_ADMIN
from app.auth.security import hash_password
from app.config import DEFAULT_ADMIN_PASSWORD, DEFAULT_ADMIN_USERNAME
from app.db import session_scope
from app.models import Organization, User


def seed_default_admin() -> None:
    """Creates a default admin account on first run only -- if any user
    already exists (including one created since, or renamed), this is a
    no-op. Change the default password immediately after first login.

    Attached to whatever organization already exists (db.init_db's
    _ensure_default_organization_and_backfill runs first in the app's
    startup sequence and always leaves at least one), or a freshly created
    default one otherwise -- e.g. a test that calls this directly without
    going through init_db first.
    """
    with session_scope() as db:
        if db.query(User).count() > 0:
            return
        org = db.query(Organization).order_by(Organization.id.asc()).first()
        if org is None:
            org = Organization(name="Default Organization", slug="default")
            db.add(org)
            db.flush()
        salt, password_hash = hash_password(DEFAULT_ADMIN_PASSWORD)
        db.add(
            User(
                organization_id=org.id,
                username=DEFAULT_ADMIN_USERNAME,
                password_salt=salt,
                password_hash=password_hash,
                role=ROLE_ADMIN,
            )
        )
