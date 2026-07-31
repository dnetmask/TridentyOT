from app.auth import ROLE_EDITOR
from app.auth.security import hash_password
from app.config import DEFAULT_ADMIN_PASSWORD, DEFAULT_ADMIN_USERNAME
from app.db import session_scope
from app.models import User


def seed_default_admin() -> None:
    """Creates a default editor account on first run only -- if any user
    already exists (including one created since, or renamed), this is a
    no-op. Change the default password immediately after first login."""
    with session_scope() as db:
        if db.query(User).count() > 0:
            return
        salt, password_hash = hash_password(DEFAULT_ADMIN_PASSWORD)
        db.add(
            User(
                username=DEFAULT_ADMIN_USERNAME,
                password_salt=salt,
                password_hash=password_hash,
                role=ROLE_EDITOR,
            )
        )
