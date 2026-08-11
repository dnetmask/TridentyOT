"""Tests for the Super Admin bootstrap -- see app/auth/seed.py. There is no
API path that can ever create a super_admin (see routes_organizations.py's
and routes_users.py's deliberate restriction to admin/viewer), so a central
console deployment that wants one has to opt in via
TRIDENTYOT_SUPER_ADMIN_USERNAME/PASSWORD at startup.
"""

import sqlalchemy as sa
import pytest

from app import db as db_module
from app.auth import ROLE_SUPER_ADMIN
from app.auth import seed as seed_module
from app.models import Organization, User


def test_unset_env_vars_create_no_super_admin(db_session):
    """Default behavior (no env vars set) must stay exactly as before this
    feature existed -- confirmed via the already-seeded db_session fixture."""
    seed_module.seed_default_super_admin()
    assert db_session.query(User).filter(User.role == ROLE_SUPER_ADMIN).count() == 0


def test_configured_super_admin_is_created_and_admin_seed_skips_default_org(db_session, monkeypatch):
    """A managed/central-console deployment that bootstraps a Super Admin
    this way has no use for the auto-created default organization/admin
    either -- seed_default_admin() must skip itself once the Super Admin
    exists, same as it already does for any other pre-existing user."""
    monkeypatch.setattr(seed_module, "SUPER_ADMIN_USERNAME", "root")
    monkeypatch.setattr(seed_module, "SUPER_ADMIN_PASSWORD", "rootpass1")

    # _reset_db's autouse fixture already ran seed_default_admin() once
    # (unpatched), so start from a clean slate to isolate this scenario.
    db_session.query(User).delete()
    db_session.query(Organization).delete()
    db_session.commit()

    seed_module.seed_default_super_admin()
    seed_module.seed_default_admin()

    users = db_session.query(User).all()
    assert len(users) == 1
    assert users[0].username == "root"
    assert users[0].role == ROLE_SUPER_ADMIN
    assert users[0].organization_id is None


def test_seed_default_super_admin_is_idempotent(db_session, monkeypatch):
    monkeypatch.setattr(seed_module, "SUPER_ADMIN_USERNAME", "root")
    monkeypatch.setattr(seed_module, "SUPER_ADMIN_PASSWORD", "rootpass1")

    seed_module.seed_default_super_admin()
    seed_module.seed_default_super_admin()

    assert db_session.query(User).filter(User.role == ROLE_SUPER_ADMIN).count() == 1


def test_username_without_password_fails_loudly(monkeypatch):
    monkeypatch.setattr(seed_module, "SUPER_ADMIN_USERNAME", "root")
    monkeypatch.setattr(seed_module, "SUPER_ADMIN_PASSWORD", None)

    with pytest.raises(RuntimeError):
        seed_module.seed_default_super_admin()


def test_fresh_database_with_super_admin_configured_gets_no_default_organization(tmp_path, monkeypatch):
    """The actual bug this file exists for: a central-console deployment
    that bootstraps a Super Admin must start with zero organizations, so
    its first login is genuinely "create your first organization" -- not a
    pre-populated "Default Organization" nobody asked for (see db.py's
    _ensure_default_organization_and_backfill). Only init_db() itself is
    exercised here (not seed_default_super_admin(), which -- like the rest
    of the app's runtime -- writes through SessionLocal, a sessionmaker
    bound at import time to the *real* engine, not whatever this test
    points the `engine` name at; see db.py's own comments on this)."""
    monkeypatch.setattr("app.config.SUPER_ADMIN_USERNAME", "root")

    db_path = tmp_path / "fresh_managed.db"
    patched_engine = sa.create_engine(f"sqlite:///{db_path}")
    monkeypatch.setattr(db_module, "engine", patched_engine)

    db_module.init_db()

    Session = sa.orm.sessionmaker(bind=patched_engine)
    with Session() as session:
        assert session.query(Organization).count() == 0


def test_fresh_database_without_super_admin_still_gets_a_default_organization(tmp_path, monkeypatch):
    """Self-hosted single-client behavior must stay unchanged when no
    Super Admin is configured -- the default org/admin bootstrap this repo
    has always relied on."""
    monkeypatch.setattr(seed_module, "SUPER_ADMIN_USERNAME", None)

    db_path = tmp_path / "fresh_self_hosted.db"
    patched_engine = sa.create_engine(f"sqlite:///{db_path}")
    monkeypatch.setattr(db_module, "engine", patched_engine)

    db_module.init_db()

    Session = sa.orm.sessionmaker(bind=patched_engine)
    with Session() as session:
        orgs = session.query(Organization).all()
        assert len(orgs) == 1
        assert orgs[0].slug == "default"
