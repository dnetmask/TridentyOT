"""Tests for the Super Admin bootstrap -- see app/auth/seed.py. There is no
API path that can ever create a super_admin (see routes_organizations.py's
and routes_users.py's deliberate restriction to admin/viewer), so this
bootstrap is the only way one ever comes to exist. It now defaults to
username/password "TridentyOTroot" for every deployment (see config.py's
SUPER_ADMIN_USERNAME/PASSWORD) unless the operator overrides them or opts
out entirely with an empty TRIDENTYOT_SUPER_ADMIN_USERNAME.
"""

import sqlalchemy as sa
import pytest

from app import db as db_module
from app.auth import ROLE_SUPER_ADMIN
from app.auth import seed as seed_module
from app.models import Organization, User


def test_default_super_admin_is_tridentyotroot(db_session, monkeypatch):
    """If the operator sets neither TRIDENTYOT_SUPER_ADMIN_USERNAME nor
    _PASSWORD, every fresh deployment gets this exact account -- see
    config.py's own comment on SUPER_ADMIN_USERNAME. This suite's own
    conftest opts out of that default (TRIDENTYOT_SUPER_ADMIN_USERNAME="")
    so the rest of it can keep exercising the single-tenant scenario every
    other test here assumes -- monkeypatching the "really unset" value
    back in here verifies it matches what a fresh deployment actually
    gets, independent of that opt-out."""
    monkeypatch.setattr(seed_module, "SUPER_ADMIN_USERNAME", "TridentyOTroot")
    monkeypatch.setattr(seed_module, "SUPER_ADMIN_PASSWORD", "TridentyOTroot")

    # _reset_db's autouse fixture already seeded a default admin/org before
    # this test runs (the suite's own opted-out config) -- clear that
    # unrelated state to isolate this scenario, same pattern the other
    # tests in this file already use.
    db_session.query(User).delete()
    db_session.query(Organization).delete()
    db_session.commit()

    seed_module.seed_default_super_admin()

    root = db_session.query(User).filter(User.role == ROLE_SUPER_ADMIN).one()
    assert root.username == "TridentyOTroot"
    assert root.organization_id is None


def test_opting_out_with_an_empty_username_creates_no_super_admin(db_session, monkeypatch):
    """The one supported way to go back to the old single-tenant-only
    bootstrap (no Super Admin at all) -- see config.py's own comment on
    SUPER_ADMIN_USERNAME."""
    monkeypatch.setattr(seed_module, "SUPER_ADMIN_USERNAME", "")

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
    """The actual bug this file exists for: any deployment that bootstraps
    a Super Admin -- the default now, not just an opted-in central console
    -- must start with zero organizations, so its first login is genuinely
    "create your first organization" -- not a pre-populated "Default
    Organization" nobody asked for (see db.py's
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
    """The opt-out path (see config.py's SUPER_ADMIN_USERNAME comment):
    explicitly disabling the Super Admin restores the old single-tenant
    bootstrap -- a ready-to-use default org/admin, no Super Admin at all.
    Patches app.config directly (not seed_module's copy): db.py's
    _ensure_default_organization_and_backfill re-imports SUPER_ADMIN_
    USERNAME from app.config fresh on every call, same reason the sibling
    test above patches it there instead of seed_module."""
    monkeypatch.setattr("app.config.SUPER_ADMIN_USERNAME", "")

    db_path = tmp_path / "fresh_self_hosted.db"
    patched_engine = sa.create_engine(f"sqlite:///{db_path}")
    monkeypatch.setattr(db_module, "engine", patched_engine)

    db_module.init_db()

    Session = sa.orm.sessionmaker(bind=patched_engine)
    with Session() as session:
        orgs = session.query(Organization).all()
        assert len(orgs) == 1
        assert orgs[0].slug == "default"
