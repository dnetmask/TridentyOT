import os
import tempfile

# Must run before anything imports app.config, so tests never touch a
# developer's real database or upload directory.
os.environ.setdefault("TRIDENTYOT_DATA_DIR", tempfile.mkdtemp(prefix="tridentyot-test-data-"))
os.environ.setdefault("TRIDENTYOT_DATABASE_URL", f"sqlite:///{tempfile.mkdtemp(prefix='tridentyot-test-db-')}/test.db")

import pytest  # noqa: E402

from app.auth.seed import seed_default_admin  # noqa: E402
from app.config import DEFAULT_ADMIN_PASSWORD, DEFAULT_ADMIN_USERNAME  # noqa: E402
from app.db import Base, SessionLocal, engine, init_db  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_db():
    Base.metadata.drop_all(bind=engine)
    init_db()
    seed_default_admin()
    yield


@pytest.fixture
def db_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def org_id(db_session):
    """The id of the one Organization init_db()'s startup migration always
    creates -- every test runs against a single-tenant database, so this is
    the organization every directly-constructed Device/CaptureSession/call
    into inventory_service belongs to."""
    from app.models import Organization

    return db_session.query(Organization).order_by(Organization.id.asc()).first().id


@pytest.fixture
def anonymous_client():
    """A TestClient with no Authorization header at all, for exercising
    401s and the login flow itself."""
    from fastapi.testclient import TestClient

    from app.main import app

    return TestClient(app)


def _login(anon_client, username: str, password: str) -> str:
    resp = anon_client.post("/api/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["token"]


@pytest.fixture
def client():
    """Pre-authenticated as the default seeded editor (admin/admin) --
    matches how almost every existing test actually uses the API. A
    separate TestClient instance from `anonymous_client` (not a mutated
    view of it), so a test can safely request both."""
    from fastapi.testclient import TestClient

    from app.main import app

    authed = TestClient(app)
    token = _login(authed, DEFAULT_ADMIN_USERNAME, DEFAULT_ADMIN_PASSWORD)
    authed.headers.update({"Authorization": f"Bearer {token}"})
    return authed


@pytest.fixture
def make_client():
    """Factory for a client authenticated as an arbitrary user, e.g. a
    freshly created viewer -- used to test role-based restrictions."""
    from fastapi.testclient import TestClient

    from app.main import app

    def _make(username: str, password: str) -> "TestClient":
        anon = TestClient(app)
        token = _login(anon, username, password)
        anon.headers.update({"Authorization": f"Bearer {token}"})
        return anon

    return _make
