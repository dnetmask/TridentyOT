import os
import tempfile

# Must run before anything imports app.config, so tests never touch a
# developer's real database or upload directory.
os.environ.setdefault("TRIDENTYOT_DATA_DIR", tempfile.mkdtemp(prefix="tridentyot-test-data-"))
os.environ.setdefault("TRIDENTYOT_DATABASE_URL", f"sqlite:///{tempfile.mkdtemp(prefix='tridentyot-test-db-')}/test.db")

import pytest  # noqa: E402

from app.db import Base, SessionLocal, engine, init_db  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_db():
    Base.metadata.drop_all(bind=engine)
    init_db()
    yield


@pytest.fixture
def db_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from app.main import app

    return TestClient(app)
