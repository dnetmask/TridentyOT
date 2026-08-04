"""Regression test for a real bug: a database created by an older version
of the app (before Device.custom_name/vendor/custom_vendor existed) used to
fail every query with "no such column: devices.custom_name", because
Base.metadata.create_all() only creates missing tables, never alters an
existing one. init_db() now also patches in any missing columns.
"""

import sqlalchemy as sa

from app import db as db_module
from app.models import CaptureSession, Device


def test_migration_adds_missing_columns_without_losing_existing_data(tmp_path, monkeypatch):
    db_path = tmp_path / "legacy.db"

    # Simulate a pre-existing database created before custom_name/vendor/
    # custom_vendor were added to the Device model.
    setup_engine = sa.create_engine(f"sqlite:///{db_path}")
    with setup_engine.begin() as conn:
        conn.execute(
            sa.text(
                """
                CREATE TABLE devices (
                    id INTEGER PRIMARY KEY,
                    mac VARCHAR(17),
                    ip VARCHAR(45),
                    hostname VARCHAR(255),
                    os_guess VARCHAR(128),
                    os_confidence FLOAT,
                    os_signature VARCHAR(255),
                    is_ot_suspected BOOLEAN,
                    first_seen DATETIME,
                    last_seen DATETIME
                )
                """
            )
        )
        conn.execute(
            sa.text(
                "INSERT INTO devices (id, ip, hostname, os_confidence, is_ot_suspected, first_seen, last_seen) "
                "VALUES (1, '10.0.0.5', 'legacy-host', 0.5, 0, '2024-01-01', '2024-01-01')"
            )
        )
    setup_engine.dispose()

    patched_engine = sa.create_engine(f"sqlite:///{db_path}")
    monkeypatch.setattr(db_module, "engine", patched_engine)

    db_module.init_db()

    columns = {col["name"] for col in sa.inspect(patched_engine).get_columns("devices")}
    assert {"custom_name", "vendor", "custom_vendor"} <= columns

    Session = sa.orm.sessionmaker(bind=patched_engine)
    with Session() as session:
        device = session.query(Device).filter(Device.ip == "10.0.0.5").one()
        # pre-existing data survived the migration untouched
        assert device.hostname == "legacy-host"
        assert device.os_confidence == 0.5
        # new columns exist and default to NULL, not an error
        assert device.custom_name is None
        assert device.vendor is None
        assert device.display_name == "legacy-host"  # falls back to the pre-existing hostname

        # and the app can now write to them, which used to be impossible
        device.custom_name = "Renamed PLC"
        session.commit()

    with Session() as session:
        device = session.query(Device).filter(Device.ip == "10.0.0.5").one()
        assert device.custom_name == "Renamed PLC"


def test_migration_backfills_a_scalar_default_instead_of_leaving_null(tmp_path, monkeypatch):
    """Regression test for a real bug: CaptureSession.dropped_count was
    added as a plain `int` in the API schema, but a bare `ALTER TABLE ADD
    COLUMN` leaves it NULL on every row that existed before the column
    did -- so GET /api/capture/sessions 500'd with a ResponseValidationError
    ("Input should be a valid integer") the moment it tried to serialize
    one of those pre-existing sessions. Any scalar-default column
    (packet_count, dropped_count, os_confidence, is_ot_suspected, ...) has
    the same exposure; this must backfill the model's default instead of
    leaving SQLite's NULL in place, and must do so even for a column an
    *earlier* run of this migration already added with the bug.
    """
    db_path = tmp_path / "legacy_sessions.db"

    setup_engine = sa.create_engine(f"sqlite:///{db_path}")
    with setup_engine.begin() as conn:
        conn.execute(
            sa.text(
                """
                CREATE TABLE capture_sessions (
                    id INTEGER PRIMARY KEY,
                    name VARCHAR(255),
                    source_type VARCHAR(16),
                    source VARCHAR(255),
                    bpf_filter VARCHAR(255),
                    status VARCHAR(16),
                    packet_count INTEGER,
                    error_message TEXT,
                    started_at DATETIME,
                    ended_at DATETIME
                )
                """
            )
        )
        conn.execute(
            sa.text(
                "INSERT INTO capture_sessions "
                "(id, name, source_type, source, bpf_filter, status, packet_count, started_at) "
                "VALUES (1, 'live:eth0', 'live', 'eth0', 'ip or arp', 'stopped', 42, '2024-01-01')"
            )
        )
    setup_engine.dispose()

    patched_engine = sa.create_engine(f"sqlite:///{db_path}")
    monkeypatch.setattr(db_module, "engine", patched_engine)

    db_module.init_db()

    Session = sa.orm.sessionmaker(bind=patched_engine)
    with Session() as session:
        capture_session = session.query(CaptureSession).filter(CaptureSession.id == 1).one()
        assert capture_session.packet_count == 42  # pre-existing data untouched
        assert capture_session.dropped_count == 0  # backfilled, not None

    # Simulate the column having already been added by an earlier (buggy)
    # startup, with the NULL still sitting there -- init_db() must repair
    # it too, not just skip columns it thinks already exist.
    with patched_engine.begin() as conn:
        conn.execute(sa.text("UPDATE capture_sessions SET dropped_count = NULL WHERE id = 1"))
    db_module.init_db()

    with Session() as session:
        capture_session = session.query(CaptureSession).filter(CaptureSession.id == 1).one()
        assert capture_session.dropped_count == 0


def test_migration_is_a_no_op_on_an_up_to_date_database(tmp_path, monkeypatch):
    db_path = tmp_path / "current.db"
    patched_engine = sa.create_engine(f"sqlite:///{db_path}")
    monkeypatch.setattr(db_module, "engine", patched_engine)

    db_module.init_db()
    db_module.init_db()  # must be safe to run again (e.g. on every app startup)

    columns = {col["name"] for col in sa.inspect(patched_engine).get_columns("devices")}
    assert {"custom_name", "vendor", "custom_vendor", "hostname"} <= columns


def test_migration_backfills_a_default_organization_and_rebuilds_the_device_unique_index(tmp_path, monkeypatch):
    """Regression test for a real bug: a database created before multi-
    tenant support existed has no organizations table and a devices unique
    index scoped to (mac, ip) alone. init_db() must, on such a database:
    create exactly one default Organization, backfill every pre-existing
    users/capture_sessions/devices row's organization_id to point at it, and
    swap the old (mac, ip) unique index for the new (organization_id, mac, ip)
    one -- all without touching the pre-existing data itself, and safely on
    a second run.
    """
    db_path = tmp_path / "legacy_multi_tenant.db"

    setup_engine = sa.create_engine(f"sqlite:///{db_path}")
    with setup_engine.begin() as conn:
        conn.execute(
            sa.text(
                """
                CREATE TABLE devices (
                    id INTEGER PRIMARY KEY,
                    mac VARCHAR(17),
                    ip VARCHAR(45),
                    first_seen DATETIME,
                    last_seen DATETIME,
                    CONSTRAINT uq_device_mac_ip UNIQUE (mac, ip)
                )
                """
            )
        )
        conn.execute(
            sa.text(
                "CREATE TABLE users (id INTEGER PRIMARY KEY, username VARCHAR(64) UNIQUE, "
                "password_salt VARCHAR(32), password_hash VARCHAR(64), role VARCHAR(16), created_at DATETIME)"
            )
        )
        conn.execute(
            sa.text(
                "CREATE TABLE capture_sessions (id INTEGER PRIMARY KEY, name VARCHAR(255), "
                "source_type VARCHAR(16), source VARCHAR(255), status VARCHAR(16), started_at DATETIME)"
            )
        )
        conn.execute(
            sa.text(
                "INSERT INTO devices (mac, ip, first_seen, last_seen) "
                "VALUES ('aa:bb:cc:dd:ee:01', '10.0.0.5', '2024-01-01', '2024-01-01')"
            )
        )
        conn.execute(
            sa.text(
                "INSERT INTO users (username, password_salt, password_hash, role, created_at) "
                "VALUES ('legacyadmin', 'salt', 'hash', 'editor', '2024-01-01')"
            )
        )
    setup_engine.dispose()

    patched_engine = sa.create_engine(f"sqlite:///{db_path}")
    monkeypatch.setattr(db_module, "engine", patched_engine)

    db_module.init_db()

    from app.models import Organization, User

    Session = sa.orm.sessionmaker(bind=patched_engine)
    with Session() as session:
        orgs = session.query(Organization).all()
        assert len(orgs) == 1
        org = orgs[0]

        device = session.query(Device).filter(Device.ip == "10.0.0.5").one()
        assert device.mac == "aa:bb:cc:dd:ee:01"  # pre-existing data untouched
        assert device.organization_id == org.id

        user = session.query(User).filter(User.username == "legacyadmin").one()
        assert user.organization_id == org.id

    index_names = {ix["name"] for ix in sa.inspect(patched_engine).get_indexes("devices")}
    assert "uq_device_org_mac_ip" in index_names
    assert "uq_device_mac_ip" not in index_names

    db_module.init_db()  # must be safe to run again without creating a second organization

    with Session() as session:
        assert session.query(Organization).count() == 1
