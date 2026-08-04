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
        conn.execute(
            sa.text(
                "INSERT INTO capture_sessions (name, source_type, source, status, started_at) "
                "VALUES ('legacy capture', 'pcap', 'legacy.pcap', 'completed', '2024-01-01')"
            )
        )
    setup_engine.dispose()

    patched_engine = sa.create_engine(f"sqlite:///{db_path}")
    monkeypatch.setattr(db_module, "engine", patched_engine)

    db_module.init_db()

    from app.models import CaptureSession, Organization, Sensor, Site, User, Zone

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
        assert user.role == "admin"  # migrated from the old 2-tier "editor"

        site = session.query(Site).filter(Site.organization_id == org.id).one()
        zone = session.query(Zone).filter(Zone.site_id == site.id).one()
        sensor = session.query(Sensor).filter(Sensor.zone_id == zone.id).one()

        capture_session = session.query(CaptureSession).filter(CaptureSession.name == "legacy capture").one()
        assert capture_session.sensor_id == sensor.id  # pre-existing session backfilled to the default sensor

    index_names = {ix["name"] for ix in sa.inspect(patched_engine).get_indexes("devices")}
    assert "uq_device_org_mac_ip" in index_names
    assert "uq_device_mac_ip" not in index_names

    user_indexes = {ix["name"]: ix for ix in sa.inspect(patched_engine).get_indexes("users")}
    assert "uq_user_org_username" in user_indexes
    assert "uq_user_username_super_admin" in user_indexes

    db_module.init_db()  # must be safe to run again without creating a second organization

    with Session() as session:
        assert session.query(Organization).count() == 1


def test_migration_rebuilds_a_pre_existing_globally_unique_username_index(tmp_path, monkeypatch):
    """Regression test: a database created by an older version of this app
    (via create_all(), before the 3-role model existed) has username as a
    single globally-unique index -- exactly what init_db() must relax to
    per-organization, per _rebuild_user_unique_constraint's docstring.
    """
    db_path = tmp_path / "legacy_global_username.db"

    setup_engine = sa.create_engine(f"sqlite:///{db_path}")
    with setup_engine.begin() as conn:
        conn.execute(
            sa.text(
                "CREATE TABLE organizations (id INTEGER PRIMARY KEY, name VARCHAR(255), "
                "slug VARCHAR(64) UNIQUE, deployment_mode VARCHAR(16), default_locale VARCHAR(5), "
                "created_at DATETIME)"
            )
        )
        conn.execute(
            sa.text("INSERT INTO organizations (name, slug, deployment_mode, default_locale, created_at) "
                     "VALUES ('Org A', 'org-a', 'self_hosted', 'es', '2024-01-01')")
        )
        conn.execute(
            sa.text(
                "CREATE TABLE users (id INTEGER PRIMARY KEY, organization_id INTEGER, "
                "username VARCHAR(64), password_salt VARCHAR(32), password_hash VARCHAR(64), "
                "role VARCHAR(16), locale VARCHAR(5), created_at DATETIME)"
            )
        )
        conn.execute(sa.text("CREATE UNIQUE INDEX ix_users_username ON users (username)"))
        conn.execute(
            sa.text(
                "INSERT INTO users (organization_id, username, password_salt, password_hash, role, "
                "locale, created_at) VALUES (1, 'admin', 'salt', 'hash', 'editor', 'es', '2024-01-01')"
            )
        )
    setup_engine.dispose()

    patched_engine = sa.create_engine(f"sqlite:///{db_path}")
    monkeypatch.setattr(db_module, "engine", patched_engine)

    db_module.init_db()

    from app.models import Organization, User

    Session = sa.orm.sessionmaker(bind=patched_engine)
    with Session() as session:
        # A second organization picking the same username must now succeed
        # -- impossible under the old globally-unique index this test set up.
        other_org = Organization(name="Org B", slug="org-b")
        session.add(other_org)
        session.flush()
        session.add(
            User(
                organization_id=other_org.id,
                username="admin",
                password_salt="salt",
                password_hash="hash",
                role="admin",
                locale="es",
            )
        )
        session.commit()  # must not raise

        assert session.query(User).filter(User.username == "admin").count() == 2


def test_firmware_and_model_columns_are_not_narrowly_length_bounded():
    """Regression test for a real bug: devices.firmware_version and
    devices.model briefly shipped as VARCHAR(128). SQLite never enforces a
    VARCHAR length, so that limit only ever bit on Postgres -- a CDP
    Software Version TLV is routinely a full multi-line IOS banner (200-400+
    characters), and an INSERT/UPDATE exceeding the column's limit fails
    outright there. On a live capture, that failure had no per-record
    handling to catch it (see live_capture.py's _consume_loop), so it
    silently killed the consumer thread and froze the capture with no
    error shown anywhere. firmware_version/custom_firmware_version must
    stay unbounded (Text); model/custom_model must stay wide enough (>=255)
    for any real-world Platform/productName/order-code string.
    """
    columns = Device.__table__.columns
    for name in ("firmware_version", "custom_firmware_version"):
        assert getattr(columns[name].type, "length", None) is None, (
            f"devices.{name} must be an unbounded Text column, not a length-bounded VARCHAR"
        )
    for name in ("model", "custom_model"):
        length = columns[name].type.length
        assert length is None or length >= 255, f"devices.{name} must allow at least 255 characters"
