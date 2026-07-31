"""Regression test for a real bug: a database created by an older version
of the app (before Device.custom_name/vendor/custom_vendor existed) used to
fail every query with "no such column: devices.custom_name", because
Base.metadata.create_all() only creates missing tables, never alters an
existing one. init_db() now also patches in any missing columns.
"""

import sqlalchemy as sa

from app import db as db_module
from app.models import Device


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


def test_migration_is_a_no_op_on_an_up_to_date_database(tmp_path, monkeypatch):
    db_path = tmp_path / "current.db"
    patched_engine = sa.create_engine(f"sqlite:///{db_path}")
    monkeypatch.setattr(db_module, "engine", patched_engine)

    db_module.init_db()
    db_module.init_db()  # must be safe to run again (e.g. on every app startup)

    columns = {col["name"] for col in sa.inspect(patched_engine).get_columns("devices")}
    assert {"custom_name", "vendor", "custom_vendor", "hostname"} <= columns
