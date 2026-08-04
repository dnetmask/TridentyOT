import logging
from contextlib import contextmanager

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import DATABASE_URL

logger = logging.getLogger(__name__)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)

if DATABASE_URL.startswith("sqlite"):
    # Default SQLite (rollback-journal + synchronous=FULL) fsyncs on every
    # commit and blocks all readers while a write transaction is open --
    # fine for occasional writes, but live capture now batches many
    # ingest_packet_record() calls per commit (see live_capture.py) and the
    # API still needs to serve Inventory/Flows reads concurrently while
    # that's happening. WAL lets readers proceed against the last
    # checkpointed state during a writer's transaction; NORMAL still
    # fsyncs at WAL checkpoints, just not on every single commit -- an
    # acceptable durability trade for a monitoring tool (a hard crash could
    # lose the last few ms of buffered writes, never a corrupt DB).
    #
    # WAL only buys concurrent *readers*; SQLite still allows only one
    # writer at a time. A long pcap upload now commits every few hundred
    # packets (see pcap_loader.py's progress tracking) instead of once at
    # the very end, so some other request's write -- e.g. POST /auth/login
    # inserting an auth_tokens row -- has a much bigger window to land
    # while that writer briefly holds the lock. Without busy_timeout,
    # SQLite raises "database is locked" the instant it can't grab the
    # lock immediately instead of just waiting the few milliseconds it
    # actually takes to free up.
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=10000")
        cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def _add_missing_columns() -> None:
    """`Base.metadata.create_all()` only creates missing *tables* -- it never
    alters an existing table, so a database created by an older version of
    the app (before a new column was added to a model) is left without that
    column, and every query against it fails with something like "no such
    column: devices.custom_name".

    This adds any column present in the current models but missing from the
    actual database, via plain `ALTER TABLE ... ADD COLUMN`, which is enough
    for how this app evolves its schema so far -- every change has been a
    new column or a brand-new table (handled by create_all itself), never a
    rename or a drop.

    A plain `ADD COLUMN` never applies the *ORM-level* default
    (`mapped_column(..., default=0)`) to rows that already existed before
    the column did -- SQLite just leaves it NULL for them. That's fine for
    an `Optional` field (custom_name, hostname, ...), but a column the API
    schema declares as a plain non-optional `int`/`float`/`bool`
    (packet_count, dropped_count, os_confidence, device_type_confidence,
    is_ot_suspected, ...) then fails response validation the moment one of
    those pre-existing rows is read back -- e.g. GET /api/capture/sessions
    500ing with "Input should be a valid integer" for dropped_count after
    upgrading to the version that added it. So every column with a plain
    scalar default gets its lingering NULLs backfilled to that default on
    every startup, not just the ones added in *this* run -- a database that
    already picked up the column with NULLs in an earlier startup needs
    the same repair, and this is idempotent (a no-op once there's nothing
    left to fix).
    """
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if table.name not in existing_tables:
                continue  # brand-new table: create_all() already made it, in full
            existing_columns = {col["name"] for col in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name not in existing_columns:
                    col_type = column.type.compile(dialect=engine.dialect)
                    logger.info("Migrating schema: adding %s.%s (%s)", table.name, column.name, col_type)
                    conn.execute(text(f'ALTER TABLE {table.name} ADD COLUMN "{column.name}" {col_type}'))

                default = column.default
                if default is not None and getattr(default, "is_scalar", False):
                    result = conn.execute(
                        text(f'UPDATE {table.name} SET "{column.name}" = :default WHERE "{column.name}" IS NULL'),
                        {"default": default.arg},
                    )
                    if result.rowcount:
                        logger.info(
                            "Migrating schema: backfilled %d NULL row(s) in %s.%s to %r",
                            result.rowcount,
                            table.name,
                            column.name,
                            default.arg,
                        )


def _ensure_default_organization_and_backfill() -> None:
    """`organization_id` on User/CaptureSession/Device is a column that, on
    a database created before multi-tenant support existed, _add_missing_
    columns() above just added as NULL (there's no scalar default like 0/""
    to backfill an FK with). This is the org-specific follow-up: make sure
    at least one Organization row exists -- creating a default one on first
    startup, exactly like seed_default_admin() does for the admin user --
    and point every NULL organization_id at it. Idempotent: a no-op once
    nothing is left to backfill, same as _add_missing_columns.
    """
    from app.models import CaptureSession, Device, Organization, User

    # Session(engine), not SessionLocal(): SessionLocal is a sessionmaker
    # bound once at import time to whatever engine object existed *then* --
    # rebinding the module-level `engine` name afterward (as tests that
    # monkeypatch db_module.engine do) doesn't change what it's bound to.
    # Session(engine) resolves the current `engine` global at call time,
    # same as inspect(engine)/engine.begin() elsewhere in this module.
    with Session(engine) as session:
        org = session.query(Organization).order_by(Organization.id.asc()).first()
        if org is None:
            org = Organization(name="Default Organization", slug="default")
            session.add(org)
            session.flush()
            logger.info("Migrating schema: created default organization (id=%s)", org.id)

        for model in (User, CaptureSession, Device):
            result = session.query(model).filter(model.organization_id.is_(None)).update(
                {"organization_id": org.id}, synchronize_session=False
            )
            if result:
                logger.info(
                    "Migrating schema: backfilled %d row(s) in %s.organization_id to org %d",
                    result,
                    model.__tablename__,
                    org.id,
                )
        session.commit()


def _rebuild_device_unique_constraint() -> None:
    """devices used to be unique on (mac, ip) alone; multi-tenancy needs
    (organization_id, mac, ip) instead, since two different organizations'
    networks can see the same MAC/IP pair without being the same asset.
    `Base.metadata.create_all()` never alters an existing table's
    constraints, so a database that still has the old index needs it
    swapped explicitly -- a brand-new database already gets the new
    definition straight from create_all() and this is a same-name no-op
    for it.
    """
    inspector = inspect(engine)
    if "devices" not in inspector.get_table_names():
        return

    names = {uc["name"] for uc in inspector.get_unique_constraints("devices")}
    names |= {ix["name"] for ix in inspector.get_indexes("devices")}
    if "uq_device_org_mac_ip" in names:
        return

    with engine.begin() as conn:
        if "uq_device_mac_ip" in names:
            logger.info("Migrating schema: rebuilding devices unique constraint to include organization_id")
            # engine.dialect.name, not DATABASE_URL.startswith(...): this
            # function operates on whatever `engine` currently is (see
            # inspect(engine)/engine.begin() above), which a test can point
            # at a different database than the one DATABASE_URL --
            # resolved once, at module import time -- still describes.
            if engine.dialect.name == "sqlite":
                conn.execute(text("DROP INDEX IF EXISTS uq_device_mac_ip"))
            else:
                conn.execute(text("ALTER TABLE devices DROP CONSTRAINT IF EXISTS uq_device_mac_ip"))
        conn.execute(
            text("CREATE UNIQUE INDEX IF NOT EXISTS uq_device_org_mac_ip ON devices (organization_id, mac, ip)")
        )


def _widen_device_identity_text_columns() -> None:
    """firmware_version/custom_firmware_version/model/custom_model briefly
    shipped as VARCHAR(128) (see models.py). Postgres enforces that limit
    strictly, and real-world values routinely exceed it -- a CDP Software
    Version TLV is often a full multi-line IOS banner (version, copyright,
    compile date -- easily 200-400+ characters). Unlike a missing column,
    _add_missing_columns() above never revisits a column that already
    exists with the wrong type, so a database that picked up the narrow
    version needs this explicit widen -- without it, every packet from a
    device with an over-limit value fails to commit, which on a live
    capture (see live_capture.py's _ingest_batch, which has no per-record
    error handling) silently kills the consumer thread and freezes the
    capture. SQLite never enforces VARCHAR length at all, so this is a
    Postgres-only fixup; safe to re-run every startup, since widening an
    already-correctly-sized column is a no-op.
    """
    if engine.dialect.name != "postgresql":
        return
    inspector = inspect(engine)
    if "devices" not in inspector.get_table_names():
        return
    existing_columns = {col["name"] for col in inspector.get_columns("devices")}
    with engine.begin() as conn:
        for column in ("firmware_version", "custom_firmware_version"):
            if column in existing_columns:
                conn.execute(text(f'ALTER TABLE devices ALTER COLUMN "{column}" TYPE TEXT'))
        for column in ("model", "custom_model"):
            if column in existing_columns:
                conn.execute(text(f'ALTER TABLE devices ALTER COLUMN "{column}" TYPE VARCHAR(255)'))


def init_db() -> None:
    from app import models  # noqa: F401  (ensure models are registered)

    Base.metadata.create_all(bind=engine)
    _add_missing_columns()
    _widen_device_identity_text_columns()
    _ensure_default_organization_and_backfill()
    _rebuild_device_unique_constraint()


@contextmanager
def session_scope():
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
