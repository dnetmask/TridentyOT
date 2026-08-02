import logging
from contextlib import contextmanager

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

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


def init_db() -> None:
    from app import models  # noqa: F401  (ensure models are registered)

    Base.metadata.create_all(bind=engine)
    _add_missing_columns()


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
