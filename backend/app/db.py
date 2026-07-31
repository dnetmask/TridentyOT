import logging
from contextlib import contextmanager

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import DATABASE_URL

logger = logging.getLogger(__name__)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def _add_missing_columns() -> None:
    """`Base.metadata.create_all()` only creates missing *tables* -- it never
    alters an existing table, so a database created by an older version of
    the app (before a new nullable column was added to a model) is left
    without that column, and every query against it fails with something
    like "no such column: devices.custom_name".

    This adds any column present in the current models but missing from the
    actual database, via plain `ALTER TABLE ... ADD COLUMN`, which is enough
    for how this app evolves its schema so far -- every change has been a
    new nullable column or a brand-new table (handled by create_all itself),
    never a rename, a drop, or a new NOT NULL column. Existing rows and data
    are left untouched; the new column is simply NULL for them.
    """
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if table.name not in existing_tables:
                continue  # brand-new table: create_all() already made it, in full
            existing_columns = {col["name"] for col in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in existing_columns:
                    continue
                col_type = column.type.compile(dialect=engine.dialect)
                logger.info("Migrating schema: adding %s.%s (%s)", table.name, column.name, col_type)
                conn.execute(text(f'ALTER TABLE {table.name} ADD COLUMN "{column.name}" {col_type}'))


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
