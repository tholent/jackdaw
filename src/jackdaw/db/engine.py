"""Async SQLAlchemy engine, session factory, and DB initialisation helper.

The engine and session factory are created lazily on first use (see
``get_engine``/``get_sessionmaker``) rather than at import time.  Importing this
module therefore has no side effect and does not require the environment to be
configured yet — which removes the fragile "set env vars before importing any
jackdaw module" ordering the tests previously depended on.

The module-level names ``engine`` and ``AsyncSessionLocal`` remain available for
backwards compatibility via :pep:`562` ``__getattr__``; accessing either builds
(and caches) the underlying object on demand.

Schema management: file-backed databases are migrated with Alembic at startup
(see ``_run_migrations``).  In-memory databases — used only by the test suite,
where each connection is its own ephemeral DB — are built directly from the ORM
metadata instead, since Alembic's separate synchronous connection could not see
them.
"""

import asyncio
import logging
from collections.abc import AsyncGenerator
from functools import lru_cache
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from jackdaw.config import get_settings
from jackdaw.db.models import Base

log = logging.getLogger(__name__)

# Backwards-compatible lazy attributes (resolved by __getattr__ below).  Declared
# for type checkers; they are intentionally never assigned so that attribute
# access falls through to __getattr__.
engine: AsyncEngine
AsyncSessionLocal: async_sessionmaker[AsyncSession]

# Late-added columns, applied idempotently to a pre-Alembic database before it is
# stamped (see ``_reconcile_pre_alembic``).  A DB from an early release that was
# never started under the current hand-rolled code could still be missing these,
# so we converge it to the Alembic baseline before claiming it matches.
_PRE_ALEMBIC_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("orders", "error", "TEXT"),
    ("certificates", "serial", "TEXT"),
)
_PRE_ALEMBIC_INDEXES: tuple[str, ...] = (
    "CREATE INDEX IF NOT EXISTS ix_accounts_public_key ON accounts (public_key)",
    "CREATE INDEX IF NOT EXISTS ix_nonces_created_at ON nonces (created_at)",
    "CREATE INDEX IF NOT EXISTS ix_orders_account_id ON orders (account_id)",
    "CREATE INDEX IF NOT EXISTS ix_certificates_serial ON certificates (serial)",
)


@lru_cache(maxsize=1)
def get_engine() -> AsyncEngine:
    """Return the process-wide async engine, creating it on first call."""
    url = get_settings().database_url

    # SQLite in-memory databases are connection-local.  Using StaticPool forces
    # all SQLAlchemy sessions to share a single connection and therefore a single
    # shared in-memory database.  This is a no-op for file-backed databases.
    engine_kwargs: dict[str, Any] = {}
    if ":memory:" in url:
        from sqlalchemy.pool import StaticPool

        engine_kwargs = {
            "connect_args": {"check_same_thread": False},
            "poolclass": StaticPool,
        }

    return create_async_engine(url, **engine_kwargs)


@lru_cache(maxsize=1)
def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    """Return the process-wide session factory, creating it on first call."""
    return async_sessionmaker(get_engine(), expire_on_commit=False)


def __getattr__(name: str) -> Any:
    if name == "engine":
        return get_engine()
    if name == "AsyncSessionLocal":
        return get_sessionmaker()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def _sync_url(async_url: str) -> str:
    """Convert an aiosqlite URL to its synchronous pysqlite form for Alembic."""
    return async_url.replace("+aiosqlite", "")


def _alembic_config(sync_url: str) -> Any:
    """Build an Alembic ``Config`` pointing at the packaged migration scripts."""
    from alembic.config import Config

    migrations_dir = Path(__file__).resolve().parent.parent / "migrations"
    cfg = Config()
    cfg.set_main_option("script_location", str(migrations_dir))
    cfg.set_main_option("sqlalchemy.url", sync_url)
    return cfg


def _reconcile_pre_alembic(sync_engine: Any) -> None:
    """Bring a pre-Alembic database up to the baseline schema before stamping.

    A database created by an early release and never started under the later
    hand-rolled column/index code could be missing the ``error``/``serial``
    columns or some indexes.  Applying them idempotently here guarantees the DB
    actually matches revision ``0001_initial`` before we stamp it as migrated.
    """
    with sync_engine.begin() as conn:
        for table, column, coltype in _PRE_ALEMBIC_COLUMNS:
            cols = {row[1] for row in conn.execute(text(f"PRAGMA table_info({table})"))}
            if cols and column not in cols:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}"))
        for stmt in _PRE_ALEMBIC_INDEXES:
            conn.execute(text(stmt))


def _run_migrations(async_url: str) -> None:
    """Migrate a file-backed database to head (synchronous; run in a thread).

    Three cases:

    - ``alembic_version`` present → a normal Alembic-managed DB; upgrade to head.
    - core tables present but no ``alembic_version`` → a pre-Alembic DB already at
      the baseline schema; reconcile any missing late columns/indexes, then stamp
      it at the baseline so future upgrades apply.
    - no tables → a fresh DB; upgrade from empty creates everything.
    """
    from alembic import command

    sync_url = _sync_url(async_url)
    cfg = _alembic_config(sync_url)
    sync_engine = create_engine(sync_url)
    try:
        table_names = set(inspect(sync_engine).get_table_names())
        if "alembic_version" in table_names:
            command.upgrade(cfg, "head")
        elif "accounts" in table_names:
            log.info("Pre-Alembic database detected; reconciling and stamping baseline")
            _reconcile_pre_alembic(sync_engine)
            command.stamp(cfg, "0001_initial")
            command.upgrade(cfg, "head")
        else:
            command.upgrade(cfg, "head")
    finally:
        sync_engine.dispose()


async def init_db() -> None:
    """Ensure the database schema is current.

    File-backed databases are migrated with Alembic (in a worker thread, since
    Alembic's command API is synchronous).  In-memory databases are connection-
    local — Alembic's separate connection could not see them — so the test suite's
    in-memory schema is built directly from the ORM metadata instead.
    """
    url = get_settings().database_url
    if ":memory:" in url:
        async with get_engine().begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        return
    await asyncio.to_thread(_run_migrations, url)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency — yields a DB session and closes it on exit."""
    async with get_sessionmaker()() as session:
        yield session
