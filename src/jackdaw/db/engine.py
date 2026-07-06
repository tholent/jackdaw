"""Async SQLAlchemy engine, session factory, and DB initialisation helper.

The engine and session factory are created lazily on first use (see
``get_engine``/``get_sessionmaker``) rather than at import time.  Importing this
module therefore has no side effect and does not require the environment to be
configured yet — which removes the fragile "set env vars before importing any
jackdaw module" ordering the tests previously depended on.

The module-level names ``engine`` and ``AsyncSessionLocal`` remain available for
backwards compatibility via :pep:`562` ``__getattr__``; accessing either builds
(and caches) the underlying object on demand.
"""

from collections.abc import AsyncGenerator
from functools import lru_cache
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from jackdaw.config import get_settings
from jackdaw.db.models import Base

# Backwards-compatible lazy attributes (resolved by __getattr__ below).  Declared
# for type checkers; they are intentionally never assigned so that attribute
# access falls through to __getattr__.
engine: AsyncEngine
AsyncSessionLocal: async_sessionmaker[AsyncSession]

# Indexes to ensure on existing databases.  ``create_all`` adds indexes only
# for tables it creates, so pre-existing deployments need these explicit,
# idempotent statements.  Names match SQLAlchemy's default (``ix_<table>_<col>``)
# so they are never created twice.
_INDEX_STATEMENTS = (
    "CREATE INDEX IF NOT EXISTS ix_accounts_public_key ON accounts (public_key)",
    "CREATE INDEX IF NOT EXISTS ix_nonces_created_at ON nonces (created_at)",
    "CREATE INDEX IF NOT EXISTS ix_orders_account_id ON orders (account_id)",
)

# Columns added after the initial release.  ``create_all`` never alters an
# existing table, so pre-existing deployments need these applied explicitly.
# SQLite has no ``ADD COLUMN IF NOT EXISTS``, so each is guarded by a
# ``PRAGMA table_info`` check in ``_ensure_columns``.
_ADDED_COLUMNS: tuple[tuple[str, str, str], ...] = (("orders", "error", "TEXT"),)


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


async def _ensure_columns(conn: Any) -> None:
    """Add post-release columns to pre-existing tables (idempotent).

    ``create_all`` creates missing tables but never alters existing ones, so a
    database created by an earlier release is missing columns added later.
    Each column is applied only if ``PRAGMA table_info`` shows it absent.
    """
    for table, column, coltype in _ADDED_COLUMNS:
        result = await conn.execute(text(f"PRAGMA table_info({table})"))
        existing = {row[1] for row in result}
        if column not in existing:
            await conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}"))


async def init_db() -> None:
    """Create all tables, indexes, and columns that do not yet exist (idempotent)."""
    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        for stmt in _INDEX_STATEMENTS:
            await conn.execute(text(stmt))
        await _ensure_columns(conn)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency — yields a DB session and closes it on exit."""
    async with get_sessionmaker()() as session:
        yield session
