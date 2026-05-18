"""Async SQLAlchemy engine, session factory, and DB initialisation helper."""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from jackdaw.config import get_settings
from jackdaw.db.models import Base

_settings = get_settings()
_url = _settings.database_url

# SQLite in-memory databases are connection-local.  Using StaticPool forces
# all SQLAlchemy sessions to share a single connection and therefore a single
# shared in-memory database.  This is a no-op for file-backed databases.
_engine_kwargs: dict[str, object] = {}
if ":memory:" in _url:
    from sqlalchemy.pool import StaticPool

    _engine_kwargs = {
        "connect_args": {"check_same_thread": False},
        "poolclass": StaticPool,
    }

engine = create_async_engine(_url, **_engine_kwargs)

AsyncSessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    engine, expire_on_commit=False
)


async def init_db() -> None:
    """Create all tables that do not yet exist (idempotent)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency — yields a DB session and closes it on exit."""
    async with AsyncSessionLocal() as session:
        yield session
