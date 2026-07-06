"""Tests for the hand-rolled schema-migration helpers in db.engine.

These cover upgrading a database created by an earlier release (missing columns
that were added later).  When Alembic replaces the hand-rolled path, this file
is superseded by the Alembic upgrade test.
"""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine


async def test_ensure_columns_adds_missing_serial(tmp_path) -> None:
    """_ensure_columns adds certificates.serial to an old-schema DB, idempotently."""
    from jackdaw.db.engine import _ensure_columns

    db_path = tmp_path / "old.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    try:
        # Old schema: certificates without serial; orders already has error.
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "CREATE TABLE certificates ("
                    "id TEXT PRIMARY KEY, order_id TEXT, pem_chain TEXT, "
                    "issued_at DATETIME, expires_at DATETIME)"
                )
            )
            await conn.execute(text("CREATE TABLE orders (id TEXT PRIMARY KEY, error TEXT)"))

        async with engine.begin() as conn:
            await _ensure_columns(conn)
            # Second pass must be a no-op, not an error (idempotent).
            await _ensure_columns(conn)

        async with engine.connect() as conn:
            result = await conn.execute(text("PRAGMA table_info(certificates)"))
            cols = {row[1] for row in result}
        assert "serial" in cols
    finally:
        await engine.dispose()


async def test_ensure_columns_leaves_existing_columns(tmp_path) -> None:
    """A column that already exists is not re-added (no duplicate-column error)."""
    from jackdaw.db.engine import _ensure_columns

    db_path = tmp_path / "current.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "CREATE TABLE certificates ("
                    "id TEXT PRIMARY KEY, order_id TEXT, pem_chain TEXT, "
                    "issued_at DATETIME, expires_at DATETIME, serial TEXT)"
                )
            )
            await conn.execute(text("CREATE TABLE orders (id TEXT PRIMARY KEY, error TEXT)"))
            await conn.execute(text("INSERT INTO certificates (id, serial) VALUES ('c1', 'abc')"))

        async with engine.begin() as conn:
            await _ensure_columns(conn)

        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT serial FROM certificates WHERE id='c1'"))
            assert result.scalar_one() == "abc"
    finally:
        await engine.dispose()
