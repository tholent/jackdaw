"""Tests for the Alembic-driven startup migrations in db.engine.

Covers the three startup cases handled by ``_run_migrations``: a fresh
file-backed database, a pre-Alembic database at the old schema (reconciled and
stamped), and an already-migrated database (idempotent re-run).
"""

from __future__ import annotations

from sqlalchemy import create_engine, inspect, text

from jackdaw.db.engine import _run_migrations

_OLD_SCHEMA = (
    "CREATE TABLE accounts (id VARCHAR PRIMARY KEY, public_key TEXT, contact TEXT, "
    "status VARCHAR, created_at DATETIME)",
    "CREATE TABLE orders (id VARCHAR PRIMARY KEY, account_id VARCHAR, status VARCHAR, "
    "identifiers TEXT, le_order_url TEXT, cert_id VARCHAR, expires_at DATETIME, "
    "created_at DATETIME)",
    "CREATE TABLE certificates (id VARCHAR PRIMARY KEY, order_id VARCHAR, pem_chain TEXT, "
    "issued_at DATETIME, expires_at DATETIME)",
    "CREATE TABLE authorizations (id VARCHAR PRIMARY KEY, order_id VARCHAR, "
    "identifier VARCHAR, status VARCHAR, challenge_token VARCHAR, le_authz_url TEXT, "
    "created_at DATETIME)",
    "CREATE TABLE nonces (value VARCHAR PRIMARY KEY, used BOOLEAN, created_at DATETIME)",
)


def _cols(engine, table: str) -> set[str]:
    with engine.connect() as conn:
        return {row[1] for row in conn.execute(text(f"PRAGMA table_info({table})"))}


def test_migrations_fresh_database(tmp_path) -> None:
    """A fresh file DB gets the full schema and is stamped at head."""
    db_path = tmp_path / "fresh.db"
    _run_migrations(f"sqlite+aiosqlite:///{db_path}")

    engine = create_engine(f"sqlite:///{db_path}")
    try:
        tables = set(inspect(engine).get_table_names())
        assert {"accounts", "orders", "certificates", "authorizations", "nonces"} <= tables
        assert "alembic_version" in tables
        assert "serial" in _cols(engine, "certificates")
        assert "error" in _cols(engine, "orders")
        with engine.connect() as conn:
            version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
        assert version == "0001_initial"
    finally:
        engine.dispose()


def test_migrations_pre_alembic_database(tmp_path) -> None:
    """A pre-Alembic DB is reconciled, stamped, and keeps its existing rows."""
    db_path = tmp_path / "legacy.db"
    engine = create_engine(f"sqlite:///{db_path}")
    with engine.begin() as conn:
        for stmt in _OLD_SCHEMA:
            conn.execute(text(stmt))
        conn.execute(
            text("INSERT INTO accounts (id, public_key, status) VALUES ('a1', '{}', 'valid')")
        )
    engine.dispose()

    _run_migrations(f"sqlite+aiosqlite:///{db_path}")

    engine = create_engine(f"sqlite:///{db_path}")
    try:
        # Late columns backfilled.
        assert "error" in _cols(engine, "orders")
        assert "serial" in _cols(engine, "certificates")
        with engine.connect() as conn:
            # Stamped at baseline.
            version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
            assert version == "0001_initial"
            # Existing data preserved.
            assert conn.execute(text("SELECT id FROM accounts")).scalar() == "a1"
    finally:
        engine.dispose()


def test_migrations_idempotent_rerun(tmp_path) -> None:
    """Running migrations twice is a no-op the second time (already at head)."""
    db_path = tmp_path / "rerun.db"
    url = f"sqlite+aiosqlite:///{db_path}"
    _run_migrations(url)
    # Second run must not raise.
    _run_migrations(url)

    engine = create_engine(f"sqlite:///{db_path}")
    try:
        with engine.connect() as conn:
            rows = conn.execute(text("SELECT COUNT(*) FROM alembic_version")).scalar()
        assert rows == 1
    finally:
        engine.dispose()
