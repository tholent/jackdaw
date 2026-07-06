"""Alembic environment — synchronous, driven programmatically from db.engine.

Jackdaw runs migrations at startup via ``alembic.command`` (see
``db.engine._run_migrations``), passing a plain synchronous SQLite URL.  We keep
this env.py deliberately simple: a sync engine, online migrations only.  The
async application engine is separate and connects to the same file afterwards.
"""

from __future__ import annotations

from alembic import context
from sqlalchemy import engine_from_config, pool

from jackdaw.db.models import Base

config = context.config
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Emit SQL to stdout without a DB connection (``alembic upgrade --sql``)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live synchronous connection."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        # ``render_as_batch`` lets future migrations use batch operations, which
        # SQLite needs for most ALTERs (table copy under the hood).
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,
        )
        with context.begin_transaction():
            context.run_migrations()
    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
