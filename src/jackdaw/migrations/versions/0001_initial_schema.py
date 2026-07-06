"""Initial schema — baseline at Alembic adoption.

This revision is a frozen snapshot of the schema exactly as the pre-Alembic
``Base.metadata.create_all`` + hand-rolled column/index hooks produced it. It is
written as raw SQL (rather than derived from the models) so it never drifts when
the models change — later schema changes get their own revisions.

Revision ID: 0001_initial
Revises:
Create Date: 2026-07-06
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# Exact DDL captured from the pre-Alembic schema.  Order is chosen so tables are
# created before those that only forward-reference them; the orders/certificates
# cycle is fine because SQLite does not validate FK targets at CREATE time.
_TABLES: tuple[str, ...] = (
    """
    CREATE TABLE accounts (
        id VARCHAR NOT NULL,
        public_key TEXT NOT NULL,
        contact TEXT,
        status VARCHAR NOT NULL,
        created_at DATETIME NOT NULL,
        PRIMARY KEY (id)
    )
    """,
    """
    CREATE TABLE certificates (
        id VARCHAR NOT NULL,
        order_id VARCHAR NOT NULL,
        pem_chain TEXT NOT NULL,
        issued_at DATETIME NOT NULL,
        expires_at DATETIME NOT NULL,
        serial VARCHAR,
        PRIMARY KEY (id),
        FOREIGN KEY(order_id) REFERENCES orders (id)
    )
    """,
    """
    CREATE TABLE nonces (
        value VARCHAR NOT NULL,
        used BOOLEAN NOT NULL,
        created_at DATETIME NOT NULL,
        PRIMARY KEY (value)
    )
    """,
    """
    CREATE TABLE orders (
        id VARCHAR NOT NULL,
        account_id VARCHAR NOT NULL,
        status VARCHAR NOT NULL,
        identifiers TEXT NOT NULL,
        le_order_url TEXT,
        cert_id VARCHAR,
        expires_at DATETIME,
        created_at DATETIME NOT NULL,
        error TEXT,
        PRIMARY KEY (id),
        FOREIGN KEY(account_id) REFERENCES accounts (id),
        FOREIGN KEY(cert_id) REFERENCES certificates (id)
    )
    """,
    """
    CREATE TABLE authorizations (
        id VARCHAR NOT NULL,
        order_id VARCHAR NOT NULL,
        identifier VARCHAR NOT NULL,
        status VARCHAR NOT NULL,
        challenge_token VARCHAR,
        le_authz_url TEXT,
        created_at DATETIME NOT NULL,
        PRIMARY KEY (id),
        FOREIGN KEY(order_id) REFERENCES orders (id)
    )
    """,
)

_INDEXES: tuple[str, ...] = (
    "CREATE INDEX ix_accounts_public_key ON accounts (public_key)",
    "CREATE INDEX ix_certificates_serial ON certificates (serial)",
    "CREATE INDEX ix_nonces_created_at ON nonces (created_at)",
    "CREATE INDEX ix_orders_account_id ON orders (account_id)",
)

_TABLE_NAMES: tuple[str, ...] = (
    "authorizations",
    "orders",
    "nonces",
    "certificates",
    "accounts",
)


def upgrade() -> None:
    for stmt in _TABLES:
        op.execute(stmt)
    for stmt in _INDEXES:
        op.execute(stmt)


def downgrade() -> None:
    for name in _TABLE_NAMES:
        op.execute(f"DROP TABLE {name}")
