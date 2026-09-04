"""Add ``error`` column to ``authorizations``.

Lets a failed HTTP-01 validation persist an RFC 8555 §7.1.6 problem document on
the authorization, so the client (and its logs) learn *why* the authorization
became ``invalid`` instead of receiving an empty problem.

Revision ID: 0002_authz_error
Revises: 0001_initial
Create Date: 2026-09-04
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002_authz_error"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TABLE authorizations ADD COLUMN error TEXT")


def downgrade() -> None:
    op.execute("ALTER TABLE authorizations DROP COLUMN error")
