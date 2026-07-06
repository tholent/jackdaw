"""Nonce lifecycle: generation, single-use consumption, and background pruning."""

import secrets
from datetime import timedelta
from typing import cast

from fastapi import HTTPException
from sqlalchemy import delete, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession

from jackdaw._util import utcnow as _utcnow
from jackdaw.config import get_settings
from jackdaw.db.models import Nonce


async def generate_nonce(db: AsyncSession) -> str:
    """Create and persist a cryptographically random nonce.

    Returns:
        The nonce value (URL-safe base64, 32 bytes of entropy).
    """
    value = secrets.token_urlsafe(32)
    db.add(Nonce(value=value, used=False, created_at=_utcnow()))
    await db.commit()
    return value


async def consume_nonce(value: str, db: AsyncSession) -> None:
    """Atomically mark *value* as used; raise HTTP 400 if invalid, reused, or expired.

    Uses a single UPDATE ... WHERE to avoid the SELECT-then-UPDATE TOCTOU race
    that would allow concurrent requests to consume the same nonce.

    Args:
        value: The nonce string from the JWS protected header.
        db:    Active database session.

    Raises:
        HTTPException(400): Nonce not found, already used, or past TTL.
    """
    # created_at is stored as naive UTC; compute cutoff as naive UTC too.
    cutoff = _utcnow() - timedelta(seconds=get_settings().nonce_ttl)
    cursor = cast(
        CursorResult[tuple[()]],
        await db.execute(
            update(Nonce)
            .where(Nonce.value == value, ~Nonce.used, Nonce.created_at >= cutoff)
            .values(used=True)
        ),
    )
    await db.commit()
    if cursor.rowcount == 0:
        raise HTTPException(status_code=400, detail="Invalid, already-used, or expired nonce")


async def prune_nonces(db: AsyncSession) -> None:
    """Delete all nonce rows older than NONCE_TTL seconds.

    Called periodically by a background task; safe to run concurrently.
    """
    cutoff = _utcnow() - timedelta(seconds=get_settings().nonce_ttl)
    await db.execute(delete(Nonce).where(Nonce.created_at < cutoff))
    await db.commit()
