"""Nonce lifecycle: generation, single-use consumption, and background pruning."""

import secrets
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from jackdaw.config import get_settings
from jackdaw.db.models import Nonce


async def generate_nonce(db: AsyncSession) -> str:
    """Create and persist a cryptographically random nonce.

    Returns:
        The nonce value (URL-safe base64, 32 bytes of entropy).
    """
    value = secrets.token_urlsafe(32)
    db.add(Nonce(value=value, used=False, created_at=datetime.now(UTC)))
    await db.commit()
    return value


async def consume_nonce(value: str, db: AsyncSession) -> None:
    """Mark *value* as used; raise HTTP 400 if invalid, reused, or expired.

    Args:
        value: The nonce string from the JWS protected header.
        db:    Active database session.

    Raises:
        HTTPException(400): Nonce not found, already used, or past TTL.
    """
    result = await db.execute(select(Nonce).where(Nonce.value == value))
    nonce = result.scalar_one_or_none()

    if nonce is None or nonce.used:
        raise HTTPException(status_code=400, detail="Invalid or already-used nonce")

    # created_at is stored as naive UTC; treat it as UTC for age calculation.
    age = (datetime.now(UTC) - nonce.created_at.replace(tzinfo=UTC)).total_seconds()
    if age > get_settings().nonce_ttl:
        raise HTTPException(status_code=400, detail="Nonce expired")

    nonce.used = True
    await db.commit()


async def prune_nonces(db: AsyncSession) -> None:
    """Delete all nonce rows older than NONCE_TTL seconds.

    Called periodically by a background task; safe to run concurrently.
    """
    cutoff = datetime.now(UTC) - timedelta(seconds=get_settings().nonce_ttl)
    await db.execute(delete(Nonce).where(Nonce.created_at < cutoff))
    await db.commit()
