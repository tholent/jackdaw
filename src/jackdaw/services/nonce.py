"""Nonce lifecycle: generation, single-use consumption, and background pruning."""

import logging
import secrets
from datetime import timedelta
from typing import cast

from fastapi import HTTPException
from sqlalchemy import delete, func, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession

from jackdaw._util import utcnow as _utcnow
from jackdaw.config import get_settings
from jackdaw.db.models import Nonce

log = logging.getLogger(__name__)


async def generate_nonce(db: AsyncSession) -> str | None:
    """Create and persist a cryptographically random nonce.

    Enforces the ``NONCE_MAX`` safety ceiling: nonces are unauthenticated, so an
    abusive caller could grow the table between prune cycles.  Once the stored
    count reaches the cap, no new nonce is issued (the caller omits the header)
    until pruning drains the backlog.

    Returns:
        The nonce value (URL-safe base64, 32 bytes of entropy), or ``None`` when
        the cap is in force and already reached.
    """
    cap = get_settings().nonce_max
    if cap > 0:
        count = await db.scalar(select(func.count()).select_from(Nonce))
        if count is not None and count >= cap:
            log.warning("Nonce cap of %d reached; not issuing a new nonce", cap)
            return None
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
