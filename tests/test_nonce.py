"""Unit tests for nonce generation, consumption, and expiry."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

if TYPE_CHECKING:
    from httpx import AsyncClient

from jackdaw.db.models import Nonce
from jackdaw.services.nonce import consume_nonce, generate_nonce, prune_nonces


async def test_generate_returns_string(db_session: AsyncSession) -> None:
    nonce = await generate_nonce(db_session)
    assert isinstance(nonce, str)
    assert len(nonce) > 0


async def test_generate_is_unique(db_session: AsyncSession) -> None:
    n1 = await generate_nonce(db_session)
    n2 = await generate_nonce(db_session)
    assert n1 != n2


async def test_consume_marks_used(db_session: AsyncSession) -> None:
    nonce = await generate_nonce(db_session)
    # Should succeed without raising.
    await consume_nonce(nonce, db_session)


async def test_consume_rejects_reuse(db_session: AsyncSession) -> None:
    nonce = await generate_nonce(db_session)
    await consume_nonce(nonce, db_session)

    with pytest.raises(HTTPException) as exc_info:
        await consume_nonce(nonce, db_session)

    assert exc_info.value.status_code == 400


async def test_consume_rejects_unknown(db_session: AsyncSession) -> None:
    with pytest.raises(HTTPException) as exc_info:
        await consume_nonce("not-a-real-nonce", db_session)

    assert exc_info.value.status_code == 400


async def test_consume_rejects_expired(db_session: AsyncSession) -> None:
    # Manually insert a nonce with an old timestamp.
    old_ts = datetime.now(UTC) - timedelta(seconds=700)  # past default 600s TTL
    db_session.add(Nonce(value="expired-nonce", used=False, created_at=old_ts))
    await db_session.commit()

    with pytest.raises(HTTPException) as exc_info:
        await consume_nonce("expired-nonce", db_session)

    assert exc_info.value.status_code == 400


async def test_prune_removes_old_nonces(db_session: AsyncSession) -> None:
    # One old, one fresh.
    old_ts = datetime.now(UTC) - timedelta(seconds=700)
    db_session.add(Nonce(value="old", used=False, created_at=old_ts))
    fresh = await generate_nonce(db_session)

    await prune_nonces(db_session)

    from sqlalchemy import select

    result = await db_session.execute(select(Nonce).where(Nonce.value == "old"))
    assert result.scalar_one_or_none() is None

    result = await db_session.execute(select(Nonce).where(Nonce.value == fresh))
    assert result.scalar_one_or_none() is not None


# ---------------------------------------------------------------------------
# HTTP route tests — HEAD and POST /acme/new-nonce
# ---------------------------------------------------------------------------


async def test_head_new_nonce_returns_200(
    test_client: "AsyncClient", db_session: AsyncSession
) -> None:
    """HEAD /acme/new-nonce must return 200 with a Replay-Nonce header."""
    resp = await test_client.head("/acme/new-nonce")
    assert resp.status_code == 200
    assert "replay-nonce" in resp.headers


async def test_post_new_nonce_returns_204(
    test_client: "AsyncClient", db_session: AsyncSession
) -> None:
    """POST /acme/new-nonce must return 204 with a Replay-Nonce header."""
    resp = await test_client.post("/acme/new-nonce")
    assert resp.status_code == 204
    assert "replay-nonce" in resp.headers
