"""Unit tests for nonce generation, consumption, and expiry."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

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


async def test_generate_returns_none_at_cap(db_session: AsyncSession) -> None:
    """generate_nonce returns None once the NONCE_MAX cap is reached."""
    from unittest.mock import patch

    # Pre-seed two nonce rows, then set the cap to 2.
    db_session.add(Nonce(value="cap-a", used=False, created_at=datetime.now(UTC)))
    db_session.add(Nonce(value="cap-b", used=False, created_at=datetime.now(UTC)))
    await db_session.commit()

    with patch("jackdaw.services.nonce.get_settings") as ms:
        ms.return_value.nonce_max = 2
        result = await generate_nonce(db_session)
    assert result is None


async def test_generate_issues_below_cap(db_session: AsyncSession) -> None:
    """Below the cap, generate_nonce still issues a nonce."""
    from unittest.mock import patch

    with patch("jackdaw.services.nonce.get_settings") as ms:
        ms.return_value.nonce_max = 10
        result = await generate_nonce(db_session)
    assert isinstance(result, str)


async def test_cap_disabled_when_zero(db_session: AsyncSession) -> None:
    """A cap of 0 disables the ceiling entirely."""
    from unittest.mock import patch

    db_session.add(Nonce(value="z1", used=False, created_at=datetime.now(UTC)))
    await db_session.commit()
    with patch("jackdaw.services.nonce.get_settings") as ms:
        ms.return_value.nonce_max = 0
        result = await generate_nonce(db_session)
    assert isinstance(result, str)


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
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    """HEAD /acme/new-nonce must return 200 with a Replay-Nonce header."""
    resp = await test_client.head("/acme/new-nonce")
    assert resp.status_code == 200
    assert "replay-nonce" in resp.headers


async def test_post_new_nonce_returns_204(
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    """POST /acme/new-nonce must return 204 with a Replay-Nonce header."""
    resp = await test_client.post("/acme/new-nonce")
    assert resp.status_code == 204
    assert "replay-nonce" in resp.headers
