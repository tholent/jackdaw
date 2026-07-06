"""Tests for the FastAPI app wiring in jackdaw.main: lifespan, the nonce-prune
loop, and the Replay-Nonce middleware's behaviour at the nonce cap."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession


async def _noop(*_args, **_kwargs) -> None:
    return None


# ---------------------------------------------------------------------------
# lifespan
# ---------------------------------------------------------------------------


async def test_lifespan_initialises_state_and_tears_down() -> None:
    """lifespan registers the LE client + DNS provider on app.state and launches
    the background tasks, then cancels them on exit."""
    from jackdaw.main import app, lifespan

    fake_client = Mock()
    with (
        patch("jackdaw.main.le.init_account", new=AsyncMock(return_value=fake_client)) as init_acct,
        patch("jackdaw.main.get_provider", return_value=Mock()) as get_prov,
        patch("jackdaw.main._prune_loop", new=lambda: _noop()),
        patch("jackdaw.main.relay_cert.renewal_loop", new=lambda *a, **k: _noop()),
    ):
        async with lifespan(app):
            assert app.state.le_client is fake_client
            assert app.state.dns_provider is not None

    init_acct.assert_awaited_once()
    get_prov.assert_called_once()


async def test_lifespan_rejects_verify_ssl_false_with_production() -> None:
    """The startup guard refuses LE_VERIFY_SSL=false against the production CA."""
    from jackdaw.main import _LE_PRODUCTION_URL, app, lifespan

    with patch("jackdaw.main.get_settings") as ms:
        ms.return_value.le_verify_ssl = False
        ms.return_value.le_directory = _LE_PRODUCTION_URL
        ms.return_value.log_level = "INFO"
        with pytest.raises(RuntimeError, match="LE_VERIFY_SSL=false"):
            async with lifespan(app):
                pass


# ---------------------------------------------------------------------------
# _prune_loop
# ---------------------------------------------------------------------------


async def test_prune_loop_prunes_then_exits() -> None:
    """One loop iteration calls prune_nonces; the loop exits when cancelled."""
    from jackdaw.main import _prune_loop

    calls = 0

    async def fake_sleep(_seconds: float) -> None:
        nonlocal calls
        calls += 1
        if calls >= 2:  # first sleep returns → prune runs; second stops the loop
            raise asyncio.CancelledError

    with (
        patch("jackdaw.main.asyncio.sleep", side_effect=fake_sleep),
        patch("jackdaw.main.prune_nonces", new=AsyncMock()) as prune,
    ):
        with pytest.raises(asyncio.CancelledError):
            await _prune_loop()

    prune.assert_awaited_once()


# ---------------------------------------------------------------------------
# Replay-Nonce middleware at the cap
# ---------------------------------------------------------------------------


async def test_middleware_omits_nonce_header_when_capped(
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    """When generate_nonce returns None (cap reached), no Replay-Nonce is set."""
    with patch("jackdaw.main.generate_nonce", new=AsyncMock(return_value=None)):
        resp = await test_client.head("/acme/new-nonce")

    assert resp.status_code == 200
    assert "replay-nonce" not in resp.headers
