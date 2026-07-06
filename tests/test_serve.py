"""Tests for the serve entry-point: TLS-mode selection, the ensure-cert
policy (block/retry/fall-back), and the renewal loop's in-place SSLContext
reload."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, Mock, call, patch

import pytest

from jackdaw.config import Settings
from jackdaw.serve import _ensure_relay_cert, _tls_enabled


def _settings(**overrides: Any) -> Settings:
    defaults: dict[str, Any] = {
        "dns_provider": "null",
        "relay_domain": "relay.test",
        "acme_email": "a@b.com",
    }
    defaults.update(overrides)
    return Settings(**defaults)


# ---------------------------------------------------------------------------
# _tls_enabled
# ---------------------------------------------------------------------------


def test_tls_enabled_by_default() -> None:
    assert _tls_enabled(_settings()) is True


def test_tls_disabled_by_setting() -> None:
    assert _tls_enabled(_settings(serve_tls=False)) is False


def test_tls_disabled_when_relay_domain_has_scheme() -> None:
    """A relay_domain with a scheme means local-dev plain-HTTP mode."""
    assert _tls_enabled(_settings(relay_domain="http://localhost:8000")) is False


# ---------------------------------------------------------------------------
# _ensure_relay_cert
# ---------------------------------------------------------------------------


async def test_ensure_returns_immediately_when_cert_healthy() -> None:
    """A cert with more than the renewal threshold remaining needs no LE contact."""
    with (
        patch("jackdaw.serve.relay_cert_exists", return_value=True),
        patch("jackdaw.serve.relay_cert_days_remaining", return_value=60.0),
        patch("jackdaw.serve.le.init_account", new_callable=AsyncMock) as init_account,
    ):
        await _ensure_relay_cert(_settings())

    init_account.assert_not_awaited()


async def test_ensure_issues_when_cert_missing() -> None:
    with (
        patch("jackdaw.serve.relay_cert_exists", return_value=False),
        patch("jackdaw.serve.get_provider"),
        patch("jackdaw.serve.le.init_account", new_callable=AsyncMock),
        patch("jackdaw.serve.issue_relay_cert", new_callable=AsyncMock) as issue,
    ):
        await _ensure_relay_cert(_settings())

    issue.assert_awaited_once()


async def test_ensure_retries_with_backoff_until_issuance_succeeds() -> None:
    """With no usable cert, failed issuance is retried — HTTPS must not come up
    without a real certificate, so the loop only exits on success."""
    with (
        patch("jackdaw.serve.relay_cert_exists", return_value=False),
        patch("jackdaw.serve.get_provider"),
        patch("jackdaw.serve.le.init_account", new_callable=AsyncMock),
        patch(
            "jackdaw.serve.issue_relay_cert",
            new_callable=AsyncMock,
            side_effect=[RuntimeError("boom"), RuntimeError("boom"), None],
        ) as issue,
        patch("asyncio.sleep", new_callable=AsyncMock) as sleep,
    ):
        await _ensure_relay_cert(_settings())

    assert issue.await_count == 3
    assert sleep.await_args_list == [call(60), call(120)]


async def test_ensure_serves_existing_cert_when_renewal_fails() -> None:
    """A still-valid cert inside the renewal window is served even if the
    renewal attempt fails; the daily renewal loop owns the retries."""
    with (
        patch("jackdaw.serve.relay_cert_exists", return_value=True),
        patch("jackdaw.serve.relay_cert_days_remaining", return_value=10.0),
        patch("jackdaw.serve.get_provider"),
        patch("jackdaw.serve.le.init_account", new_callable=AsyncMock),
        patch(
            "jackdaw.serve.issue_relay_cert",
            new_callable=AsyncMock,
            side_effect=RuntimeError("boom"),
        ) as issue,
    ):
        await _ensure_relay_cert(_settings())

    issue.assert_awaited_once()


async def test_ensure_retries_when_cert_expired() -> None:
    """An expired cert is as good as none: block and retry, don't serve it."""
    with (
        patch("jackdaw.serve.relay_cert_exists", return_value=True),
        patch("jackdaw.serve.relay_cert_days_remaining", return_value=-1.0),
        patch("jackdaw.serve.get_provider"),
        patch("jackdaw.serve.le.init_account", new_callable=AsyncMock),
        patch(
            "jackdaw.serve.issue_relay_cert",
            new_callable=AsyncMock,
            side_effect=[RuntimeError("boom"), None],
        ) as issue,
        patch("asyncio.sleep", new_callable=AsyncMock),
    ):
        await _ensure_relay_cert(_settings())

    assert issue.await_count == 2


# ---------------------------------------------------------------------------
# _renewal_loop SSLContext reload
# ---------------------------------------------------------------------------


async def test_renewal_loop_reloads_ssl_context_after_renewal(tmp_path) -> None:
    """After a successful renewal the live SSLContext is reloaded in place."""
    from jackdaw.services.relay_cert import renewal_loop

    ctx = Mock()
    sleep_count = 0

    async def fake_sleep(_seconds: float) -> None:
        nonlocal sleep_count
        sleep_count += 1
        if sleep_count > 1:  # one renewal cycle, then stop the loop
            raise asyncio.CancelledError

    with (
        patch("asyncio.sleep", side_effect=fake_sleep),
        patch("jackdaw.services.relay_cert.relay_cert_days_remaining", return_value=10.0),
        patch("jackdaw.services.relay_cert.issue_relay_cert", new_callable=AsyncMock) as issue,
        patch("jackdaw.services.relay_cert.get_settings") as mock_settings,
    ):
        mock_settings.return_value.ssl_dir = str(tmp_path)
        with pytest.raises(asyncio.CancelledError):
            await renewal_loop(Mock(), "relay.test", ctx)

    issue.assert_awaited_once()
    ctx.load_cert_chain.assert_called_once()


async def test_renewal_loop_survives_failed_renewal(tmp_path) -> None:
    """A failed renewal is logged and retried next cycle — the loop must not die
    and the stale context must not be reloaded."""
    from jackdaw.services.relay_cert import renewal_loop

    ctx = Mock()
    sleep_count = 0

    async def fake_sleep(_seconds: float) -> None:
        nonlocal sleep_count
        sleep_count += 1
        if sleep_count > 2:  # two cycles: one failed renewal, one skipped check
            raise asyncio.CancelledError

    with (
        patch("asyncio.sleep", side_effect=fake_sleep),
        patch("jackdaw.services.relay_cert.relay_cert_days_remaining", side_effect=[10.0, 60.0]),
        patch(
            "jackdaw.services.relay_cert.issue_relay_cert",
            new_callable=AsyncMock,
            side_effect=RuntimeError("boom"),
        ) as issue,
        patch("jackdaw.services.relay_cert.get_settings") as mock_settings,
    ):
        mock_settings.return_value.ssl_dir = str(tmp_path)
        with pytest.raises(asyncio.CancelledError):
            await renewal_loop(Mock(), "relay.test", ctx)

    issue.assert_awaited_once()
    ctx.load_cert_chain.assert_not_called()


async def test_renewal_loop_skips_reload_without_ssl_context(tmp_path) -> None:
    """With no live SSLContext (tests / plain-HTTP mode) a renewal still issues
    but performs no in-place reload."""
    from jackdaw.services.relay_cert import renewal_loop

    sleep_count = 0

    async def fake_sleep(_seconds: float) -> None:
        nonlocal sleep_count
        sleep_count += 1
        if sleep_count > 1:
            raise asyncio.CancelledError

    with (
        patch("asyncio.sleep", side_effect=fake_sleep),
        patch("jackdaw.services.relay_cert.relay_cert_days_remaining", return_value=10.0),
        patch("jackdaw.services.relay_cert.issue_relay_cert", new_callable=AsyncMock) as issue,
        patch("jackdaw.services.relay_cert.get_settings") as mock_settings,
    ):
        mock_settings.return_value.ssl_dir = str(tmp_path)
        with pytest.raises(asyncio.CancelledError):
            await renewal_loop(Mock(), "relay.test", None)

    issue.assert_awaited_once()


# ---------------------------------------------------------------------------
# _health_app — minimal ASGI liveness app
# ---------------------------------------------------------------------------


async def _drive_health(path: str, scope_type: str = "http") -> list[dict[str, Any]]:
    from jackdaw.serve import _health_app

    sent: list[dict[str, Any]] = []

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    async def receive() -> dict[str, Any]:
        return {}

    await _health_app({"type": scope_type, "path": path}, receive, send)
    return sent


async def test_health_app_healthz_200() -> None:
    sent = await _drive_health("/healthz")
    assert sent[0]["status"] == 200


async def test_health_app_other_path_404() -> None:
    sent = await _drive_health("/nope")
    assert sent[0]["status"] == 404


async def test_health_app_ignores_non_http_scope() -> None:
    sent = await _drive_health("/healthz", scope_type="lifespan")
    assert sent == []


# ---------------------------------------------------------------------------
# _start_health_listener
# ---------------------------------------------------------------------------


def test_start_health_listener_spawns_daemon_thread() -> None:
    """The liveness listener runs uvicorn in a started daemon thread."""
    from jackdaw import serve

    fake_thread = Mock()
    with (
        patch("jackdaw.serve.uvicorn.Server", return_value=Mock()) as server_cls,
        patch("jackdaw.serve.threading.Thread", return_value=fake_thread) as thread_cls,
    ):
        result = serve._start_health_listener()

    thread_cls.assert_called_once()
    assert thread_cls.call_args.kwargs.get("daemon") is True
    fake_thread.start.assert_called_once()
    assert result is server_cls.return_value


# ---------------------------------------------------------------------------
# _build_tls_server
# ---------------------------------------------------------------------------


def test_build_tls_server_sets_min_tls_and_live_context(tmp_path) -> None:
    """The TLS server pins TLS 1.2 and hands its context to app.state for reloads."""
    import ssl as ssl_mod

    from jackdaw.serve import _build_tls_server, app
    from tests.test_startup import _write_cert_pair

    _write_cert_pair(tmp_path)
    server = _build_tls_server(_settings(ssl_dir=str(tmp_path)))
    try:
        assert server is not None
        assert app.state.relay_ssl_context is not None
        assert app.state.relay_ssl_context.minimum_version == ssl_mod.TLSVersion.TLSv1_2
    finally:
        if hasattr(app.state, "relay_ssl_context"):
            del app.state.relay_ssl_context


# ---------------------------------------------------------------------------
# main() — entry orchestration
# ---------------------------------------------------------------------------


def test_main_plain_http_mode() -> None:
    """SERVE_TLS=false serves directly via uvicorn.run, no cert issuance."""
    from jackdaw import serve

    with (
        patch("jackdaw.serve._tls_enabled", return_value=False),
        patch("jackdaw.serve.uvicorn.run") as run,
        patch("jackdaw.serve.get_settings") as ms,
    ):
        ms.return_value.log_level = "INFO"
        serve.main()

    run.assert_called_once()


def test_main_tls_mode_issues_then_serves() -> None:
    """TLS mode starts the health listener, ensures a cert, then runs the server."""
    from jackdaw import serve

    server = Mock()
    with (
        patch("jackdaw.serve._tls_enabled", return_value=True),
        patch("jackdaw.serve._start_health_listener", return_value=Mock()) as health,
        patch("jackdaw.serve._ensure_relay_cert", new=Mock()),
        patch("jackdaw.serve.asyncio.run") as arun,
        patch("jackdaw.serve._build_tls_server", return_value=server),
        patch("jackdaw.serve.get_settings") as ms,
    ):
        ms.return_value.log_level = "INFO"
        ms.return_value.relay_domain = "relay.test"
        serve.main()

    arun.assert_called_once()
    server.run.assert_called_once()
    assert health.return_value.should_exit is True
