"""Container entry-point: obtain the relay's TLS certificate, then serve.

uvicorn terminates TLS itself.  The public HTTPS listener stays offline until
a real Let's Encrypt certificate is on disk — there is no self-signed
placeholder — and the in-process renewal loop (see jackdaw.main) reloads the
live SSLContext when the cert rotates, so no restart or external reload
signal is needed.

A plain-HTTP liveness listener on 127.0.0.1:8000 serves the Docker
healthcheck from the moment the process starts, including during the
(possibly long) first-boot DNS-01 issuance.

With SERVE_TLS=false, or when RELAY_DOMAIN contains a scheme (local dev),
the app serves plain HTTP on port 8000 instead.
"""

import asyncio
import logging
import ssl
import threading
from collections.abc import Awaitable, Callable, MutableMapping
from pathlib import Path
from typing import Any

import uvicorn

from jackdaw.config import Settings, get_settings
from jackdaw.dns.loader import get_provider
from jackdaw.main import app
from jackdaw.services import le_client as le
from jackdaw.services.relay_cert import (
    CERT_FILENAME,
    KEY_FILENAME,
    RENEW_THRESHOLD_DAYS,
    issue_relay_cert,
    relay_cert_days_remaining,
    relay_cert_exists,
)

log = logging.getLogger(__name__)

HTTP_PORT = 8000
HTTPS_PORT = 443

# Backoff for first-boot issuance failures.  Let's Encrypt allows 5 failed
# validations per account/hostname/hour; capping retries at 15 min keeps a
# misconfigured deployment safely under that limit.
_RETRY_INITIAL_S = 60
_RETRY_MAX_S = 900


def _tls_enabled(settings: Settings) -> bool:
    """True when this process should terminate TLS on the public port."""
    return settings.serve_tls and "://" not in settings.relay_domain


async def _health_app(
    scope: MutableMapping[str, Any],
    receive: Callable[[], Awaitable[Any]],
    send: Callable[[MutableMapping[str, Any]], Awaitable[None]],
) -> None:
    """Minimal ASGI liveness app — 200 on /healthz, 404 otherwise."""
    if scope["type"] != "http":
        return
    status = 200 if scope["path"] == "/healthz" else 404
    await send({"type": "http.response.start", "status": status, "headers": []})
    await send({"type": "http.response.body", "body": b""})


def _start_health_listener() -> uvicorn.Server:
    """Serve the liveness endpoint on plain HTTP in a daemon thread.

    Bound to 127.0.0.1 — only the Docker healthcheck (same network namespace)
    uses it.  Running in a non-main thread keeps uvicorn from installing its
    own signal handlers here; the main TLS server owns process shutdown.
    """
    server = uvicorn.Server(
        uvicorn.Config(
            _health_app,
            host="127.0.0.1",
            port=HTTP_PORT,
            lifespan="off",
            access_log=False,
            log_level="warning",
        )
    )
    threading.Thread(target=server.run, name="health-listener", daemon=True).start()
    return server


async def _cert_days_remaining_if_usable() -> float | None:
    """Days remaining on a loadable cert/key pair, or None if absent/unusable."""
    if not await asyncio.to_thread(relay_cert_exists):
        return None
    return await asyncio.to_thread(relay_cert_days_remaining)


async def _ensure_relay_cert(settings: Settings) -> None:
    """Block until a usable relay certificate is on disk, issuing one if needed.

    Missing or expired → retry issuance with backoff until it succeeds (the
    HTTPS listener stays offline meanwhile).  Present but expiring within the
    renewal threshold → try to renew once, and fall back to serving the
    existing cert (the daily renewal loop keeps retrying).
    """
    days = await _cert_days_remaining_if_usable()
    if days is not None and days >= RENEW_THRESHOLD_DAYS:
        return

    dns_provider = get_provider(settings.dns_provider)
    client = await le.init_account(dns_provider)

    delay = _RETRY_INITIAL_S
    while True:
        try:
            await issue_relay_cert(client, settings.relay_domain)
            return
        except Exception:
            if days is not None and days > 0:
                log.exception(
                    "Relay cert renewal failed — serving the existing cert "
                    "(%.1f days left); the daily renewal loop will retry",
                    days,
                )
                return
            log.exception(
                "Relay cert issuance failed — HTTPS stays offline; retrying in %d s", delay
            )
            await asyncio.sleep(delay)
            delay = min(delay * 2, _RETRY_MAX_S)


def _build_tls_server(settings: Settings) -> uvicorn.Server:
    """Build the public HTTPS server; the cert files must already exist."""
    ssl_dir = Path(settings.ssl_dir)
    config = uvicorn.Config(
        app,
        host="0.0.0.0",  # noqa: S104 — the public listener; the container publishes it
        port=HTTPS_PORT,
        ssl_certfile=str(ssl_dir / CERT_FILENAME),
        ssl_keyfile=str(ssl_dir / KEY_FILENAME),
    )
    config.load()  # builds config.ssl; Server.serve() skips re-loading
    assert config.ssl is not None
    config.ssl.minimum_version = ssl.TLSVersion.TLSv1_2
    # Hand the live context to the renewal loop (via lifespan) so a renewed
    # cert takes effect on new handshakes without a restart.
    app.state.relay_ssl_context = config.ssl
    return uvicorn.Server(config)


def main() -> None:
    settings = get_settings()
    logging.basicConfig(level=getattr(logging, settings.log_level.upper()))

    if not _tls_enabled(settings):
        log.info("TLS disabled — serving plain HTTP on :%d", HTTP_PORT)
        uvicorn.run(app, host="0.0.0.0", port=HTTP_PORT)  # noqa: S104 — plain-HTTP mode
        return

    health_server = _start_health_listener()
    asyncio.run(_ensure_relay_cert(settings))
    server = _build_tls_server(settings)
    log.info("Serving https://%s on :%d", settings.relay_domain, HTTPS_PORT)
    server.run()
    health_server.should_exit = True


if __name__ == "__main__":
    main()
