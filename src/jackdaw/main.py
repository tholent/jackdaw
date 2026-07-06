"""FastAPI application entry-point: lifespan, middleware, and router registration."""

import asyncio
import json
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from sqlalchemy import update
from starlette.middleware.base import BaseHTTPMiddleware

from jackdaw import __version__
from jackdaw.config import get_settings
from jackdaw.db.engine import AsyncSessionLocal, init_db
from jackdaw.db.models import Authorization, Order
from jackdaw.dns.loader import get_provider
from jackdaw.services import le_client as le
from jackdaw.services import relay_cert
from jackdaw.services.nonce import generate_nonce, prune_nonces

log = logging.getLogger(__name__)


_LE_PRODUCTION_URL = "https://acme-v02.api.letsencrypt.org/directory"


_INTERRUPTED_ORDER_ERROR = json.dumps(
    {
        "type": "urn:ietf:params:acme:error:serverInternal",
        "detail": "Certificate issuance was interrupted by a relay restart; submit a new order.",
    }
)


async def _reset_processing_orders() -> None:
    """Reset orders/authz stuck in 'processing' to 'invalid' after an unclean shutdown."""
    async with AsyncSessionLocal() as db:
        await db.execute(
            update(Order)
            .where(Order.status == "processing")
            .values(status="invalid", error=_INTERRUPTED_ORDER_ERROR)
        )
        await db.execute(
            update(Authorization)
            .where(Authorization.status == "processing")
            .values(status="invalid")
        )
        await db.commit()
    log.info("Reset any stuck 'processing' orders to 'invalid'")


async def _prune_loop() -> None:
    """Delete expired nonces every 60 s (runs for the lifetime of the process)."""
    while True:
        await asyncio.sleep(60)
        async with AsyncSessionLocal() as db:
            await prune_nonces(db)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan: initialise shared resources, yield, then tear down."""
    settings = get_settings()
    logging.basicConfig(level=getattr(logging, settings.log_level.upper()))

    if not settings.le_verify_ssl and settings.le_directory == _LE_PRODUCTION_URL:
        raise RuntimeError(
            "LE_VERIFY_SSL=false must not be used with the production Let's Encrypt directory. "
            "Set LE_DIRECTORY to the staging URL or re-enable TLS verification."
        )

    await init_db()
    log.info("Database ready")

    await _reset_processing_orders()

    dns_provider = get_provider(settings.dns_provider)
    client = await le.init_account(dns_provider)
    log.info("LE account ready")

    # Expose to routes via app.state.
    app.state.dns_provider = dns_provider
    app.state.le_client = client

    prune_task = asyncio.create_task(_prune_loop())
    # The serve entry-point (jackdaw.serve) stashes the live SSLContext on
    # app.state before starting uvicorn; absent (tests, plain-HTTP mode) the
    # renewal loop skips the in-place reload.
    ssl_context = getattr(app.state, "relay_ssl_context", None)
    renewal_task = asyncio.create_task(
        relay_cert.renewal_loop(client, settings.relay_domain, ssl_context)
    )

    yield

    prune_task.cancel()
    renewal_task.cancel()


# ---------------------------------------------------------------------------
# Application instance
# ---------------------------------------------------------------------------

app = FastAPI(lifespan=lifespan, version=__version__, docs_url=None, redoc_url=None)


class _AcmeHeaderMiddleware(BaseHTTPMiddleware):
    """Attach ``Replay-Nonce`` and ``Link`` headers to every ACME response.

    RFC 8555 §6.5 mandates a fresh nonce on every POST response.
    The ``Link`` header pointing to the directory is required on all responses.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        settings = get_settings()
        index_link = f'<{settings.relay_base_url}/directory>;rel="index"'
        existing = response.headers.get("Link", "")
        response.headers["Link"] = f"{existing}, {index_link}" if existing else index_link
        if request.method in ("HEAD", "POST"):
            async with AsyncSessionLocal() as db:
                nonce = await generate_nonce(db)
            # generate_nonce returns None only when the NONCE_MAX cap is reached;
            # omit the header rather than emit a bogus value.
            if nonce is not None:
                response.headers["Replay-Nonce"] = nonce
        return response


app.add_middleware(_AcmeHeaderMiddleware)

# ---------------------------------------------------------------------------
# Routers — imported after app creation to avoid circular imports.
# ---------------------------------------------------------------------------

from jackdaw.routes import (  # noqa: E402
    account,
    authz,
    cert,
    challenge,
    directory,
    health,
    keychange,
    nonce,
    order,
    revoke,
    terms,
)

app.include_router(health.router)
app.include_router(directory.router)
app.include_router(nonce.router)
app.include_router(account.router)
app.include_router(order.router)
app.include_router(authz.router)
app.include_router(challenge.router)
app.include_router(cert.router)
app.include_router(revoke.router)
app.include_router(keychange.router)
app.include_router(terms.router)
