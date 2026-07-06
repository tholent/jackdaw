"""FastAPI application entry-point: lifespan, middleware, and router registration."""

import asyncio
import logging
import os
import signal
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI, Request, Response
from sqlalchemy import update
from starlette.middleware.base import BaseHTTPMiddleware

from jackdaw import __version__
from jackdaw.config import get_settings
from jackdaw.db.engine import AsyncSessionLocal, init_db
from jackdaw.db.models import Authorization, Order
from jackdaw.dns.loader import get_provider
from jackdaw.services import le_client as le
from jackdaw.services.nonce import generate_nonce, prune_nonces

log = logging.getLogger(__name__)


_LE_PRODUCTION_URL = "https://acme-v02.api.letsencrypt.org/directory"
_CERT_FILENAME = "fullchain.pem"
_KEY_FILENAME = "privkey.pem"


async def _reset_processing_orders() -> None:
    """Reset orders/authz stuck in 'processing' to 'invalid' after an unclean shutdown."""
    async with AsyncSessionLocal() as db:
        await db.execute(update(Order).where(Order.status == "processing").values(status="invalid"))
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


def _write_relay_cert(cert_path: Path, key_path: Path, pem_chain: str, key_pem: str) -> None:
    """Write certificate and key to disk, then signal nginx — runs in a thread.

    Both files are written to temp paths and atomically renamed so a crash
    mid-write can never leave nginx pairing a new cert with an old key (or a
    truncated file), which would break the TLS handshake.
    """
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    cert_tmp = cert_path.with_name(cert_path.name + ".tmp")
    key_tmp = key_path.with_name(key_path.name + ".tmp")
    cert_tmp.write_text(pem_chain)
    key_tmp.write_text(key_pem)
    key_tmp.chmod(0o600)
    # Both temp files are fully written; the renames themselves are atomic.
    os.replace(key_tmp, key_path)
    os.replace(cert_tmp, cert_path)
    log.info("Relay TLS cert written to %s", cert_path)

    nginx_pid_file = Path("/var/run/nginx.pid")
    if nginx_pid_file.exists():
        pid = int(nginx_pid_file.read_text().strip())
        os.kill(pid, signal.SIGHUP)
        log.info("Sent SIGHUP to nginx pid %d", pid)


def _relay_cert_exists() -> bool:
    """Return True if both cert and key files are already present."""
    ssl_dir = Path(get_settings().ssl_dir)
    return (ssl_dir / _CERT_FILENAME).exists() and (ssl_dir / _KEY_FILENAME).exists()


def _relay_cert_days_remaining() -> float | None:
    """Return days until fullchain.pem expires, or None if missing or unreadable."""
    cert_path = Path(get_settings().ssl_dir) / _CERT_FILENAME
    if not cert_path.exists():
        return None
    try:
        from cryptography import x509

        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        delta = cert.not_valid_after_utc - datetime.now(UTC)
        return delta.total_seconds() / 86400
    except Exception:
        log.warning("Could not parse relay cert expiry", exc_info=True)
        return None


async def _bootstrap_relay_cert(
    client: le.JackdawAcmeClient, relay_domain: str, *, force: bool = False
) -> None:
    """Issue a cert for *relay_domain*, then signal nginx to reload.

    On first boot (force=False) this resolves the chicken-and-egg problem:
    nginx starts with the self-signed cert from the init container, Jackdaw
    requests a real LE cert, writes it to the shared data volume, then sends
    SIGHUP to nginx.  Called with force=True by the renewal loop.
    """
    if "://" in relay_domain:
        log.debug("relay_domain is a URL (%s); skipping TLS bootstrap", relay_domain)
        return  # local dev — no nginx, no cert needed

    if not force and await asyncio.to_thread(_relay_cert_exists):
        return  # LE cert already in place

    log.info("Bootstrapping TLS cert for %s …", relay_domain)
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )
        from cryptography.x509.oid import NameOID

        priv = generate_private_key(SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, relay_domain)]))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(relay_domain)]),
                critical=False,
            )
            .sign(priv, hashes.SHA256())
        )
        csr_der = csr.public_bytes(Encoding.DER)

        pem_chain = await le.order_cert(client, relay_domain, csr_der)
        key_pem = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()

        ssl_dir = Path(get_settings().ssl_dir)
        await asyncio.to_thread(
            _write_relay_cert,
            ssl_dir / _CERT_FILENAME,
            ssl_dir / _KEY_FILENAME,
            pem_chain,
            key_pem,
        )

    except Exception:
        log.exception("Failed to bootstrap relay TLS cert — nginx keeps the self-signed cert")


async def _renewal_loop(client: le.JackdawAcmeClient, relay_domain: str) -> None:
    """Renew the relay's own TLS cert when fewer than 30 days remain.

    Checks once per day.  Skipped automatically in local-dev mode (when
    relay_domain contains a scheme) because _bootstrap_relay_cert is a no-op
    there.
    """
    while True:
        await asyncio.sleep(86400)  # 24 h
        days = await asyncio.to_thread(_relay_cert_days_remaining)
        if days is not None and days < 30:
            log.info("Relay cert expires in %.1f days — renewing", days)
            await _bootstrap_relay_cert(client, relay_domain, force=True)


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
    renewal_task = asyncio.create_task(_renewal_loop(client, settings.relay_domain))
    bootstrap_task = asyncio.create_task(_bootstrap_relay_cert(client, settings.relay_domain))

    yield

    prune_task.cancel()
    renewal_task.cancel()
    bootstrap_task.cancel()


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
