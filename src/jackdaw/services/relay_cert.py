"""The relay's own TLS certificate: issuance, on-disk checks, and renewal.

Split out of ``jackdaw.main`` so the ASGI wiring there stays focused on the
application, and so this lifecycle logic — the most operationally dangerous part
of the service (the relay losing its own TLS) — can be tested independently.

``jackdaw.serve`` obtains/loads the cert at boot; ``jackdaw.main``'s lifespan
launches :func:`renewal_loop` for the life of the process.
"""

import asyncio
import logging
import os
import ssl
from datetime import UTC, datetime
from pathlib import Path

from jackdaw.config import get_settings
from jackdaw.services import le_client as le

log = logging.getLogger(__name__)

CERT_FILENAME = "fullchain.pem"
KEY_FILENAME = "privkey.pem"
RENEW_THRESHOLD_DAYS = 30


def write_relay_cert(cert_path: Path, key_path: Path, pem_chain: str, key_pem: str) -> None:
    """Atomically write the relay's certificate and key to disk — runs in a thread.

    Both files are written to temp paths and atomically renamed so a crash
    mid-write can never leave a new cert paired with an old key (or a
    truncated file) for the next process start.  The key is renamed before
    the cert so that once fullchain.pem changes it is already paired with
    the new key on disk.
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


def relay_cert_exists() -> bool:
    """Return True if a parseable relay cert and its private key are on disk."""
    ssl_dir = Path(get_settings().ssl_dir)
    cert_path = ssl_dir / CERT_FILENAME
    key_path = ssl_dir / KEY_FILENAME
    if not cert_path.exists() or not key_path.exists():
        return False
    try:
        from cryptography import x509

        x509.load_pem_x509_certificate(cert_path.read_bytes())
    except Exception:
        log.warning("Could not parse relay cert; treating as absent", exc_info=True)
        return False
    return True


def relay_cert_days_remaining() -> float | None:
    """Return days until fullchain.pem expires, or None if missing or unreadable."""
    cert_path = Path(get_settings().ssl_dir) / CERT_FILENAME
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


async def issue_relay_cert(client: le.JackdawAcmeClient, relay_domain: str) -> None:
    """Issue a cert for *relay_domain* via DNS-01 and write it to the data volume.

    Raises on failure — callers decide the retry policy (the serve entry-point
    retries with backoff on first boot; the renewal loop retries daily).
    """
    log.info("Requesting TLS cert for %s …", relay_domain)
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
        write_relay_cert,
        ssl_dir / CERT_FILENAME,
        ssl_dir / KEY_FILENAME,
        pem_chain,
        key_pem,
    )


async def renewal_loop(
    client: le.JackdawAcmeClient,
    relay_domain: str,
    ssl_context: ssl.SSLContext | None,
) -> None:
    """Renew the relay's own TLS cert when fewer than 30 days remain.

    Checks once per day.  After a successful renewal the live *ssl_context*
    is reloaded in place so new handshakes present the new cert without a
    restart.  In local-dev / plain-HTTP mode no cert is ever on disk, so the
    expiry check never fires.
    """
    while True:
        await asyncio.sleep(86400)  # 24 h
        days = await asyncio.to_thread(relay_cert_days_remaining)
        if days is None or days >= RENEW_THRESHOLD_DAYS:
            continue
        log.info("Relay cert expires in %.1f days — renewing", days)
        try:
            await issue_relay_cert(client, relay_domain)
        except Exception:
            log.exception("Relay cert renewal failed — retrying in 24 h")
            continue
        if ssl_context is not None:
            ssl_dir = Path(get_settings().ssl_dir)
            await asyncio.to_thread(
                ssl_context.load_cert_chain,
                ssl_dir / CERT_FILENAME,
                ssl_dir / KEY_FILENAME,
            )
            log.info("Live TLS context reloaded with the renewed certificate")
