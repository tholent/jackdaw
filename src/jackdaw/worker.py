"""Background tasks for ACME challenge handling and order finalization.

Two entry points:

``run_challenge`` — Called when a client POSTs to /challenge/{id}.  Performs
real HTTP-01 validation: fetches the challenge token from the client's domain
and verifies the key authorization.  Only on success are the authorization and
order advanced to ``valid``/``ready``.  On failure both are set to ``invalid``.

``process_finalize`` — Called when a client POSTs to /order/{id}/finalize.
Runs the complete gufo-acme flow (DNS-01 TXT → propagation wait → LE
validation → TXT cleanup → cert issuance), stores the certificate, and marks
the order ``valid``.  Sets the order ``invalid`` on any unrecoverable error.
"""

import json
import logging
from datetime import datetime, timedelta

from sqlalchemy import select

from jackdaw._util import utcnow
from jackdaw.db.engine import AsyncSessionLocal
from jackdaw.db.models import Account, Authorization, Order
from jackdaw.services import le_client as le
from jackdaw.services.cert_store import store_cert
from jackdaw.services.http01 import Http01ValidationError, key_authorization, validate_http01

log = logging.getLogger(__name__)


def _s(value: str) -> str:
    """Strip newlines from user-supplied strings before logging to prevent log injection."""
    return value.replace("\n", "\\n").replace("\r", "\\r")


def _cert_expiry_from_pem(pem_chain: str) -> datetime:
    """Return the leaf certificate's notAfter as naive UTC.

    The leaf is the first certificate in the chain.  Falls back to a
    conservative 89-day estimate (Let's Encrypt issues 90-day certs) if the
    chain cannot be parsed, so a stored record always carries a usable expiry.
    """
    try:
        from cryptography import x509

        leaf = x509.load_pem_x509_certificate(pem_chain.encode())
        return leaf.not_valid_after_utc.replace(tzinfo=None)
    except Exception:
        log.warning("Could not parse issued cert expiry; using 89-day estimate", exc_info=True)
        return utcnow() + timedelta(days=89)


async def run_challenge(authz_id: str, order_id: str) -> None:
    """Validate HTTP-01 proof of control, then advance authz/order status.

    Fetches ``http://<domain>/.well-known/acme-challenge/<token>`` and checks
    the response matches the expected key authorization (token + account-key
    thumbprint).  On success the authorization becomes ``valid`` and the order
    becomes ``ready``.  On failure both become ``invalid``.

    Args:
        authz_id: UUID of the ``authorizations`` row to validate.
        order_id: UUID of the parent ``orders`` row to update.
    """
    async with AsyncSessionLocal() as db:
        authz = await db.get(Authorization, authz_id)
        order = await db.get(Order, order_id)

        if authz is None or order is None:
            log.error(
                "run_challenge: row not found — authz=%s order=%s", _s(authz_id), _s(order_id)
            )
            return

        if authz.challenge_token is None:
            log.error("run_challenge: authz %s has no challenge token", _s(authz_id))
            authz.status = "invalid"
            order.status = "invalid"
            await db.commit()
            return

        # Load the account key to compute the expected key authorization.
        account = await db.get(Account, order.account_id)
        if account is None:
            log.error(
                "run_challenge: account %s not found for order %s", order.account_id, order_id
            )
            authz.status = "invalid"
            order.status = "invalid"
            await db.commit()
            return

        token = authz.challenge_token
        domain = authz.identifier
        expected = key_authorization(token, account.public_key)

    log.info("Starting HTTP-01 validation for %s (authz %s)", _s(domain), _s(authz_id))

    try:
        await validate_http01(domain, token, expected)
        validated = True
        log.info("HTTP-01 validation succeeded for %s", domain)
    except Http01ValidationError as exc:
        validated = False
        log.warning("HTTP-01 validation failed for %s: %s", domain, exc.detail)
    except Exception:
        validated = False
        log.exception("Unexpected error during HTTP-01 validation for %s", domain)

    async with AsyncSessionLocal() as db:
        authz = await db.get(Authorization, authz_id)
        order = await db.get(Order, order_id)

        if authz is None or order is None:
            log.error("run_challenge: rows vanished after validation — authz=%s", _s(authz_id))
            return

        if validated:
            authz.status = "valid"
            # Advance the order to "ready" only once every authorization it owns
            # is valid.  Jackdaw rejects multi-identifier orders at new-order, so
            # in practice this is the single authz — but checking the whole set
            # keeps the order-state invariant correct regardless of how the rows
            # were created.  Autoflush ensures this query sees the "valid" just
            # assigned above.
            result = await db.execute(
                select(Authorization.status).where(Authorization.order_id == order_id)
            )
            statuses = list(result.scalars().all())
            if all(s == "valid" for s in statuses):
                order.status = "ready"
                log.info("Order %s marked ready (all %d authz valid)", _s(order_id), len(statuses))
            else:
                log.info(
                    "Authz %s validated; order %s still awaiting other authorizations",
                    _s(authz_id),
                    _s(order_id),
                )
        else:
            authz.status = "invalid"
            order.status = "invalid"
            log.warning("Order %s marked invalid (authz %s failed)", _s(order_id), _s(authz_id))

        await db.commit()


async def process_finalize(
    order_id: str,
    domain: str,
    csr_der: bytes,
    acme_client: le.JackdawAcmeClient,
) -> None:
    """Run the full LE ACME flow and persist the resulting certificate.

    The ``acme_client`` already encapsulates the DNS provider, so DNS-01
    fulfilment and cleanup are handled transparently by gufo-acme callbacks.

    Transitions:
        order.status: ready → processing → valid (or invalid on failure)

    Args:
        order_id:    UUID of the order to finalize.
        domain:      Primary domain name to certify.
        csr_der:     DER-encoded CSR supplied by the ACME client.
        acme_client: Initialised ``JackdawAcmeClient`` for LE communication.
    """
    # The finalize route already transitioned the order to "processing" and
    # committed before dispatching this task; just verify it still exists.
    async with AsyncSessionLocal() as db:
        order = await db.get(Order, order_id)
        if order is None:
            log.error("process_finalize: order %s not found", _s(order_id))
            return

    log.info("Starting LE flow for order %s (domain=%s)", _s(order_id), _s(domain))

    try:
        pem_chain = await le.order_cert(acme_client, domain, csr_der)
    except Exception as exc:
        problem = le.acme_problem(exc)
        if le.is_known_acme_error(exc):
            # Expected operational failure (rate limit, DNS, etc.) — log a clean
            # warning rather than a full traceback.
            log.warning(
                "LE cert issuance failed for order %s (%s): %s",
                _s(order_id),
                problem["type"],
                problem["detail"],
            )
        else:
            log.exception("Unexpected error issuing cert for order %s", _s(order_id))
        async with AsyncSessionLocal() as db:
            order = await db.get(Order, order_id)
            if order is not None:
                order.status = "invalid"
                order.error = json.dumps(problem)
                await db.commit()
        return

    # Store the leaf certificate's real notAfter (falls back to an estimate only
    # if the issued chain is unparseable).
    expires_at = _cert_expiry_from_pem(pem_chain)

    async with AsyncSessionLocal() as db:
        order = await db.get(Order, order_id)
        if order is None:
            log.error("process_finalize: order %s vanished after cert issuance", _s(order_id))
            return

        cert_id = await store_cert(db, order_id, pem_chain, expires_at)
        order.cert_id = cert_id
        order.status = "valid"
        await db.commit()

    log.info("Order %s complete — cert %s stored", _s(order_id), _s(cert_id))
