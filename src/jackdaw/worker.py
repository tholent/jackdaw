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

import logging
from datetime import UTC, datetime, timedelta

from jackdaw.db.engine import AsyncSessionLocal
from jackdaw.db.models import Account, Authorization, Order
from jackdaw.services import le_client as le
from jackdaw.services.cert_store import store_cert
from jackdaw.services.http01 import Http01ValidationError, key_authorization, validate_http01

log = logging.getLogger(__name__)


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
            log.error("run_challenge: row not found — authz=%s order=%s", authz_id, order_id)
            return

        if authz.challenge_token is None:
            log.error("run_challenge: authz %s has no challenge token", authz_id)
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

    log.info("Starting HTTP-01 validation for %s (authz %s)", domain, authz_id)

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
            log.error("run_challenge: rows vanished after validation — authz=%s", authz_id)
            return

        if validated:
            authz.status = "valid"
            order.status = "ready"
            log.info("Order %s marked ready (authz %s validated)", order_id, authz_id)
        else:
            authz.status = "invalid"
            order.status = "invalid"
            log.warning("Order %s marked invalid (authz %s failed)", order_id, authz_id)

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
    # Mark processing so the client sees the transition when polling.
    async with AsyncSessionLocal() as db:
        order = await db.get(Order, order_id)
        if order is None:
            log.error("process_finalize: order %s not found", order_id)
            return
        order.status = "processing"
        await db.commit()

    log.info("Starting LE flow for order %s (domain=%s)", order_id, domain)

    try:
        pem_chain = await le.order_cert(acme_client, domain, csr_der)
    except Exception:
        log.exception("LE cert issuance failed for order %s", order_id)
        async with AsyncSessionLocal() as db:
            order = await db.get(Order, order_id)
            if order is not None:
                order.status = "invalid"
                await db.commit()
        return

    # Approximate expiry — LE issues 90-day certs; we store 89 days to be safe.
    expires_at = datetime.now(UTC) + timedelta(days=89)

    async with AsyncSessionLocal() as db:
        order = await db.get(Order, order_id)
        if order is None:
            log.error("process_finalize: order %s vanished after cert issuance", order_id)
            return

        cert_id = await store_cert(db, order_id, pem_chain, expires_at)
        order.cert_id = cert_id
        order.status = "valid"
        await db.commit()

    log.info("Order %s complete — cert %s stored", order_id, cert_id)
