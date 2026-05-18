"""Background tasks for ACME challenge handling and order finalization.

Two entry points:

``run_challenge`` — Called when a client POSTs to /challenge/{id}.  Advances
the relay's internal authorization and order status to ``ready`` so the client
can proceed to finalization.  The actual DNS-01 interaction with LE happens
inside ``process_finalize`` when the CSR is available.

``process_finalize`` — Called when a client POSTs to /order/{id}/finalize.
Runs the complete gufo-acme flow (DNS-01 TXT → propagation wait → LE
validation → TXT cleanup → cert issuance), stores the certificate, and marks
the order ``valid``.  Sets the order ``invalid`` on any unrecoverable error.
"""

import logging
from datetime import UTC, datetime, timedelta

from jackdaw.db.engine import AsyncSessionLocal
from jackdaw.db.models import Authorization, Order
from jackdaw.services import le_client as le
from jackdaw.services.cert_store import store_cert

log = logging.getLogger(__name__)


async def run_challenge(authz_id: str, order_id: str) -> None:
    """Advance authz and order to ``ready`` after client challenge acknowledgement.

    This is optimistic: we mark the relay state immediately so the client can
    poll ``GET /order/{id}`` and see ``status=ready``.  LE validation is
    deferred to ``process_finalize`` where the real CSR is available.

    Args:
        authz_id: UUID of the ``authorizations`` row to update.
        order_id: UUID of the parent ``orders`` row to update.
    """
    async with AsyncSessionLocal() as db:
        authz = await db.get(Authorization, authz_id)
        order = await db.get(Order, order_id)

        if authz is None or order is None:
            log.error("run_challenge: row not found — authz=%s order=%s", authz_id, order_id)
            return

        authz.status = "valid"
        order.status = "ready"
        await db.commit()

    log.info("Order %s marked ready (authz %s)", order_id, authz_id)


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
