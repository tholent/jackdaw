"""POST /acme/revoke-cert — certificate revocation (RFC 8555 §7.6)."""

from __future__ import annotations

import logging
from typing import Annotated

from cryptography import x509
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jackdaw._util import b64url_decode
from jackdaw.db.engine import get_db
from jackdaw.db.models import Certificate, Order
from jackdaw.services import le_client as le
from jackdaw.services.cert_store import serial_hex
from jackdaw.services.jws import verify_jws

log = logging.getLogger(__name__)
router = APIRouter()

_DB = Annotated[AsyncSession, Depends(get_db)]

_UNAUTHORIZED = {
    "type": "urn:ietf:params:acme:error:unauthorized",
    "detail": "Certificate not found or not owned by this account",
    "status": 403,
}


def _serial_from_pem(pem_chain: str) -> int:
    """Extract the serial number from the first certificate in a PEM chain."""
    pem_bytes = pem_chain.encode()
    cert = x509.load_pem_x509_certificate(pem_bytes)
    return cert.serial_number


@router.post("/acme/revoke-cert")
async def revoke_cert(request: Request, db: _DB) -> JSONResponse:
    """Revoke a certificate issued by this relay (RFC 8555 §7.6).

    Only account-key revocation is supported — client private keys never touch
    the relay, so certificate-key signing is not possible here.

    The relay verifies ownership (the cert was issued under the caller's account),
    then forwards the revocation to Let's Encrypt using its own LE account.
    """
    payload, account_id = await verify_jws(request, db)

    if not isinstance(payload, dict) or "certificate" not in payload:
        return JSONResponse(
            content={
                "type": "urn:ietf:params:acme:error:malformed",
                "detail": "Payload must contain 'certificate'",
                "status": 400,
            },
            status_code=400,
        )

    cert_b64: str = payload["certificate"]
    reason: int | None = payload.get("reason")

    # Decode the DER certificate to extract its serial number.
    try:
        cert_der = b64url_decode(cert_b64)
        client_cert = x509.load_der_x509_certificate(cert_der)
        serial = client_cert.serial_number
    except Exception as exc:
        log.debug("Failed to parse revocation certificate: %s", exc)
        return JSONResponse(
            content={
                "type": "urn:ietf:params:acme:error:malformed",
                "detail": "Invalid certificate DER encoding",
                "status": 400,
            },
            status_code=400,
        )

    # Fast path: indexed lookup by stored serial, scoped to the caller's account
    # (join to order for the ownership check).
    result = await db.execute(
        select(Certificate)
        .join(Order, Order.id == Certificate.order_id)
        .where(Order.account_id == account_id, Certificate.serial == serial_hex(serial))
    )
    db_cert: Certificate | None = result.scalars().first()

    # Fallback for legacy rows written before the serial column existed
    # (serial IS NULL): parse their PEM to compare.  New rows never reach this.
    if db_cert is None:
        legacy = await db.execute(
            select(Certificate)
            .join(Order, Order.id == Certificate.order_id)
            .where(Order.account_id == account_id, Certificate.serial.is_(None))
        )
        for cert_row in legacy.scalars().all():
            try:
                if _serial_from_pem(cert_row.pem_chain) == serial:
                    db_cert = cert_row
                    break
            except Exception as exc:
                log.debug("Skipping cert row with unparseable PEM: %s", exc)
                continue

    if db_cert is None:
        return JSONResponse(content=_UNAUTHORIZED, status_code=403)

    # Forward the revocation to LE using Jackdaw's own LE account.
    le_client = request.app.state.le_client
    try:
        await le.revoke_cert(le_client, cert_b64, reason)
        log.info("Revoked certificate serial %x for account %s", serial, account_id)
    except Exception as exc:
        log.warning("LE revocation failed for serial %x: %s", serial, exc)
        return JSONResponse(
            content={
                "type": "urn:ietf:params:acme:error:serverInternal",
                "detail": "Revocation request to Let's Encrypt failed",
                "status": 500,
            },
            status_code=500,
        )

    return JSONResponse(content={}, status_code=200)
