"""Certificate persistence: store issued certs and retrieve them by ID."""

import uuid
from datetime import datetime

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jackdaw._util import utcnow
from jackdaw.db.models import Certificate


async def store_cert(
    db: AsyncSession,
    order_id: str,
    pem_chain: str,
    expires_at: datetime,
) -> str:
    """Persist a PEM certificate chain and return its UUID.

    Args:
        db:         Active database session.
        order_id:   The order this certificate belongs to.
        pem_chain:  Full PEM chain (leaf + intermediates).
        expires_at: Certificate expiry datetime (UTC).

    Returns:
        The new certificate UUID string.
    """
    cert_id = str(uuid.uuid4())
    db.add(
        Certificate(
            id=cert_id,
            order_id=order_id,
            pem_chain=pem_chain,
            issued_at=utcnow(),
            expires_at=expires_at,
        )
    )
    await db.commit()
    return cert_id


async def get_cert(db: AsyncSession, cert_id: str) -> str:
    """Return the PEM chain for *cert_id*, raising HTTP 404 if absent.

    Args:
        db:      Active database session.
        cert_id: Certificate UUID.

    Returns:
        PEM-encoded certificate chain string.

    Raises:
        HTTPException(404): Certificate not found.
    """
    result = await db.execute(select(Certificate).where(Certificate.id == cert_id))
    cert = result.scalar_one_or_none()
    if cert is None:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return cert.pem_chain
