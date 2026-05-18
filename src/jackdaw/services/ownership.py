"""Ownership enforcement helpers for ACME resource routes.

Every authenticated route that accesses an order, authorization, or
certificate must verify the resource belongs to the requesting account.
These helpers load the resource *and* assert ownership in one step,
raising HTTP 403 on a mismatch so callers never accidentally skip the check.
"""

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jackdaw.db.models import Authorization, Certificate, Order

_UNAUTHORIZED = {
    "type": "urn:ietf:params:acme:error:unauthorized",
    "detail": "This resource does not belong to the requesting account",
    "status": 403,
}


async def require_order_owner(db: AsyncSession, order_id: str, account_id: str) -> Order:
    """Return the Order if it belongs to *account_id*, else raise HTTP 403/404.

    Args:
        db:         Active database session.
        order_id:   Primary-key UUID of the order to load.
        account_id: Account UUID extracted from the verified JWS kid.

    Returns:
        The matching ``Order`` row.

    Raises:
        HTTPException(404): Order does not exist.
        HTTPException(403): Order exists but belongs to a different account.
    """
    order = await db.get(Order, order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")
    if order.account_id != account_id:
        raise HTTPException(status_code=403, detail=_UNAUTHORIZED)
    return order


async def require_authz_owner(
    db: AsyncSession, authz_id: str, account_id: str
) -> Authorization:
    """Return the Authorization if its parent order belongs to *account_id*.

    Args:
        db:         Active database session.
        authz_id:   Primary-key UUID of the authorization to load.
        account_id: Account UUID extracted from the verified JWS kid.

    Returns:
        The matching ``Authorization`` row.

    Raises:
        HTTPException(404): Authorization does not exist.
        HTTPException(403): Authorization's order belongs to a different account.
    """
    authz = await db.get(Authorization, authz_id)
    if authz is None:
        raise HTTPException(status_code=404, detail="Authorization not found")
    # Join to the parent order to check ownership.
    order = await db.get(Order, authz.order_id)
    if order is None or order.account_id != account_id:
        raise HTTPException(status_code=403, detail=_UNAUTHORIZED)
    return authz


async def require_cert_owner(
    db: AsyncSession, cert_id: str, account_id: str
) -> Certificate:
    """Return the Certificate if its parent order belongs to *account_id*.

    Args:
        db:         Active database session.
        cert_id:    Primary-key UUID of the certificate to load.
        account_id: Account UUID extracted from the verified JWS kid.

    Returns:
        The matching ``Certificate`` row.

    Raises:
        HTTPException(404): Certificate does not exist.
        HTTPException(403): Certificate's order belongs to a different account.
    """
    result = await db.execute(select(Certificate).where(Certificate.id == cert_id))
    cert = result.scalar_one_or_none()
    if cert is None:
        raise HTTPException(status_code=404, detail="Certificate not found")
    order = await db.get(Order, cert.order_id)
    if order is None or order.account_id != account_id:
        raise HTTPException(status_code=403, detail=_UNAUTHORIZED)
    return cert
