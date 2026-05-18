"""Order lifecycle routes: new-order, order status, and finalization."""

import asyncio
import json
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jackdaw._util import b64url_decode
from jackdaw.config import get_settings
from jackdaw.db.engine import get_db
from jackdaw.db.models import Authorization, Order
from jackdaw.schemas.acme import (
    FinalizeRequest,
    Identifier,
    NewOrderRequest,
    OrderResponse,
)
from jackdaw.services.jws import verify_jws
from jackdaw.services.ownership import require_order_owner

router = APIRouter()

_DB = Annotated[AsyncSession, Depends(get_db)]

# Strong references to finalization tasks so they cannot be GC'd mid-flight.
_background_tasks: set[asyncio.Task[None]] = set()


def _check_domain_policy(identifiers: list[Identifier]) -> None:
    """Reject identifiers not under an allowed base domain.

    When ``ALLOWED_DOMAINS`` is empty every domain is accepted.  Otherwise
    each requested domain must be a subdomain of (or equal to) one of the
    configured base domains.

    Raises:
        HTTPException(403): At least one identifier is not allowed.
    """
    allowed = get_settings().allowed_domain_list
    if not allowed:
        return
    for ident in identifiers:
        if not any(ident.value == base or ident.value.endswith(f".{base}") for base in allowed):
            raise HTTPException(
                status_code=403,
                detail={
                    "type": "urn:ietf:params:acme:error:rejectedIdentifier",
                    "detail": f"Domain {ident.value!r} is not under an allowed base domain",
                },
            )


@router.post("/acme/new-order", responses={403: {"description": "Domain not permitted by policy"}})
async def new_order(request: Request, db: _DB) -> JSONResponse:
    """Create a new certificate order (RFC 8555 §7.4).

    Verifies the JWS, validates the requested domains against domain policy,
    creates ``orders`` and ``authorizations`` rows, and returns HTTP 201 with
    the order resource and a ``Location`` header.
    """
    payload, account_id = await verify_jws(request, db)
    order_req = NewOrderRequest.model_validate(payload)

    _check_domain_policy(order_req.identifiers)

    settings = get_settings()
    base = settings.relay_base_url

    order_id = str(uuid.uuid4())
    expires_at = datetime.now(UTC) + timedelta(days=1)

    db.add(
        Order(
            id=order_id,
            account_id=account_id,
            status="pending",
            identifiers=json.dumps([i.model_dump() for i in order_req.identifiers]),
            expires_at=expires_at,
            created_at=datetime.now(UTC),
        )
    )

    authz_urls: list[str] = []
    for ident in order_req.identifiers:
        authz_id = str(uuid.uuid4())
        db.add(
            Authorization(
                id=authz_id,
                order_id=order_id,
                identifier=ident.value,
                status="pending",
                challenge_token=secrets.token_urlsafe(32),
                created_at=datetime.now(UTC),
            )
        )
        authz_urls.append(f"{base}/acme/authz/{authz_id}")

    await db.commit()

    location = f"{base}/acme/order/{order_id}"
    body = OrderResponse(
        status="pending",
        identifiers=order_req.identifiers,
        authorizations=authz_urls,
        finalize=f"{base}/acme/order/{order_id}/finalize",
        expires=expires_at.isoformat(),
    )
    return JSONResponse(
        content=body.model_dump(exclude_none=True),
        status_code=201,
        headers={"Location": location},
    )


@router.post("/acme/order/{order_id}")
async def get_order(order_id: str, request: Request, db: _DB) -> JSONResponse:
    """Return current status of an order (RFC 8555 §7.4, POST-as-GET)."""
    _, account_id = await verify_jws(request, db)
    order = await require_order_owner(db, order_id, account_id)

    settings = get_settings()
    base = settings.relay_base_url

    identifiers: list[Any] = json.loads(order.identifiers)

    result = await db.execute(select(Authorization).where(Authorization.order_id == order_id))
    authzs = result.scalars().all()
    authz_urls = [f"{base}/acme/authz/{a.id}" for a in authzs]

    body = OrderResponse(
        status=order.status,
        identifiers=[Identifier(**i) for i in identifiers],
        authorizations=authz_urls,
        finalize=f"{base}/acme/order/{order_id}/finalize",
        certificate=(f"{base}/acme/cert/{order.cert_id}" if order.cert_id else None),
        expires=order.expires_at.isoformat() if order.expires_at else None,
    )
    return JSONResponse(content=body.model_dump(exclude_none=True))


@router.post(
    "/acme/order/{order_id}/finalize",
    responses={
        400: {"description": "Order has no identifiers"},
        403: {"description": "Order is not in ready state"},
    },
)
async def finalize_order(order_id: str, request: Request, db: _DB) -> JSONResponse:
    """Accept the client's CSR and begin certificate issuance (RFC 8555 §7.4).

    The order must be in ``ready`` state.  The CSR is extracted from the JWS
    payload and handed to the background worker.
    """
    payload, account_id = await verify_jws(request, db)
    finalize_req = FinalizeRequest.model_validate(payload)

    order = await require_order_owner(db, order_id, account_id)
    if order.status != "ready":
        raise HTTPException(
            status_code=403,
            detail={
                "type": "urn:ietf:params:acme:error:orderNotReady",
                "detail": f"Order status is {order.status!r}, expected 'ready'",
            },
        )

    # Decode the DER CSR from the base64url payload field.
    csr_der = b64url_decode(finalize_req.csr)

    identifiers: list[Any] = json.loads(order.identifiers)
    if not identifiers:
        raise HTTPException(status_code=400, detail="Order has no identifiers")
    domain: str = identifiers[0]["value"]

    # Kick off the background worker.  We import here to avoid circular imports
    # at module load time.
    from jackdaw import worker

    task = asyncio.create_task(
        worker.process_finalize(
            order_id=order_id,
            domain=domain,
            csr_der=csr_der,
            acme_client=request.app.state.le_client,
        )
    )
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)

    settings = get_settings()
    base = settings.relay_base_url
    result = await db.execute(select(Authorization).where(Authorization.order_id == order_id))
    authzs = result.scalars().all()
    body = OrderResponse(
        status=order.status,
        identifiers=[Identifier(**i) for i in identifiers],
        authorizations=[f"{base}/acme/authz/{a.id}" for a in authzs],
        finalize=f"{base}/acme/order/{order_id}/finalize",
        expires=order.expires_at.isoformat() if order.expires_at else None,
    )
    return JSONResponse(content=body.model_dump(exclude_none=True))
