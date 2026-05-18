"""POST /acme/challenge/{id} — accept client's readiness signal and start HTTP-01 validation."""

import asyncio
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from jackdaw.config import get_settings
from jackdaw.db.engine import get_db
from jackdaw.db.models import Order
from jackdaw.schemas.acme import ChallengeObject
from jackdaw.services.jws import verify_jws
from jackdaw.services.ownership import require_authz_owner

router = APIRouter()

_DB = Annotated[AsyncSession, Depends(get_db)]

# Strong references to background validation tasks so they cannot be GC'd mid-flight.
_background_tasks: set[asyncio.Task[None]] = set()


@router.post("/acme/challenge/{authz_id}")
async def acknowledge_challenge(authz_id: str, request: Request, db: _DB) -> JSONResponse:
    """Handle the client's challenge-ready notification (RFC 8555 §7.5.1).

    The payload is intentionally empty (``{}``).  This endpoint:
    1. Verifies the JWS and asserts the authz belongs to the requesting account.
    2. Sets authz status to ``processing`` immediately (prevents duplicate runs).
    3. Launches a background task that performs real HTTP-01 validation and
       transitions the authz/order to ``valid``/``ready`` (or ``invalid``).

    Returns the challenge object with ``status="processing"``.
    """
    _, account_id = await verify_jws(request, db)
    authz = await require_authz_owner(db, authz_id, account_id)

    if authz.status not in ("pending", "processing"):
        raise HTTPException(status_code=400, detail=f"Authorization is already {authz.status!r}")

    # Transition to processing now so duplicate POSTs are idempotent and the
    # client sees the state change immediately when polling.
    if authz.status == "pending":
        authz.status = "processing"
        order = await db.get(Order, authz.order_id)
        if order is not None and order.status == "pending":
            order.status = "processing"
        await db.commit()

    from jackdaw import worker

    task = asyncio.create_task(
        worker.run_challenge(
            authz_id=authz_id,
            order_id=authz.order_id,
        )
    )
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)

    settings = get_settings()
    base = settings.relay_base_url
    body = ChallengeObject(
        type="dns-01",
        url=f"{base}/acme/challenge/{authz_id}",
        status="processing",
        token=authz.challenge_token or "",
    )
    return JSONResponse(
        content=body.model_dump(),
        headers={"Link": f'<{base}/acme/authz/{authz_id}>;rel="up"'},
    )
