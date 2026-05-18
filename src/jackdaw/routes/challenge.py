"""POST /acme/challenge/{id} — accept client's readiness signal."""

import asyncio
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from jackdaw.config import get_settings
from jackdaw.db.engine import get_db
from jackdaw.db.models import Authorization
from jackdaw.schemas.acme import ChallengeObject
from jackdaw.services.jws import verify_jws

router = APIRouter()

_DB = Annotated[AsyncSession, Depends(get_db)]


@router.post("/acme/challenge/{authz_id}")
async def acknowledge_challenge(authz_id: str, request: Request, db: _DB) -> JSONResponse:
    """Handle the client's challenge-ready notification (RFC 8555 §7.5.1).

    The payload is intentionally empty (``{}``).  This endpoint launches a
    background task that:
    1. Optimistically marks the authorisation and its order as ``ready``.
    2. The actual DNS-01 validation with LE takes place during finalization
       via ``worker.process_finalize``.

    Returns the challenge object with ``status="processing"``.
    """
    # JWS verification still required even though the payload is empty.
    await verify_jws(request, db)

    authz = await db.get(Authorization, authz_id)
    if authz is None:
        raise HTTPException(status_code=404, detail="Authorization not found")
    if authz.status not in ("pending", "processing"):
        raise HTTPException(status_code=400, detail=f"Authorization is already {authz.status!r}")

    # Kick off background state transition.
    from jackdaw import worker

    asyncio.create_task(
        worker.run_challenge(
            authz_id=authz_id,
            order_id=authz.order_id,
        )
    )

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
