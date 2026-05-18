"""POST /acme/authz/{id} — return the current authorisation status (POST-as-GET)."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from jackdaw.config import get_settings
from jackdaw.db.engine import get_db
from jackdaw.db.models import Authorization
from jackdaw.schemas.acme import AuthzResponse, ChallengeObject, Identifier
from jackdaw.services.jws import verify_jws

router = APIRouter()

_DB = Annotated[AsyncSession, Depends(get_db)]


@router.post("/acme/authz/{authz_id}")
async def get_authz(authz_id: str, request: Request, db: _DB) -> JSONResponse:
    """Return the authorisation resource for *authz_id* (RFC 8555 §7.5).

    RFC 8555 §6.3 requires POST-as-GET (POST with empty JWS payload) for
    resource fetches.
    """
    await verify_jws(request, db)
    authz = await db.get(Authorization, authz_id)
    if authz is None:
        raise HTTPException(status_code=404, detail="Authorization not found")

    settings = get_settings()
    base = settings.relay_base_url

    body = AuthzResponse(
        status=authz.status,
        identifier=Identifier(type="dns", value=authz.identifier),
        challenges=[
            ChallengeObject(
                type="dns-01",
                url=f"{base}/acme/challenge/{authz_id}",
                status=authz.status,
                token=authz.challenge_token or "",
            )
        ],
    )
    return JSONResponse(
        content=body.model_dump(),
        headers={"Link": f'<{base}/acme/order/{authz.order_id}>;rel="up"'},
    )
