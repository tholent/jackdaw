"""POST /acme/new-account — register or look up an ACME account."""

import json
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jackdaw._util import b64url_decode, canonical_jwk, utcnow
from jackdaw.config import get_settings
from jackdaw.db.engine import get_db
from jackdaw.db.models import Account
from jackdaw.schemas.acme import AccountResponse, NewAccountRequest
from jackdaw.services.jws import verify_jws

router = APIRouter()

_DB = Annotated[AsyncSession, Depends(get_db)]


def _extract_jwk(raw_body: dict[str, Any]) -> dict[str, Any]:
    """Return the JWK object from the JWS protected header."""
    protected: dict[str, Any] = json.loads(b64url_decode(raw_body["protected"]))
    return protected["jwk"]  # type: ignore[no-any-return]


@router.post("/acme/new-account")
async def new_account(request: Request, db: _DB) -> JSONResponse:
    """Create a new ACME account or return an existing one (RFC 8555 §7.3).

    Returns HTTP 201 for a newly created account and HTTP 200 when an
    account already exists for the supplied key.  The ``Location`` header
    always contains the canonical account URL.
    """
    payload, _ = await verify_jws(request, db)
    acct_req = NewAccountRequest.model_validate(payload)

    raw_body: dict[str, Any] = await request.json()
    jwk_data = _extract_jwk(raw_body)
    stored_key = canonical_jwk(jwk_data)

    # Existing account look-up — indexed by canonical public-key JSON.
    result = await db.execute(select(Account).where(Account.public_key == stored_key))
    existing = result.scalar_one_or_none()

    settings = get_settings()
    base = settings.relay_base_url

    if existing is not None:
        location = f"{base}/acme/account/{existing.id}"
        body = AccountResponse(
            status=existing.status,
            contact=json.loads(existing.contact) if existing.contact else None,
            orders=f"{base}/acme/account/{existing.id}/orders",
        )
        return JSONResponse(
            content=body.model_dump(exclude_none=True),
            status_code=200,
            headers={"Location": location},
        )

    if acct_req.onlyReturnExisting:
        return JSONResponse(
            content={
                "type": "urn:ietf:params:acme:error:accountDoesNotExist",
                "detail": "No account found for this key",
                "status": 400,
            },
            status_code=400,
        )

    account_id = str(uuid.uuid4())
    db.add(
        Account(
            id=account_id,
            public_key=stored_key,
            contact=json.dumps(acct_req.contact) if acct_req.contact else None,
            status="valid",
            created_at=utcnow(),
        )
    )
    await db.commit()

    location = f"{base}/acme/account/{account_id}"
    body = AccountResponse(
        status="valid",
        contact=acct_req.contact,
        orders=f"{base}/acme/account/{account_id}/orders",
    )
    return JSONResponse(
        content=body.model_dump(exclude_none=True),
        status_code=201,
        headers={"Location": location},
    )
