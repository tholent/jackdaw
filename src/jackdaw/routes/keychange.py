"""POST /acme/key-change — account key roll-over (RFC 8555 §7.3.5)."""

from __future__ import annotations

import json
import logging
from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from josepy.jwk import JWK
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jackdaw._util import b64url_decode, canonical_jwk
from jackdaw.config import get_settings
from jackdaw.db.engine import get_db
from jackdaw.db.models import Account
from jackdaw.services.jws import _ALLOWED_ALGS, ALG_MAP, verify_jws

log = logging.getLogger(__name__)
router = APIRouter()

_DB = Annotated[AsyncSession, Depends(get_db)]


def _verify_inner_jws(
    inner: dict[str, Any],
    *,
    expected_account_url: str,
    old_public_key_json: str,
    key_change_url: str,
) -> dict[str, Any]:
    """Verify the inner JWS of a key-change request and return its payload.

    Raises HTTPException(400) if anything is invalid.
    """
    protected_b64: str = inner.get("protected", "")
    payload_b64: str = inner.get("payload", "")
    signature_b64: str = inner.get("signature", "")

    if not protected_b64 or not signature_b64:
        raise HTTPException(status_code=400, detail="Inner JWS missing required fields")

    try:
        protected: dict[str, Any] = json.loads(b64url_decode(protected_b64))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid inner JWS protected header") from exc

    alg_name: str = protected.get("alg", "")
    if alg_name not in _ALLOWED_ALGS:
        raise HTTPException(
            status_code=400, detail=f"Inner JWS unsupported algorithm: {alg_name!r}"
        )

    # Inner URL must match the key-change endpoint URL.
    if protected.get("url") != key_change_url:
        raise HTTPException(status_code=400, detail="Inner JWS url does not match key-change URL")

    # Inner must carry jwk (new key), not kid.
    new_jwk_data: dict[str, Any] | None = protected.get("jwk")
    if new_jwk_data is None:
        raise HTTPException(status_code=400, detail="Inner JWS protected header must contain 'jwk'")
    if protected.get("kid") is not None:
        raise HTTPException(status_code=400, detail="Inner JWS must not contain 'kid'")

    # Verify inner signature with the new key.
    try:
        new_jwk = cast(JWK, JWK.from_json(new_jwk_data))
        signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
        sig_bytes = b64url_decode(signature_b64)
        alg = ALG_MAP[alg_name]
        valid = alg.verify(new_jwk.public_key().key, signing_input, sig_bytes)
    except Exception as exc:
        log.debug("Inner JWS signature check raised: %s", exc)
        valid = False

    if not valid:
        raise HTTPException(status_code=400, detail="Inner JWS signature verification failed")

    # Decode inner payload.
    try:
        inner_payload: dict[str, Any] = json.loads(b64url_decode(payload_b64))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid inner JWS payload") from exc

    # Inner payload must bind the account and old key.
    if inner_payload.get("account") != expected_account_url:
        raise HTTPException(
            status_code=400,
            detail="Inner JWS payload 'account' does not match the requesting account",
        )

    old_key_in_payload: dict[str, Any] | None = inner_payload.get("oldKey")
    if old_key_in_payload is None:
        raise HTTPException(status_code=400, detail="Inner JWS payload missing 'oldKey'")

    if canonical_jwk(old_key_in_payload) != old_public_key_json:
        raise HTTPException(
            status_code=400,
            detail="Inner JWS payload 'oldKey' does not match the current account key",
        )

    return new_jwk_data


@router.post(
    "/acme/key-change",
    responses={
        400: {"description": "Malformed JWS or invalid key-change payload"},
        401: {"description": "Account not found"},
        409: {"description": "New key already registered to another account"},
    },
)
async def key_change(request: Request, db: _DB) -> JSONResponse:
    """Roll over the account signing key (RFC 8555 §7.3.5).

    The outer JWS is signed by the old account key (kid).
    Its payload is the inner JWS, signed by the new key (jwk), whose payload
    binds the account URL and old key to prevent cross-account attacks.
    """
    # Outer JWS — verified with old account key; payload is the inner JWS object.
    inner_jws_dict, account_id = await verify_jws(request, db)

    if not account_id:
        raise HTTPException(status_code=400, detail="key-change requires 'kid' (not 'jwk')")

    if not isinstance(inner_jws_dict, dict):
        raise HTTPException(status_code=400, detail="key-change payload must be a JSON object")

    # Load the existing account.
    result = await db.execute(select(Account).where(Account.id == account_id))
    account = result.scalar_one_or_none()
    if account is None:
        raise HTTPException(status_code=401, detail="Account not found")

    settings = get_settings()
    account_url = f"{settings.relay_base_url}/acme/account/{account_id}"
    key_change_url = str(request.url)

    new_jwk_data = _verify_inner_jws(
        inner_jws_dict,
        expected_account_url=account_url,
        old_public_key_json=account.public_key,
        key_change_url=key_change_url,
    )

    new_canonical = canonical_jwk(new_jwk_data)

    # Reject if new key is already registered to a different account.
    existing = await db.execute(
        select(Account).where(Account.public_key == new_canonical, Account.id != account_id)
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=409,
            detail="New key is already registered to a different account",
        )

    account.public_key = new_canonical
    await db.commit()
    log.info("Account %s key-change complete", account_id)

    contact = json.loads(account.contact) if account.contact else None
    return JSONResponse(
        content={
            "status": account.status,
            **({"contact": contact} if contact else {}),
            "orders": f"{settings.relay_base_url}/acme/account/{account_id}/orders",
        },
        status_code=200,
        headers={"Location": account_url},
    )
