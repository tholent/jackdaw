"""JWS (JSON Web Signature) verification for all ACME POST requests.

Every ACME POST body is a flat-JSON JWS (RFC 7515 §7.2.2).  This module
decodes the protected header, validates the nonce and URL, resolves the
account key, and verifies the signature.
"""

import json
import logging
from typing import Any, cast

from fastapi import HTTPException, Request
from josepy.jwa import ES256, ES384, ES512, RS256, RS384, RS512
from josepy.jwk import JWK
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jackdaw._util import b64url_decode
from jackdaw.config import get_settings
from jackdaw.db.models import Account
from jackdaw.services.nonce import consume_nonce

log = logging.getLogger(__name__)

# RFC 8555 §7.4 — only these algorithms are permitted.
_ALLOWED_ALGS: frozenset[str] = frozenset({"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"})

# Map algorithm name → josepy JWA instance (also used by key-change route).
ALG_MAP = {
    "RS256": RS256,
    "RS384": RS384,
    "RS512": RS512,
    "ES256": ES256,
    "ES384": ES384,
    "ES512": ES512,
}

# Prefix all account kid URLs must start with (populated on first use).
_ACCOUNT_URL_PREFIX: str | None = None


def _account_url_prefix() -> str:
    """Return the expected kid URL prefix, e.g. 'https://relay.example.com/acme/account/'."""
    global _ACCOUNT_URL_PREFIX
    if _ACCOUNT_URL_PREFIX is None:
        _ACCOUNT_URL_PREFIX = f"{get_settings().relay_base_url}/acme/account/"
    return _ACCOUNT_URL_PREFIX


async def _resolve_key_and_account(
    protected: dict[str, Any],
    db: AsyncSession,
) -> tuple[JWK, str]:
    """Resolve the signing key and account ID from the protected header.

    Returns ``(jwk, account_id)`` where ``account_id`` is an empty string for
    ``newAccount`` requests (``jwk`` path).

    Raises:
        HTTPException(400): Invalid or missing ``jwk``/``kid``.
        HTTPException(401): Unknown or deactivated account.
    """
    jwk_data: dict[str, Any] | None = protected.get("jwk")
    kid: str | None = protected.get("kid")

    if jwk_data is not None and kid is not None:
        raise HTTPException(
            status_code=400,
            detail="JWS protected header must contain 'jwk' or 'kid', not both",
        )

    if jwk_data is not None:
        return cast(JWK, JWK.from_json(jwk_data)), ""

    if kid is not None:
        prefix = _account_url_prefix()
        if not kid.startswith(prefix):
            raise HTTPException(
                status_code=400,
                detail="JWS kid is not a valid account URL for this server",
            )
        account_id = kid[len(prefix) :].rstrip("/")
        if not account_id:
            raise HTTPException(status_code=400, detail="JWS kid is missing the account ID")

        result = await db.execute(select(Account).where(Account.id == account_id))
        account = result.scalar_one_or_none()
        if account is None:
            raise HTTPException(status_code=401, detail="Account not found")
        if account.status != "valid":
            raise HTTPException(status_code=401, detail="Account is not active")
        return cast(JWK, JWK.from_json(json.loads(account.public_key))), account_id

    raise HTTPException(
        status_code=400, detail="JWS protected header must contain 'jwk' or 'kid'"
    )


def _verify_jws_signature(alg_name: str, jwk: JWK, signing_input: bytes, sig_bytes: bytes) -> None:
    """Verify the JWS signature; raises HTTPException(400) on failure."""
    try:
        pub_key = jwk.public_key().key
        valid = ALG_MAP[alg_name].verify(pub_key, signing_input, sig_bytes)
    except Exception as exc:
        log.debug("JWS signature check raised: %s", exc)
        valid = False
    if not valid:
        raise HTTPException(status_code=400, detail="JWS signature verification failed")


def _decode_jws_payload(payload_b64: str) -> dict[str, Any]:
    """Decode a base64url JWS payload; empty string returns ``{}``."""
    if not payload_b64:
        return {}
    try:
        return cast(dict[str, Any], json.loads(b64url_decode(payload_b64)))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JWS payload encoding") from exc


async def verify_jws(
    request: Request,
    db: AsyncSession,
) -> tuple[dict[str, Any], str]:
    """Verify a JWS-signed ACME request and return the payload and account ID.

    For ``newAccount`` requests, ``jwk`` is embedded in the protected header
    and the returned ``account_id`` is an empty string (the account does not
    exist yet).  For all other requests, ``kid`` identifies the account URL
    and the returned ``account_id`` is the UUID portion of that URL.

    Args:
        request: Incoming FastAPI request.
        db:      Active database session (for nonce and account look-ups).

    Returns:
        ``(payload_dict, account_id)`` tuple.

    Raises:
        HTTPException(400): Bad nonce, URL mismatch, invalid signature, malformed kid, etc.
        HTTPException(401): Unknown or deactivated account when ``kid`` is present.
        HTTPException(415): Wrong ``Content-Type``.
    """
    content_type = request.headers.get("content-type", "")
    if "application/jose+json" not in content_type:
        raise HTTPException(status_code=415, detail="Content-Type must be application/jose+json")

    try:
        body = await request.json()
        if not isinstance(body, dict):
            raise ValueError("body must be a JSON object")
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Request body is not valid JSON") from exc

    protected_b64 = body.get("protected", "")
    payload_b64 = body.get("payload", "")
    signature_b64 = body.get("signature", "")

    if not protected_b64 or not signature_b64:
        raise HTTPException(status_code=400, detail="JWS missing required fields")

    try:
        protected: dict[str, Any] = json.loads(b64url_decode(protected_b64))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JWS protected header") from exc

    alg_name: str = protected.get("alg", "")
    if alg_name not in _ALLOWED_ALGS:
        raise HTTPException(status_code=400, detail=f"Unsupported JWS algorithm: {alg_name!r}")

    if protected.get("url") != str(request.url):
        raise HTTPException(status_code=400, detail="JWS url claim does not match request URL")

    jwk, account_id = await _resolve_key_and_account(protected, db)

    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
    sig_bytes = b64url_decode(signature_b64)
    _verify_jws_signature(alg_name, jwk, signing_input, sig_bytes)

    # Consume nonce only after the signature is verified so a bad request cannot
    # burn a valid nonce (preventing the legitimate client from using it).
    await consume_nonce(protected.get("nonce", ""), db)

    return _decode_jws_payload(payload_b64), account_id
