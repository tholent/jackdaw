"""Unit tests for JWS verification."""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from jackdaw.services.nonce import generate_nonce
from tests.conftest import build_jws, jwk_for_key, make_ec_key


async def _get_nonce(db: AsyncSession) -> str:
    return await generate_nonce(db)


# ---------------------------------------------------------------------------
# Helpers that POST a JWS-signed new-account request (simplest POST endpoint)
# ---------------------------------------------------------------------------


async def test_valid_jws_is_accepted(test_client: AsyncClient, db_session: AsyncSession) -> None:
    """A correctly signed JWS with a valid nonce should return 2xx."""
    key = make_ec_key()
    jwk = jwk_for_key(key)
    nonce = await _get_nonce(db_session)
    url = "https://jackdaw.test/acme/new-account"

    body = build_jws(
        payload={"termsOfServiceAgreed": True},
        url=url,
        nonce=nonce,
        key=key,
        jwk=jwk,
    )
    resp = await test_client.post(
        "/acme/new-account",
        json=body,
        headers={"Content-Type": "application/jose+json"},
    )
    assert resp.status_code in (200, 201)


async def test_wrong_content_type_rejected(
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    key = make_ec_key()
    jwk = jwk_for_key(key)
    nonce = await _get_nonce(db_session)
    url = "https://jackdaw.test/acme/new-account"
    body = build_jws(payload={"termsOfServiceAgreed": True}, url=url, nonce=nonce, key=key, jwk=jwk)

    resp = await test_client.post(
        "/acme/new-account",
        json=body,
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 415


async def test_bad_nonce_rejected(test_client: AsyncClient, db_session: AsyncSession) -> None:
    key = make_ec_key()
    jwk = jwk_for_key(key)
    url = "https://jackdaw.test/acme/new-account"
    body = build_jws(
        payload={"termsOfServiceAgreed": True},
        url=url,
        nonce="completely-invalid-nonce",
        key=key,
        jwk=jwk,
    )
    resp = await test_client.post(
        "/acme/new-account",
        json=body,
        headers={"Content-Type": "application/jose+json"},
    )
    assert resp.status_code == 400


async def test_wrong_url_rejected(test_client: AsyncClient, db_session: AsyncSession) -> None:
    key = make_ec_key()
    jwk = jwk_for_key(key)
    nonce = await _get_nonce(db_session)
    # URL in protected header points elsewhere.
    body = build_jws(
        payload={"termsOfServiceAgreed": True},
        url="https://jackdaw.test/acme/some-other-endpoint",
        nonce=nonce,
        key=key,
        jwk=jwk,
    )
    resp = await test_client.post(
        "/acme/new-account",
        json=body,
        headers={"Content-Type": "application/jose+json"},
    )
    assert resp.status_code == 400


async def test_tampered_signature_rejected(
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    import base64

    key = make_ec_key()
    jwk = jwk_for_key(key)
    nonce = await _get_nonce(db_session)
    url = "https://jackdaw.test/acme/new-account"
    body = build_jws(payload={"termsOfServiceAgreed": True}, url=url, nonce=nonce, key=key, jwk=jwk)

    # Decode, flip the first byte, re-encode — produces an invalid signature.
    sig_str = body["signature"]
    pad = 4 - len(sig_str) % 4
    raw = bytearray(base64.urlsafe_b64decode(sig_str + ("=" * pad if pad != 4 else "")))
    raw[0] ^= 0xFF
    body["signature"] = base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()

    resp = await test_client.post(
        "/acme/new-account",
        json=body,
        headers={"Content-Type": "application/jose+json"},
    )
    assert resp.status_code == 400


async def test_replay_nonce_in_post_response(
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    """Every POST response must carry a fresh Replay-Nonce header."""
    key = make_ec_key()
    jwk = jwk_for_key(key)
    nonce = await _get_nonce(db_session)
    url = "https://jackdaw.test/acme/new-account"
    body = build_jws(payload={"termsOfServiceAgreed": True}, url=url, nonce=nonce, key=key, jwk=jwk)

    resp = await test_client.post(
        "/acme/new-account",
        json=body,
        headers={"Content-Type": "application/jose+json"},
    )
    assert "replay-nonce" in resp.headers
