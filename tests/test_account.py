"""Unit tests for POST /acme/new-account."""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from jackdaw.services.nonce import generate_nonce
from tests.conftest import build_jws, jwk_for_key, make_ec_key


async def _post_new_account(
    test_client: AsyncClient,
    db_session: AsyncSession,
    *,
    key=None,
    terms_agreed: bool = True,
) -> tuple[int, dict]:
    """Helper — create a new account and return (status_code, body)."""
    if key is None:
        key = make_ec_key()
    jwk = jwk_for_key(key)
    nonce = await generate_nonce(db_session)
    url = "https://jackdaw.test/acme/new-account"
    body = build_jws(
        payload={"termsOfServiceAgreed": terms_agreed},
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
    return resp.status_code, resp.json()


async def test_new_account_returns_201(test_client: AsyncClient, db_session: AsyncSession) -> None:
    status, body = await _post_new_account(test_client, db_session)
    assert status == 201
    assert body["status"] == "valid"


async def test_new_account_has_location_header(
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    key = make_ec_key()
    jwk = jwk_for_key(key)
    nonce = await generate_nonce(db_session)
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
    assert resp.status_code == 201
    assert "location" in resp.headers
    assert "/acme/account/" in resp.headers["location"]


async def test_duplicate_key_returns_200(
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    """Posting with the same key twice should return 200 (existing account)."""
    key = make_ec_key()

    status1, _ = await _post_new_account(test_client, db_session, key=key)
    assert status1 == 201

    # Use a fresh nonce for the second request.
    status2, _ = await _post_new_account(test_client, db_session, key=key)
    assert status2 == 200


async def test_only_return_existing_unknown_key(
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    """onlyReturnExisting=True with an unknown key must return a 400 ACME error."""
    key = make_ec_key()
    jwk = jwk_for_key(key)
    nonce = await generate_nonce(db_session)
    url = "https://jackdaw.test/acme/new-account"
    body = build_jws(
        payload={"termsOfServiceAgreed": True, "onlyReturnExisting": True},
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
    assert resp.status_code == 400
    assert "accountDoesNotExist" in resp.text
