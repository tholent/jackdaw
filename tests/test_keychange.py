"""Tests for POST /acme/key-change (H4c)."""

from __future__ import annotations

import base64
import json
from typing import Any

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jackdaw._util import canonical_jwk
from jackdaw.db.models import Account
from jackdaw.services.nonce import generate_nonce
from tests.conftest import build_jws, jwk_for_key, make_ec_key

_CT = {"Content-Type": "application/jose+json"}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


async def _create_account(client: AsyncClient, db: AsyncSession) -> tuple[Any, str]:
    key = make_ec_key()
    jwk = jwk_for_key(key)
    nonce = await generate_nonce(db)
    body = build_jws(
        payload={"termsOfServiceAgreed": True},
        url="https://jackdaw.test/acme/new-account",
        nonce=nonce,
        key=key,
        jwk=jwk,
    )
    resp = await client.post("/acme/new-account", json=body, headers=_CT)
    assert resp.status_code == 201
    return key, resp.headers["location"]


def _build_inner_jws(
    *,
    new_key: Any,
    new_jwk: dict[str, Any],
    account_url: str,
    old_jwk: dict[str, Any],
    url: str,
) -> dict[str, Any]:
    """Build the inner JWS for a key-change request."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    protected_obj = {"alg": "ES256", "jwk": new_jwk, "url": url}
    payload_obj = {"account": account_url, "oldKey": old_jwk}

    protected_b64 = _b64url(json.dumps(protected_obj).encode())
    payload_b64 = _b64url(json.dumps(payload_obj).encode())
    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")

    der_sig = new_key.sign(signing_input, ECDSA(hashes.SHA256()))
    r_int, s_int = decode_dss_signature(der_sig)
    sig = _b64url(r_int.to_bytes(32, "big") + s_int.to_bytes(32, "big"))

    return {"protected": protected_b64, "payload": payload_b64, "signature": sig}


async def test_key_change_success(test_client: AsyncClient, db_session: AsyncSession) -> None:
    """POST /acme/key-change updates the account public key."""
    old_key, account_url = await _create_account(test_client, db_session)
    old_jwk = jwk_for_key(old_key)
    account_id = account_url.rsplit("/", 1)[-1]

    new_key = make_ec_key()
    new_jwk = jwk_for_key(new_key)

    url = "https://jackdaw.test/acme/key-change"
    inner = _build_inner_jws(
        new_key=new_key,
        new_jwk=new_jwk,
        account_url=account_url,
        old_jwk=old_jwk,
        url=url,
    )

    nonce = await generate_nonce(db_session)
    outer = build_jws(
        payload=inner,
        url=url,
        nonce=nonce,
        key=old_key,
        kid=account_url,
    )

    resp = await test_client.post("/acme/key-change", json=outer, headers=_CT)
    assert resp.status_code == 200

    result = await db_session.execute(select(Account).where(Account.id == account_id))
    account = result.scalar_one()
    assert account.public_key == canonical_jwk(new_jwk)


async def test_key_change_wrong_old_key(test_client: AsyncClient, db_session: AsyncSession) -> None:
    """Inner JWS with wrong oldKey must be rejected (400)."""
    old_key, account_url = await _create_account(test_client, db_session)

    new_key = make_ec_key()
    new_jwk = jwk_for_key(new_key)
    wrong_old_jwk = jwk_for_key(make_ec_key())  # not the real old key

    url = "https://jackdaw.test/acme/key-change"
    inner = _build_inner_jws(
        new_key=new_key,
        new_jwk=new_jwk,
        account_url=account_url,
        old_jwk=wrong_old_jwk,
        url=url,
    )

    nonce = await generate_nonce(db_session)
    outer = build_jws(payload=inner, url=url, nonce=nonce, key=old_key, kid=account_url)

    resp = await test_client.post("/acme/key-change", json=outer, headers=_CT)
    assert resp.status_code == 400


async def test_key_change_duplicate_key(test_client: AsyncClient, db_session: AsyncSession) -> None:
    """Using a key already registered to another account must be rejected (409)."""
    old_key1, account_url1 = await _create_account(test_client, db_session)
    old_key2, account_url2 = await _create_account(test_client, db_session)
    old_jwk1 = jwk_for_key(old_key1)

    url = "https://jackdaw.test/acme/key-change"
    # Try to change account2's key to account1's key.
    inner = _build_inner_jws(
        new_key=old_key1,
        new_jwk=old_jwk1,
        account_url=account_url2,
        old_jwk=jwk_for_key(old_key2),
        url=url,
    )

    nonce = await generate_nonce(db_session)
    outer = build_jws(payload=inner, url=url, nonce=nonce, key=old_key2, kid=account_url2)

    resp = await test_client.post("/acme/key-change", json=outer, headers=_CT)
    assert resp.status_code == 409
