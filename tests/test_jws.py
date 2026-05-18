"""Unit tests for JWS verification."""

from __future__ import annotations

import base64
import json
import uuid

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from jackdaw.services.jws import _decode_jws_payload, _verify_jws_signature
from jackdaw.services.nonce import generate_nonce
from tests.conftest import build_jws, jwk_for_key, make_ec_key

_CT = {"Content-Type": "application/jose+json"}

_NEW_ACCOUNT = "https://jackdaw.test/acme/new-account"
_REVOKE = "https://jackdaw.test/acme/revoke-cert"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_protected(**fields: object) -> str:
    """Return a base64url-encoded JWS protected header with exactly the given fields."""
    return _b64url(json.dumps(fields).encode())


async def _create_account(client: AsyncClient, db: AsyncSession) -> tuple:
    """Create a fresh account; return (key, account_url)."""
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


# ---------------------------------------------------------------------------
# C3: kid/jwk mutual exclusivity and URL prefix validation
# ---------------------------------------------------------------------------


async def test_both_jwk_and_kid_rejected(
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    """Protected header containing both 'jwk' and 'kid' must be rejected (RFC 8555 §6.2)."""
    key, account_url = await _create_account(test_client, db_session)
    jwk = jwk_for_key(key)
    nonce = await generate_nonce(db_session)

    # Manually build a protected header with both fields — build_jws enforces mutual exclusivity.
    protected_obj = {
        "alg": "ES256",
        "nonce": nonce,
        "url": "https://jackdaw.test/acme/new-order",
        "jwk": jwk,
        "kid": account_url,
    }
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    protected_b64 = _b64url(json.dumps(protected_obj).encode())
    ident_payload = json.dumps({"identifiers": [{"type": "dns", "value": "x.test"}]}).encode()
    payload_b64 = _b64url(ident_payload)
    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
    der_sig = key.sign(signing_input, ECDSA(hashes.SHA256()))
    r_int, s_int = decode_dss_signature(der_sig)
    sig = _b64url(r_int.to_bytes(32, "big") + s_int.to_bytes(32, "big"))

    resp = await test_client.post(
        "/acme/new-order",
        json={"protected": protected_b64, "payload": payload_b64, "signature": sig},
        headers=_CT,
    )
    assert resp.status_code == 400


async def test_kid_wrong_prefix_rejected(
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    """A kid pointing at a foreign server must be rejected."""
    key, account_url = await _create_account(test_client, db_session)
    account_id = account_url.rsplit("/", 1)[-1]
    nonce = await generate_nonce(db_session)

    # kid looks valid structurally but the host is wrong.
    evil_kid = f"https://evil.example.com/acme/account/{account_id}"
    body = build_jws(
        payload={"identifiers": [{"type": "dns", "value": "x.test"}]},
        url="https://jackdaw.test/acme/new-order",
        nonce=nonce,
        key=key,
        kid=evil_kid,
    )
    resp = await test_client.post("/acme/new-order", json=body, headers=_CT)
    assert resp.status_code == 400


async def test_bad_signature_does_not_burn_nonce(
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    """A tampered-signature request must not consume the nonce (H3).

    After a failed request with a bad signature the same nonce must still be
    usable by a correctly signed request.
    """
    key = make_ec_key()
    jwk = jwk_for_key(key)
    nonce = await _get_nonce(db_session)
    url = "https://jackdaw.test/acme/new-account"

    # First request: valid nonce, bad signature.
    body = build_jws(payload={"termsOfServiceAgreed": True}, url=url, nonce=nonce, key=key, jwk=jwk)
    import base64

    sig_str = body["signature"]
    pad = 4 - len(sig_str) % 4
    raw = bytearray(base64.urlsafe_b64decode(sig_str + ("=" * pad if pad != 4 else "")))
    raw[0] ^= 0xFF
    body["signature"] = base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()

    bad_resp = await test_client.post(
        "/acme/new-account", json=body, headers={"Content-Type": "application/jose+json"}
    )
    assert bad_resp.status_code == 400

    # Second request: same nonce, correct signature — must succeed.
    good_body = build_jws(
        payload={"termsOfServiceAgreed": True}, url=url, nonce=nonce, key=key, jwk=jwk
    )
    good_resp = await test_client.post(
        "/acme/new-account", json=good_body, headers={"Content-Type": "application/jose+json"}
    )
    assert good_resp.status_code in (200, 201)


async def test_deactivated_account_rejected(
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    """Requests signed by a deactivated account must return 401."""
    from sqlalchemy import select

    from jackdaw.db.models import Account

    key, account_url = await _create_account(test_client, db_session)
    account_id = account_url.rsplit("/", 1)[-1]

    # Directly flip the account status.
    result = await db_session.execute(select(Account).where(Account.id == account_id))
    account = result.scalar_one()
    account.status = "deactivated"
    await db_session.commit()

    nonce = await generate_nonce(db_session)
    body = build_jws(
        payload={"identifiers": [{"type": "dns", "value": "x.test"}]},
        url="https://jackdaw.test/acme/new-order",
        nonce=nonce,
        key=key,
        kid=account_url,
    )
    resp = await test_client.post("/acme/new-order", json=body, headers=_CT)
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Body not valid JSON / not a dict (lines 149-151)
# ---------------------------------------------------------------------------


async def test_non_json_body_returns_400(test_client: AsyncClient) -> None:
    resp = await test_client.post("/acme/new-account", content=b"not json", headers=_CT)
    assert resp.status_code == 400


async def test_json_array_body_returns_400(test_client: AsyncClient) -> None:
    """A valid JSON value that is not a dict must trigger the isinstance check (line 149)."""
    resp = await test_client.post("/acme/new-account", content=b"[1,2,3]", headers=_CT)
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Missing required fields (line 158)
# ---------------------------------------------------------------------------


async def test_missing_signature_returns_400(test_client: AsyncClient) -> None:
    resp = await test_client.post(
        "/acme/new-account",
        json={"protected": "aaa", "payload": ""},
        headers=_CT,
    )
    assert resp.status_code == 400


async def test_missing_protected_returns_400(test_client: AsyncClient) -> None:
    resp = await test_client.post(
        "/acme/new-account",
        json={"payload": "", "signature": "aaa"},
        headers=_CT,
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Invalid protected header encoding (lines 162-163)
# ---------------------------------------------------------------------------


async def test_invalid_protected_encoding_returns_400(test_client: AsyncClient) -> None:
    resp = await test_client.post(
        "/acme/new-account",
        json={"protected": "!!!not-base64!!!", "payload": "", "signature": "aaa"},
        headers=_CT,
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Unsupported algorithm (line 167)
# ---------------------------------------------------------------------------


async def test_unsupported_algorithm_returns_400(test_client: AsyncClient) -> None:
    protected_b64 = _make_protected(alg="HS256", url=_NEW_ACCOUNT, jwk={})
    resp = await test_client.post(
        "/acme/new-account",
        json={"protected": protected_b64, "payload": "", "signature": "aaa"},
        headers=_CT,
    )
    assert resp.status_code == 400
    assert "HS256" in resp.text


# ---------------------------------------------------------------------------
# kid — empty account ID (line 84)
# ---------------------------------------------------------------------------


async def test_kid_empty_account_id_returns_400(test_client: AsyncClient) -> None:
    """kid equal to the bare account-URL prefix (trailing slash, no UUID) must return 400."""
    protected_b64 = _make_protected(
        alg="ES256",
        url=_REVOKE,
        kid="https://jackdaw.test/acme/account/",
    )
    resp = await test_client.post(
        "/acme/revoke-cert",
        json={"protected": protected_b64, "payload": "", "signature": "aaa"},
        headers=_CT,
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# kid — account not found (line 89)
# ---------------------------------------------------------------------------


async def test_kid_unknown_account_returns_401(test_client: AsyncClient) -> None:
    """A valid-format kid pointing to a non-existent account UUID must return 401."""
    kid = f"https://jackdaw.test/acme/account/{uuid.uuid4()}"
    protected_b64 = _make_protected(alg="ES256", url=_REVOKE, kid=kid)
    resp = await test_client.post(
        "/acme/revoke-cert",
        json={"protected": protected_b64, "payload": "", "signature": "aaa"},
        headers=_CT,
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Neither jwk nor kid (line 94)
# ---------------------------------------------------------------------------


async def test_neither_jwk_nor_kid_returns_400(test_client: AsyncClient) -> None:
    """A protected header with neither 'jwk' nor 'kid' must return 400."""
    protected_b64 = _make_protected(alg="ES256", url=_NEW_ACCOUNT)
    resp = await test_client.post(
        "/acme/new-account",
        json={"protected": protected_b64, "payload": "", "signature": "aaa"},
        headers=_CT,
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# _verify_jws_signature — exception path (lines 102-104)
# ---------------------------------------------------------------------------


def test_verify_jws_signature_crypto_exception_raises_400() -> None:
    """When the crypto layer raises (not returns False), the except branch must catch it.

    josepy returns False for a bad signature — it doesn't raise.  To exercise
    lines 102-104 we patch ALG_MAP so that verify() raises RuntimeError, which
    is caught by 'except Exception' and turned into HTTP 400.
    """
    from unittest.mock import MagicMock, patch

    from josepy.jwk import JWK

    jwk_data = jwk_for_key(make_ec_key())
    jwk = JWK.from_json(jwk_data)

    exploding_alg = MagicMock()
    exploding_alg.verify.side_effect = RuntimeError("crypto layer exploded")

    with patch.dict("jackdaw.services.jws.ALG_MAP", {"ES256": exploding_alg}):
        with pytest.raises(HTTPException) as exc_info:
            _verify_jws_signature("ES256", jwk, b"signing.input", b"sig")
    assert exc_info.value.status_code == 400


# ---------------------------------------------------------------------------
# _decode_jws_payload — invalid payload encoding (lines 115-116)
# ---------------------------------------------------------------------------


def test_decode_jws_payload_non_json_raises_400() -> None:
    """base64url payload that decodes to non-JSON must raise HTTP 400."""
    bad_b64 = _b64url(b"not-json-{{{")
    with pytest.raises(HTTPException) as exc_info:
        _decode_jws_payload(bad_b64)
    assert exc_info.value.status_code == 400
    assert "Invalid JWS payload" in exc_info.value.detail
