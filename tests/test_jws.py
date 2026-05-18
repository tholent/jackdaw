"""Unit tests for JWS verification."""

from __future__ import annotations

import base64
import json

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from jackdaw.services.nonce import generate_nonce
from tests.conftest import build_jws, jwk_for_key, make_ec_key

_CT = {"Content-Type": "application/jose+json"}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


async def _create_account(client: AsyncClient, db: AsyncSession) -> tuple:
    """Create a fresh account; return (key, account_url)."""
    key = make_ec_key()
    jwk = jwk_for_key(key)
    nonce = await generate_nonce(db)
    body = build_jws(
        payload={"termsOfServiceAgreed": True},
        url="https://jackdaw.test/acme/new-account",
        nonce=nonce, key=key, jwk=jwk,
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
