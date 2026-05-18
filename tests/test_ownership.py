"""Tests for C2: resource ownership enforcement across all ACME routes.

Every authenticated route must verify the requested resource belongs to the
account that signed the JWS.  A different account must receive 403, not the
resource.
"""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from jackdaw.services.nonce import generate_nonce
from tests.conftest import build_jws, jwk_for_key, make_ec_key

_CT = {"Content-Type": "application/jose+json"}


async def _create_account(client: AsyncClient, db: AsyncSession):
    """Return (key, account_url) for a freshly registered account."""
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


async def _create_order(client: AsyncClient, db: AsyncSession, key, account_url: str, domain: str):
    """Place a new order; return (order_url, order_data, authz_url)."""
    nonce = await generate_nonce(db)
    body = build_jws(
        payload={"identifiers": [{"type": "dns", "value": domain}]},
        url="https://jackdaw.test/acme/new-order",
        nonce=nonce, key=key, kid=account_url,
    )
    resp = await client.post("/acme/new-order", json=body, headers=_CT)
    assert resp.status_code == 201
    data = resp.json()
    return resp.headers["location"], data, data["authorizations"][0]


async def _post_as_get(client: AsyncClient, db: AsyncSession, key, kid: str, url: str):
    """Issue a POST-as-GET (empty payload) to *url* as *kid* and return the response."""
    nonce = await generate_nonce(db)
    body = build_jws(payload=None, url=url, nonce=nonce, key=key, kid=kid)
    path = url.replace("https://jackdaw.test", "")
    return await client.post(path, json=body, headers=_CT)


# ---------------------------------------------------------------------------
# Cross-account order access
# ---------------------------------------------------------------------------


async def test_cross_account_get_order_returns_403(
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    """Account B must not be able to GET account A's order."""
    key_a, url_a = await _create_account(test_client, db_session)
    key_b, url_b = await _create_account(test_client, db_session)

    order_url, _, _ = await _create_order(test_client, db_session, key_a, url_a, "a.example.com")

    resp = await _post_as_get(test_client, db_session, key_b, url_b, order_url)
    assert resp.status_code == 403


async def test_cross_account_finalize_returns_403(
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    """Account B must not be able to finalize account A's order."""
    import base64

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    key_a, url_a = await _create_account(test_client, db_session)
    key_b, url_b = await _create_account(test_client, db_session)

    order_url, order_data, _ = await _create_order(
        test_client, db_session, key_a, url_a, "a.example.com"
    )

    # Build a minimal CSR to send in the finalize payload.
    csr_key = generate_private_key(SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "a.example.com")]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("a.example.com")]), critical=False
        )
        .sign(csr_key, hashes.SHA256())
    )
    csr_b64 = base64.urlsafe_b64encode(csr.public_bytes(Encoding.DER)).rstrip(b"=").decode()

    finalize_url = order_data["finalize"]
    nonce = await generate_nonce(db_session)
    body = build_jws(
        payload={"csr": csr_b64},
        url=finalize_url,
        nonce=nonce,
        key=key_b,
        kid=url_b,
    )
    path = finalize_url.replace("https://jackdaw.test", "")
    resp = await test_client.post(path, json=body, headers=_CT)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Cross-account authz access
# ---------------------------------------------------------------------------


async def test_cross_account_get_authz_returns_403(
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    """Account B must not be able to GET account A's authorization."""
    key_a, url_a = await _create_account(test_client, db_session)
    key_b, url_b = await _create_account(test_client, db_session)

    _, _, authz_url = await _create_order(test_client, db_session, key_a, url_a, "a.example.com")

    resp = await _post_as_get(test_client, db_session, key_b, url_b, authz_url)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Cross-account challenge access
# ---------------------------------------------------------------------------


async def test_cross_account_challenge_returns_403(
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    """Account B must not be able to trigger validation of account A's challenge."""
    key_a, url_a = await _create_account(test_client, db_session)
    key_b, url_b = await _create_account(test_client, db_session)

    _, _, authz_url = await _create_order(test_client, db_session, key_a, url_a, "a.example.com")

    # GET the authz as account A to find the challenge URL.
    authz_resp = await _post_as_get(test_client, db_session, key_a, url_a, authz_url)
    assert authz_resp.status_code == 200
    challenge_url = authz_resp.json()["challenges"][0]["url"]

    # Account B tries to POST to the challenge.
    nonce = await generate_nonce(db_session)
    challenge_path = challenge_url.replace("https://jackdaw.test", "")
    body = build_jws(payload={}, url=challenge_url, nonce=nonce, key=key_b, kid=url_b)
    resp = await test_client.post(challenge_path, json=body, headers=_CT)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Own resources are accessible
# ---------------------------------------------------------------------------


async def test_own_order_is_accessible(
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    """Sanity check: an account can always access its own order."""
    key_a, url_a = await _create_account(test_client, db_session)
    order_url, _, _ = await _create_order(test_client, db_session, key_a, url_a, "a.example.com")

    resp = await _post_as_get(test_client, db_session, key_a, url_a, order_url)
    assert resp.status_code == 200


async def test_own_authz_is_accessible(
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    """Sanity check: an account can always access its own authorization."""
    key_a, url_a = await _create_account(test_client, db_session)
    _, _, authz_url = await _create_order(test_client, db_session, key_a, url_a, "a.example.com")

    resp = await _post_as_get(test_client, db_session, key_a, url_a, authz_url)
    assert resp.status_code == 200
