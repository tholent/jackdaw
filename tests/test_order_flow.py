"""Integration test for the full ACME order flow against Pebble.

These tests require a running Pebble instance (LE's test ACME server).
Run with:

    docker-compose -f docker-compose.test.yml up -d pebble
    pytest tests/test_order_flow.py

The ``PEBBLE_URL`` environment variable overrides the default URL.
Skip the module automatically when Pebble is not reachable.
"""

from __future__ import annotations

import asyncio
import base64
import os
import tempfile
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from httpx import ASGITransport, AsyncClient
from josepy.jwa import ES256

from jackdaw.db.engine import AsyncSessionLocal, get_db
from jackdaw.main import app
from jackdaw.services.le_client import JackdawAcmeClient, _load_or_create_account_key
from jackdaw.services.nonce import generate_nonce
from tests.conftest import build_jws, jwk_for_key, make_ec_key

PEBBLE_URL = os.environ.get("PEBBLE_URL", "https://localhost:14000")

# ---------------------------------------------------------------------------
# Skip entire module when Pebble is unreachable.
# ---------------------------------------------------------------------------


def _pebble_reachable() -> bool:
    try:
        import httpx as _httpx

        with _httpx.Client(verify=False, timeout=2) as c:
            c.get(f"{PEBBLE_URL}/dir")
            return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _pebble_reachable(),
    reason="Pebble ACME test server not reachable — skipping integration tests",
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_test_csr(domain: str) -> bytes:
    """Build a DER-encoded CSR for *domain*."""
    key = generate_private_key(SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(Encoding.DER)


async def _poll_order(
    client: AsyncClient,
    order_url: str,
    target_status: str,
    account_key: Any,
    kid: str,
    max_tries: int = 30,
) -> dict:
    """POST-as-GET *order_url* until ``status`` equals *target_status* (RFC 8555 §6.3)."""
    body: dict = {}
    order_path = order_url.replace("https://jackdaw.test", "")
    for _ in range(max_tries):
        async with AsyncSessionLocal() as db:
            nonce = await generate_nonce(db)
        jws = build_jws(
            payload=None,
            url=order_url,
            nonce=nonce,
            key=account_key,
            kid=kid,
        )
        resp = await client.post(
            order_path,
            json=jws,
            headers={"Content-Type": "application/jose+json"},
        )
        body = resp.json()
        if body["status"] == target_status:
            return body
        await asyncio.sleep(1)
    raise AssertionError(f"Order never reached status={target_status!r}; last={body!r}")


# ---------------------------------------------------------------------------
# Fixture: test client wired to the module-level DB + Pebble LE client.
# ---------------------------------------------------------------------------


class _NopDNSProvider:
    """No-op DNS provider — Pebble's PEBBLE_VA_ALWAYS_VALID=1 skips DNS checks."""

    set_txt = AsyncMock(return_value=None)
    delete_txt = AsyncMock(return_value=None)


@pytest_asyncio.fixture()
async def pebble_client() -> AsyncGenerator[AsyncClient, None]:
    """AsyncClient backed by the app, using the module-level DB and a live Pebble LE client.

    Route handlers and the background worker both use ``AsyncSessionLocal``, so
    rows written by a route are visible to the worker running in the same process.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        key = _load_or_create_account_key(Path(tmpdir) / "le_account.key")
        le_client = JackdawAcmeClient(
            f"{PEBBLE_URL}/dir",
            dns_provider=_NopDNSProvider(),
            propagation_wait=0,
            verify_ssl=False,
            key=key,
            alg=ES256,
        )
        await le_client.new_account("test@example.com")
        app.state.le_client = le_client

        async def _override_db() -> AsyncGenerator:
            async with AsyncSessionLocal() as session:
                yield session

        app.dependency_overrides[get_db] = _override_db  # type: ignore[assignment]

        async with AsyncClient(
            transport=ASGITransport(app=app),  # type: ignore[arg-type]
            base_url="https://jackdaw.test",
        ) as client:
            yield client

    app.dependency_overrides.clear()
    if hasattr(app.state, "le_client"):
        del app.state.le_client


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------


async def test_full_order_flow(pebble_client: AsyncClient) -> None:
    """Happy-path end-to-end: directory → nonce → account → order → cert.

    The relay's HTTP-01 leg is mocked out here — it is tested independently
    in tests/test_http01.py.  This test exercises the LE/Pebble leg only.
    """
    domain = "test.example.com"

    # Step 1: GET /directory
    dir_resp = await pebble_client.get("/directory")
    assert dir_resp.status_code == 200

    # Step 2: HEAD /acme/new-nonce
    nonce_resp = await pebble_client.head("/acme/new-nonce")
    assert nonce_resp.status_code == 200
    assert "replay-nonce" in nonce_resp.headers

    account_key = make_ec_key()
    jwk = jwk_for_key(account_key)

    # Step 3: POST /acme/new-account
    async with AsyncSessionLocal() as db:
        nonce = await generate_nonce(db)
    acct_body = build_jws(
        payload={"termsOfServiceAgreed": True},
        url="https://jackdaw.test/acme/new-account",
        nonce=nonce,
        key=account_key,
        jwk=jwk,
    )
    acct_resp = await pebble_client.post(
        "/acme/new-account",
        json=acct_body,
        headers={"Content-Type": "application/jose+json"},
    )
    assert acct_resp.status_code == 201
    account_url = acct_resp.headers["location"]

    # Step 4: POST /acme/new-order
    async with AsyncSessionLocal() as db:
        nonce = await generate_nonce(db)
    order_body = build_jws(
        payload={"identifiers": [{"type": "dns", "value": domain}]},
        url="https://jackdaw.test/acme/new-order",
        nonce=nonce,
        key=account_key,
        kid=account_url,
    )
    order_resp = await pebble_client.post(
        "/acme/new-order",
        json=order_body,
        headers={"Content-Type": "application/jose+json"},
    )
    assert order_resp.status_code == 201
    order_data = order_resp.json()
    order_url = order_resp.headers["location"]

    # Step 5: POST /acme/authz/{id} (POST-as-GET, RFC 8555 §6.3)
    authz_url = order_data["authorizations"][0]
    authz_path = authz_url.replace("https://jackdaw.test", "")
    async with AsyncSessionLocal() as db:
        nonce = await generate_nonce(db)
    authz_body = build_jws(
        payload=None,
        url=authz_url,
        nonce=nonce,
        key=account_key,
        kid=account_url,
    )
    authz_resp = await pebble_client.post(
        authz_path,
        json=authz_body,
        headers={"Content-Type": "application/jose+json"},
    )
    assert authz_resp.status_code == 200
    authz_data = authz_resp.json()
    # Jackdaw validates HTTP-01 from the client, so it must advertise http-01.
    assert not any(c["type"] == "dns-01" for c in authz_data["challenges"])
    challenge = next(c for c in authz_data["challenges"] if c["type"] == "http-01")
    challenge_path = challenge["url"].replace("https://jackdaw.test", "")

    # Step 6: POST /acme/challenge/{id}
    # Patch HTTP-01 validation to succeed instantly; Pebble (PEBBLE_VA_ALWAYS_VALID=1)
    # handles its own challenge validation independently on the LE leg.
    async with AsyncSessionLocal() as db:
        nonce = await generate_nonce(db)
    chall_body = build_jws(
        payload={},
        url=challenge["url"],
        nonce=nonce,
        key=account_key,
        kid=account_url,
    )
    with patch("jackdaw.worker.validate_http01", new=AsyncMock(return_value=None)):
        chall_resp = await pebble_client.post(
            challenge_path,
            json=chall_body,
            headers={"Content-Type": "application/jose+json"},
        )
    assert chall_resp.status_code == 200

    # Step 7: Poll until order is ready
    order_state = await _poll_order(pebble_client, order_url, "ready", account_key, account_url)
    assert order_state["status"] == "ready"

    # Step 8: POST /acme/order/{id}/finalize
    csr_der = _make_test_csr(domain)
    async with AsyncSessionLocal() as db:
        nonce = await generate_nonce(db)
    finalize_url = order_state["finalize"]
    finalize_path = finalize_url.replace("https://jackdaw.test", "")
    finalize_body = build_jws(
        payload={"csr": _b64url(csr_der)},
        url=finalize_url,
        nonce=nonce,
        key=account_key,
        kid=account_url,
    )
    fin_resp = await pebble_client.post(
        finalize_path,
        json=finalize_body,
        headers={"Content-Type": "application/jose+json"},
    )
    assert fin_resp.status_code == 200

    # Step 9: Poll until order is valid
    order_state = await _poll_order(pebble_client, order_url, "valid", account_key, account_url)
    assert order_state["status"] == "valid"
    assert "certificate" in order_state

    # Step 10: POST /acme/cert/{id} (POST-as-GET, RFC 8555 §6.3)
    cert_url = order_state["certificate"]
    cert_path = cert_url.replace("https://jackdaw.test", "")
    async with AsyncSessionLocal() as db:
        nonce = await generate_nonce(db)
    cert_body = build_jws(
        payload=None,
        url=cert_url,
        nonce=nonce,
        key=account_key,
        kid=account_url,
    )
    cert_resp = await pebble_client.post(
        cert_path,
        json=cert_body,
        headers={"Content-Type": "application/jose+json"},
    )
    assert cert_resp.status_code == 200
    assert "-----BEGIN CERTIFICATE-----" in cert_resp.text
    assert cert_resp.headers["content-type"] == "application/pem-certificate-chain"
