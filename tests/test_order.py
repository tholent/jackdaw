"""Tests for order-related routes: domain policy, finalize_order error paths."""

from __future__ import annotations

import base64
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jackdaw.db.models import Authorization, Order
from jackdaw.routes.order import _check_domain_policy, _validate_identifiers
from jackdaw.schemas.acme import Identifier
from jackdaw.services.nonce import generate_nonce
from tests.conftest import build_jws, jwk_for_key, make_ec_key

_CT = {"Content-Type": "application/jose+json"}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_csr(domain: str) -> bytes:
    """Return a minimal DER-encoded CSR for *domain*."""
    key = generate_private_key(SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(Encoding.DER)


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


async def _create_order(
    client: AsyncClient, db: AsyncSession, key: Any, account_url: str, domain: str
) -> tuple[str, dict]:
    nonce = await generate_nonce(db)
    body = build_jws(
        payload={"identifiers": [{"type": "dns", "value": domain}]},
        url="https://jackdaw.test/acme/new-order",
        nonce=nonce,
        key=key,
        kid=account_url,
    )
    resp = await client.post("/acme/new-order", json=body, headers=_CT)
    assert resp.status_code == 201
    return resp.headers["location"], resp.json()


# ---------------------------------------------------------------------------
# _check_domain_policy unit tests
# ---------------------------------------------------------------------------


def test_check_domain_policy_rejects_disallowed_domain() -> None:
    with patch("jackdaw.routes.order.get_settings") as mock_settings:
        mock_settings.return_value.allowed_domain_list = ["example.com"]
        with pytest.raises(HTTPException) as exc_info:
            _check_domain_policy([Identifier(type="dns", value="evil.com")])
    assert exc_info.value.status_code == 403


def test_check_domain_policy_allows_exact_match() -> None:
    with patch("jackdaw.routes.order.get_settings") as mock_settings:
        mock_settings.return_value.allowed_domain_list = ["example.com"]
        _check_domain_policy([Identifier(type="dns", value="example.com")])  # no raise


def test_check_domain_policy_allows_subdomain() -> None:
    with patch("jackdaw.routes.order.get_settings") as mock_settings:
        mock_settings.return_value.allowed_domain_list = ["example.com"]
        _check_domain_policy([Identifier(type="dns", value="sub.example.com")])  # no raise


# ---------------------------------------------------------------------------
# _validate_identifiers unit tests
# ---------------------------------------------------------------------------


def test_validate_identifiers_accepts_valid_dns() -> None:
    _validate_identifiers([Identifier(type="dns", value="example.com")])  # no raise


def test_validate_identifiers_rejects_empty_list() -> None:
    with pytest.raises(HTTPException) as exc_info:
        _validate_identifiers([])
    assert exc_info.value.status_code == 400


def test_validate_identifiers_rejects_non_dns_type() -> None:
    with pytest.raises(HTTPException) as exc_info:
        _validate_identifiers([Identifier(type="ip", value="192.168.1.1")])
    assert exc_info.value.status_code == 400


def test_validate_identifiers_rejects_blank_value() -> None:
    with pytest.raises(HTTPException) as exc_info:
        _validate_identifiers([Identifier(type="dns", value="   ")])
    assert exc_info.value.status_code == 400


# ---------------------------------------------------------------------------
# finalize_order error paths
# ---------------------------------------------------------------------------


async def test_finalize_order_non_ready_returns_403(
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    """finalize_order must return 403 when order is not in 'ready' state."""
    key, account_url = await _create_account(test_client, db_session)
    order_url, order_data = await _create_order(
        test_client, db_session, key, account_url, "test.example.com"
    )
    # Order is still 'pending' — not yet ready.
    csr_b64 = _b64url(_make_csr("test.example.com"))
    finalize_url = order_data["finalize"]
    nonce = await generate_nonce(db_session)
    body = build_jws(
        payload={"csr": csr_b64},
        url=finalize_url,
        nonce=nonce,
        key=key,
        kid=account_url,
    )
    path = finalize_url.replace("https://jackdaw.test", "")
    resp = await test_client.post(path, json=body, headers=_CT)
    assert resp.status_code == 403
    assert "orderNotReady" in resp.text


async def test_finalize_order_ready_dispatches_task(
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    """finalize_order with a ready order should return 200 and kick off the background task."""
    from unittest.mock import MagicMock

    from jackdaw.main import app

    key, account_url = await _create_account(test_client, db_session)
    order_url, order_data = await _create_order(
        test_client, db_session, key, account_url, "test.example.com"
    )

    # Advance order (and its authz) to 'ready' so finalize is accepted.
    order_id = order_url.rsplit("/", 1)[-1]
    result = await db_session.execute(select(Order).where(Order.id == order_id))
    order = result.scalar_one()
    order.status = "ready"
    result2 = await db_session.execute(
        select(Authorization).where(Authorization.order_id == order_id)
    )
    for authz in result2.scalars().all():
        authz.status = "valid"
    await db_session.commit()

    csr_b64 = _b64url(_make_csr("test.example.com"))
    finalize_url = order_data["finalize"]
    nonce = await generate_nonce(db_session)
    body = build_jws(
        payload={"csr": csr_b64},
        url=finalize_url,
        nonce=nonce,
        key=key,
        kid=account_url,
    )
    path = finalize_url.replace("https://jackdaw.test", "")

    app.state.le_client = MagicMock()
    try:
        with patch("jackdaw.worker.process_finalize", new=AsyncMock(return_value=None)):
            resp = await test_client.post(path, json=body, headers=_CT)
    finally:
        del app.state.le_client

    assert resp.status_code == 200
    body_json = resp.json()
    assert "finalize" in body_json
