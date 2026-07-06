"""Tests for POST /acme/revoke-cert (H4b)."""

from __future__ import annotations

import base64
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from jackdaw.db.models import Certificate, Order
from jackdaw.services.nonce import generate_nonce
from tests.conftest import build_jws, jwk_for_key, make_ec_key

_CT = {"Content-Type": "application/jose+json"}


def _make_cert() -> tuple[str, str]:
    """Generate a self-signed cert; return (pem_chain, der_b64url)."""
    priv = generate_private_key(SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.internal")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=90))
        .sign(priv, hashes.SHA256())
    )
    pem = cert.public_bytes(Encoding.PEM).decode()
    der_b64 = base64.urlsafe_b64encode(cert.public_bytes(Encoding.DER)).rstrip(b"=").decode()
    return pem, der_b64


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


async def _insert_cert_for_account(db: AsyncSession, account_id: str, pem_chain: str) -> None:
    """Insert an order + certificate row for the given account."""
    ord_id = f"rev-ord-{uuid.uuid4()}"
    cert_id = f"rev-cert-{uuid.uuid4()}"
    db.add(
        Order(
            id=ord_id,
            account_id=account_id,
            status="valid",
            identifiers=json.dumps([{"type": "dns", "value": "test.example.internal"}]),
            cert_id=cert_id,
            created_at=datetime.now(UTC),
        )
    )
    db.add(
        Certificate(
            id=cert_id,
            order_id=ord_id,
            pem_chain=pem_chain,
            issued_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(days=90),
        )
    )
    await db.commit()


async def test_revoke_cert_success(test_client: AsyncClient, db_session: AsyncSession) -> None:
    """POST /acme/revoke-cert returns 200 when cert is owned by the caller."""
    key, account_url = await _create_account(test_client, db_session)
    account_id = account_url.rsplit("/", 1)[-1]

    pem, der_b64 = _make_cert()
    await _insert_cert_for_account(db_session, account_id, pem)

    nonce = await generate_nonce(db_session)
    revoke_url = "https://jackdaw.test/acme/revoke-cert"
    body = build_jws(
        payload={"certificate": der_b64},
        url=revoke_url,
        nonce=nonce,
        key=key,
        kid=account_url,
    )

    from jackdaw.main import app

    mock_dir = MagicMock()
    mock_dir.revoke_cert = "https://acme-v02.api.letsencrypt.org/acme/revoke-cert"
    mock_le = MagicMock()
    mock_le._get_directory = AsyncMock(return_value=mock_dir)
    mock_le._post = AsyncMock(return_value=None)

    app.state.le_client = mock_le
    try:
        resp = await test_client.post("/acme/revoke-cert", json=body, headers=_CT)
    finally:
        del app.state.le_client

    assert resp.status_code == 200
    mock_le._post.assert_awaited_once()


def test_serial_hex_format() -> None:
    """serial_hex renders an int as lowercase hex with no prefix."""
    from jackdaw.services.cert_store import serial_hex

    assert serial_hex(255) == "ff"
    assert serial_hex(0) == "0"
    # A 160-bit value round-trips without overflow (the reason we store hex).
    big = 2**159 + 123
    assert int(serial_hex(big), 16) == big


async def test_store_cert_populates_serial(db_session: AsyncSession) -> None:
    """store_cert records the leaf's serial as hex."""
    from jackdaw.services.cert_store import serial_hex, store_cert

    pem, _ = _make_cert()
    leaf = x509.load_pem_x509_certificate(pem.encode())

    ord_id = f"ser-ord-{uuid.uuid4()}"
    db_session.add(
        Order(
            id=ord_id,
            account_id="ser-acct",
            status="valid",
            identifiers="[]",
            created_at=datetime.now(UTC),
        )
    )
    await db_session.commit()
    cert_id = await store_cert(db_session, ord_id, pem, datetime.now(UTC) + timedelta(days=90))

    cert = await db_session.get(Certificate, cert_id)
    assert cert is not None
    assert cert.serial == serial_hex(leaf.serial_number)


async def test_revoke_cert_fast_path_by_serial(
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    """A cert stored with its serial is revoked via the indexed lookup (fast path)."""
    from jackdaw.main import app
    from jackdaw.services.cert_store import store_cert

    key, account_url = await _create_account(test_client, db_session)
    account_id = account_url.rsplit("/", 1)[-1]

    pem, der_b64 = _make_cert()
    ord_id = f"rev-fast-ord-{uuid.uuid4()}"
    db_session.add(
        Order(
            id=ord_id,
            account_id=account_id,
            status="valid",
            identifiers=json.dumps([{"type": "dns", "value": "test.example.internal"}]),
            created_at=datetime.now(UTC),
        )
    )
    await db_session.commit()
    await store_cert(db_session, ord_id, pem, datetime.now(UTC) + timedelta(days=90))

    nonce = await generate_nonce(db_session)
    body = build_jws(
        payload={"certificate": der_b64},
        url="https://jackdaw.test/acme/revoke-cert",
        nonce=nonce,
        key=key,
        kid=account_url,
    )

    mock_dir = MagicMock()
    mock_dir.revoke_cert = "https://acme-v02.api.letsencrypt.org/acme/revoke-cert"
    mock_le = MagicMock()
    mock_le._get_directory = AsyncMock(return_value=mock_dir)
    mock_le._post = AsyncMock(return_value=None)

    app.state.le_client = mock_le
    try:
        resp = await test_client.post("/acme/revoke-cert", json=body, headers=_CT)
    finally:
        del app.state.le_client

    assert resp.status_code == 200
    mock_le._post.assert_awaited_once()


async def test_revoke_cert_wrong_account(
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    """POST /acme/revoke-cert returns 403 when cert belongs to a different account."""
    owner_key, owner_url = await _create_account(test_client, db_session)
    caller_key, caller_url = await _create_account(test_client, db_session)

    owner_id = owner_url.rsplit("/", 1)[-1]
    pem, der_b64 = _make_cert()
    await _insert_cert_for_account(db_session, owner_id, pem)

    nonce = await generate_nonce(db_session)
    body = build_jws(
        payload={"certificate": der_b64},
        url="https://jackdaw.test/acme/revoke-cert",
        nonce=nonce,
        key=caller_key,
        kid=caller_url,
    )

    resp = await test_client.post("/acme/revoke-cert", json=body, headers=_CT)
    assert resp.status_code == 403


async def test_revoke_cert_missing_payload(
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    """POST /acme/revoke-cert returns 400 when 'certificate' field is absent."""
    key, account_url = await _create_account(test_client, db_session)
    nonce = await generate_nonce(db_session)
    body = build_jws(
        payload={"reason": 1},
        url="https://jackdaw.test/acme/revoke-cert",
        nonce=nonce,
        key=key,
        kid=account_url,
    )
    resp = await test_client.post("/acme/revoke-cert", json=body, headers=_CT)
    assert resp.status_code == 400


async def test_revoke_cert_bad_der_returns_400(
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    """'certificate' field with invalid base64url/DER must return 400."""
    key, account_url = await _create_account(test_client, db_session)
    nonce = await generate_nonce(db_session)
    body = build_jws(
        payload={"certificate": "not-valid-der!!!"},
        url="https://jackdaw.test/acme/revoke-cert",
        nonce=nonce,
        key=key,
        kid=account_url,
    )
    resp = await test_client.post("/acme/revoke-cert", json=body, headers=_CT)
    assert resp.status_code == 400
    assert "Invalid certificate DER" in resp.text


async def test_revoke_cert_le_failure_returns_500(
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    """When the LE revocation call fails, the route must return 500."""
    from jackdaw.main import app

    key, account_url = await _create_account(test_client, db_session)
    account_id = account_url.rsplit("/", 1)[-1]

    pem, der_b64 = _make_cert()
    await _insert_cert_for_account(db_session, account_id, pem)

    nonce = await generate_nonce(db_session)
    body = build_jws(
        payload={"certificate": der_b64, "reason": 1},
        url="https://jackdaw.test/acme/revoke-cert",
        nonce=nonce,
        key=key,
        kid=account_url,
    )

    mock_dir = MagicMock()
    mock_dir.revoke_cert = "https://acme-v02.api.letsencrypt.org/acme/revoke-cert"
    mock_le = MagicMock()
    mock_le._get_directory = AsyncMock(return_value=mock_dir)
    mock_le._post = AsyncMock(side_effect=RuntimeError("LE unavailable"))

    app.state.le_client = mock_le
    try:
        resp = await test_client.post("/acme/revoke-cert", json=body, headers=_CT)
    finally:
        del app.state.le_client

    assert resp.status_code == 500
    assert "serverInternal" in resp.text
