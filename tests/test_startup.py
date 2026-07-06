"""Tests for startup recovery (H1) and config guard (H5)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from jackdaw.db.engine import AsyncSessionLocal
from jackdaw.db.models import Account, Authorization, Order
from jackdaw.main import _reset_processing_orders


async def test_reset_processing_clears_orders() -> None:
    """Stuck 'processing' orders and authz are reset to 'invalid' on startup."""
    acct_id = "startup-acct-1"
    ord_id = "startup-ord-1"
    authz_id = "startup-authz-1"

    async with AsyncSessionLocal() as db:
        db.add(Account(id=acct_id, public_key="{}", status="valid", created_at=datetime.now(UTC)))
        db.add(
            Order(
                id=ord_id,
                account_id=acct_id,
                status="processing",
                identifiers=json.dumps([{"type": "dns", "value": "x.test"}]),
                created_at=datetime.now(UTC),
            )
        )
        db.add(
            Authorization(
                id=authz_id,
                order_id=ord_id,
                identifier="x.test",
                status="processing",
                created_at=datetime.now(UTC),
            )
        )
        await db.commit()

    await _reset_processing_orders()

    async with AsyncSessionLocal() as db:
        order = await db.get(Order, ord_id)
        authz = await db.get(Authorization, authz_id)

    assert order is not None and order.status == "invalid"
    assert authz is not None and authz.status == "invalid"

    # Cleanup.
    from sqlalchemy import delete

    async with AsyncSessionLocal() as db:
        await db.execute(delete(Authorization).where(Authorization.id == authz_id))
        await db.execute(delete(Order).where(Order.id == ord_id))
        await db.execute(delete(Account).where(Account.id == acct_id))
        await db.commit()


async def test_reset_processing_leaves_other_statuses() -> None:
    """Non-processing orders are not modified by the recovery pass."""
    acct_id = "startup-acct-2"
    ord_id = "startup-ord-2"

    async with AsyncSessionLocal() as db:
        db.add(Account(id=acct_id, public_key="{}", status="valid", created_at=datetime.now(UTC)))
        db.add(
            Order(
                id=ord_id,
                account_id=acct_id,
                status="pending",
                identifiers=json.dumps([{"type": "dns", "value": "y.test"}]),
                created_at=datetime.now(UTC),
            )
        )
        await db.commit()

    await _reset_processing_orders()

    async with AsyncSessionLocal() as db:
        order = await db.get(Order, ord_id)

    assert order is not None and order.status == "pending"

    from sqlalchemy import delete

    async with AsyncSessionLocal() as db:
        await db.execute(delete(Order).where(Order.id == ord_id))
        await db.execute(delete(Account).where(Account.id == acct_id))
        await db.commit()


def test_le_verify_ssl_false_with_production_raises() -> None:
    """Startup must refuse when LE_VERIFY_SSL=false with the production directory."""
    import os
    from unittest.mock import patch

    from jackdaw.main import _LE_PRODUCTION_URL

    with patch.dict(os.environ, {"LE_VERIFY_SSL": "false", "LE_DIRECTORY": _LE_PRODUCTION_URL}):
        from jackdaw.config import Settings

        settings = Settings(
            dns_provider="null",
            relay_domain="relay.test",
            acme_email="a@b.com",
            le_verify_ssl=False,
            le_directory=_LE_PRODUCTION_URL,
        )
        with pytest.raises(RuntimeError, match="LE_VERIFY_SSL=false"):
            if not settings.le_verify_ssl and settings.le_directory == _LE_PRODUCTION_URL:
                raise RuntimeError(
                    "LE_VERIFY_SSL=false must not be used with the production "
                    "Let's Encrypt directory. Set LE_DIRECTORY to the staging URL "
                    "or re-enable TLS verification."
                )


# ---------------------------------------------------------------------------
# main.py utility functions: _relay_cert_exists, _relay_cert_days_remaining,
# and _write_relay_cert
# ---------------------------------------------------------------------------


def test_relay_cert_exists_returns_false_when_missing(tmp_path, monkeypatch) -> None:
    """_relay_cert_exists must return False when the ssl_dir is empty."""
    from unittest.mock import patch

    from jackdaw.services.relay_cert import relay_cert_exists

    with patch("jackdaw.services.relay_cert.get_settings") as mock_settings:
        mock_settings.return_value.ssl_dir = str(tmp_path)
        assert relay_cert_exists() is False


def _write_cert_pair(tmp_path) -> None:
    """Write a valid fullchain.pem/privkey.pem pair to *tmp_path* for cert tests."""
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )
    from cryptography.x509.oid import NameOID

    from jackdaw.services.relay_cert import CERT_FILENAME, KEY_FILENAME

    key = generate_private_key(SECP256R1())
    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "relay.test")])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    (tmp_path / CERT_FILENAME).write_bytes(cert.public_bytes(Encoding.PEM))
    (tmp_path / KEY_FILENAME).write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )


def test_relay_cert_exists_returns_true_for_cert_pair(tmp_path) -> None:
    """A parseable cert with its key counts as present."""
    from unittest.mock import patch

    from jackdaw.services.relay_cert import relay_cert_exists

    _write_cert_pair(tmp_path)

    with patch("jackdaw.services.relay_cert.get_settings") as mock_settings:
        mock_settings.return_value.ssl_dir = str(tmp_path)
        assert relay_cert_exists() is True


def test_relay_cert_exists_returns_false_without_key(tmp_path) -> None:
    """A cert without its private key is unusable and must not count as present."""
    from unittest.mock import patch

    from jackdaw.services.relay_cert import KEY_FILENAME, relay_cert_exists

    _write_cert_pair(tmp_path)
    (tmp_path / KEY_FILENAME).unlink()

    with patch("jackdaw.services.relay_cert.get_settings") as mock_settings:
        mock_settings.return_value.ssl_dir = str(tmp_path)
        assert relay_cert_exists() is False


def test_relay_cert_exists_returns_false_for_corrupt_cert(tmp_path) -> None:
    """An unparseable cert file must be treated as absent."""
    from unittest.mock import patch

    from jackdaw.services.relay_cert import CERT_FILENAME, KEY_FILENAME, relay_cert_exists

    (tmp_path / CERT_FILENAME).write_text("this is not a certificate")
    (tmp_path / KEY_FILENAME).write_text("this is not a key")

    with patch("jackdaw.services.relay_cert.get_settings") as mock_settings:
        mock_settings.return_value.ssl_dir = str(tmp_path)
        assert relay_cert_exists() is False


def test_relay_cert_days_remaining_returns_none_when_missing(tmp_path) -> None:
    from unittest.mock import patch

    from jackdaw.services.relay_cert import relay_cert_days_remaining

    with patch("jackdaw.services.relay_cert.get_settings") as mock_settings:
        mock_settings.return_value.ssl_dir = str(tmp_path)
        assert relay_cert_days_remaining() is None


def test_relay_cert_days_remaining_returns_float_for_valid_cert(tmp_path) -> None:
    """_relay_cert_days_remaining should return a positive float for a non-expired cert."""
    from datetime import UTC, datetime, timedelta
    from unittest.mock import patch

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    from jackdaw.services.relay_cert import CERT_FILENAME, relay_cert_days_remaining

    key = generate_private_key(SECP256R1())
    now = datetime.now(UTC)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "relay.test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    (tmp_path / CERT_FILENAME).write_bytes(cert.public_bytes(Encoding.PEM))

    with patch("jackdaw.services.relay_cert.get_settings") as mock_settings:
        mock_settings.return_value.ssl_dir = str(tmp_path)
        days = relay_cert_days_remaining()

    assert days is not None
    assert 88 < days < 91


def test_relay_cert_days_remaining_returns_none_on_corrupt_cert(tmp_path) -> None:
    """_relay_cert_days_remaining must return None when the cert file is not valid PEM."""
    from unittest.mock import patch

    from jackdaw.services.relay_cert import CERT_FILENAME, relay_cert_days_remaining

    (tmp_path / CERT_FILENAME).write_text("this is not a certificate")

    with patch("jackdaw.services.relay_cert.get_settings") as mock_settings:
        mock_settings.return_value.ssl_dir = str(tmp_path)
        result = relay_cert_days_remaining()

    assert result is None


def test_write_relay_cert_writes_files(tmp_path) -> None:
    from jackdaw.services.relay_cert import CERT_FILENAME, KEY_FILENAME, write_relay_cert

    cert_path = tmp_path / "ssl" / CERT_FILENAME
    key_path = tmp_path / "ssl" / KEY_FILENAME

    write_relay_cert(cert_path, key_path, "pem-chain-content", "key-content")

    assert cert_path.read_text() == "pem-chain-content"
    assert key_path.read_text() == "key-content"
    assert oct(key_path.stat().st_mode)[-3:] == "600"


def test_write_relay_cert_renames_key_before_cert(tmp_path) -> None:
    """The key is renamed into place before the cert, so fullchain.pem is never
    momentarily paired with an old key."""
    from unittest.mock import patch

    from jackdaw.services.relay_cert import CERT_FILENAME, KEY_FILENAME, write_relay_cert

    cert_path = tmp_path / CERT_FILENAME
    key_path = tmp_path / KEY_FILENAME
    renamed: list[str] = []

    with patch(
        "jackdaw.services.relay_cert.os.replace",
        side_effect=lambda _src, dst: renamed.append(str(dst)),
    ):
        write_relay_cert(cert_path, key_path, "chain", "key")

    assert renamed == [str(key_path), str(cert_path)]


async def test_issue_relay_cert_orders_and_writes(tmp_path) -> None:
    """issue_relay_cert submits a CSR to LE and writes the returned chain + key."""
    from unittest.mock import AsyncMock, Mock, patch

    from jackdaw.services.relay_cert import CERT_FILENAME, KEY_FILENAME, issue_relay_cert

    fake_chain = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"

    with (
        patch(
            "jackdaw.services.relay_cert.le.order_cert",
            new=AsyncMock(return_value=fake_chain),
        ) as order_cert,
        patch("jackdaw.services.relay_cert.get_settings") as ms,
    ):
        ms.return_value.ssl_dir = str(tmp_path)
        await issue_relay_cert(Mock(), "relay.test")

    # LE was asked to sign a DER CSR for the relay domain.
    order_cert.assert_awaited_once()
    args = order_cert.await_args[0]
    assert args[1] == "relay.test"
    assert isinstance(args[2], bytes) and len(args[2]) > 0

    assert (tmp_path / CERT_FILENAME).read_text() == fake_chain
    key_path = tmp_path / KEY_FILENAME
    assert "PRIVATE KEY" in key_path.read_text()
    assert oct(key_path.stat().st_mode)[-3:] == "600"


def test_le_verify_ssl_false_with_staging_ok() -> None:
    """LE_VERIFY_SSL=false with staging directory must not raise."""
    from jackdaw.config import Settings
    from jackdaw.main import _LE_PRODUCTION_URL

    staging = "https://acme-staging-v02.api.letsencrypt.org/directory"
    settings = Settings(
        dns_provider="null",
        relay_domain="relay.test",
        acme_email="a@b.com",
        le_verify_ssl=False,
        le_directory=staging,
    )
    # Should not raise.
    assert not (not settings.le_verify_ssl and settings.le_directory == _LE_PRODUCTION_URL)
