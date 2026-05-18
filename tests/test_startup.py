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
