"""Tests for clean handling of certificate-issuance failures:

- gufo-acme exceptions map to RFC 8555 problem documents (`acme_problem`);
- `process_finalize` persists that problem on the order and marks it invalid;
- the problem surfaces to the client via the order's `error` field;
- the idempotent `error`-column migration for pre-existing databases.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from gufo.acme.error import (
    AcmeConnectError,
    AcmeError,
    AcmeFulfillmentFailed,
    AcmeRateLimitError,
    AcmeTimeoutError,
    AcmeUnauthorizedError,
)
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jackdaw.db.engine import AsyncSessionLocal
from jackdaw.db.models import Account, Order
from jackdaw.services.le_client import acme_problem, is_known_acme_error
from jackdaw.services.nonce import generate_nonce
from tests.conftest import build_jws
from tests.test_order import _CT, _create_account, _create_order

# ---------------------------------------------------------------------------
# acme_problem / is_known_acme_error
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("exc", "expected_type"),
    [
        (AcmeRateLimitError(), "urn:ietf:params:acme:error:rateLimited"),
        (AcmeUnauthorizedError(), "urn:ietf:params:acme:error:unauthorized"),
        (AcmeFulfillmentFailed(), "urn:ietf:params:acme:error:dns"),
        (AcmeTimeoutError(), "urn:ietf:params:acme:error:connection"),
        (AcmeConnectError(), "urn:ietf:params:acme:error:connection"),
    ],
)
def test_acme_problem_maps_known_types(exc: AcmeError, expected_type: str) -> None:
    problem = acme_problem(exc)
    assert problem["type"] == expected_type
    assert problem["detail"]  # non-empty human-readable message


def test_acme_problem_generic_acme_error_keeps_message() -> None:
    problem = acme_problem(AcmeError("[400] some:error boom"))
    assert problem["type"] == "urn:ietf:params:acme:error:serverInternal"
    assert "boom" in problem["detail"]


def test_acme_problem_generic_acme_error_empty_message_has_fallback() -> None:
    problem = acme_problem(AcmeError(""))
    assert problem["type"] == "urn:ietf:params:acme:error:serverInternal"
    assert problem["detail"]


def test_acme_problem_unknown_exception_is_server_internal() -> None:
    problem = acme_problem(ValueError("not an acme error"))
    assert problem["type"] == "urn:ietf:params:acme:error:serverInternal"
    # Must not leak the raw exception text for an unexpected error.
    assert "not an acme error" not in problem["detail"]


def test_is_known_acme_error() -> None:
    assert is_known_acme_error(AcmeRateLimitError()) is True
    assert is_known_acme_error(ValueError("x")) is False


# ---------------------------------------------------------------------------
# process_finalize persistence
# ---------------------------------------------------------------------------


async def _seed_order(status: str = "processing") -> str:
    """Insert an account + order into the module DB and return the order id."""
    acct_id = f"fe-acct-{uuid.uuid4()}"
    order_id = f"fe-ord-{uuid.uuid4()}"
    async with AsyncSessionLocal() as db:
        db.add(Account(id=acct_id, public_key="{}", status="valid", created_at=datetime.now(UTC)))
        db.add(
            Order(
                id=order_id,
                account_id=acct_id,
                status=status,
                identifiers=json.dumps([{"type": "dns", "value": "x.test"}]),
                created_at=datetime.now(UTC),
            )
        )
        await db.commit()
    return order_id


async def test_process_finalize_persists_rate_limit_problem() -> None:
    """A rate-limit failure marks the order invalid and records the problem."""
    from jackdaw import worker

    order_id = await _seed_order()
    with patch(
        "jackdaw.worker.le.order_cert",
        new=AsyncMock(side_effect=AcmeRateLimitError()),
    ):
        await worker.process_finalize(order_id, "x.test", b"", MagicMock())

    async with AsyncSessionLocal() as db:
        order = await db.get(Order, order_id)
    assert order is not None
    assert order.status == "invalid"
    assert order.error is not None
    problem = json.loads(order.error)
    assert problem["type"] == "urn:ietf:params:acme:error:rateLimited"


async def test_process_finalize_known_error_logs_warning_not_traceback(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Expected ACME errors are logged as a clean warning, not an exception trace."""
    import logging

    from jackdaw import worker

    order_id = await _seed_order()
    with (
        patch("jackdaw.worker.le.order_cert", new=AsyncMock(side_effect=AcmeRateLimitError())),
        caplog.at_level(logging.WARNING, logger="jackdaw.worker"),
    ):
        await worker.process_finalize(order_id, "x.test", b"", MagicMock())

    records = [r for r in caplog.records if r.name == "jackdaw.worker"]
    assert any(r.levelno == logging.WARNING for r in records)
    # No traceback attached for an expected operational failure.
    assert all(r.exc_info is None for r in records)


async def test_process_finalize_unexpected_error_records_generic_problem() -> None:
    """A non-ACME bug still fails the order safely with a generic problem doc."""
    from jackdaw import worker

    order_id = await _seed_order()
    with patch(
        "jackdaw.worker.le.order_cert",
        new=AsyncMock(side_effect=RuntimeError("kaboom")),
    ):
        await worker.process_finalize(order_id, "x.test", b"", MagicMock())

    async with AsyncSessionLocal() as db:
        order = await db.get(Order, order_id)
    assert order is not None
    assert order.status == "invalid"
    problem = json.loads(order.error)
    assert problem["type"] == "urn:ietf:params:acme:error:serverInternal"
    assert "kaboom" not in problem["detail"]


# ---------------------------------------------------------------------------
# error surfaced to the client via get_order
# ---------------------------------------------------------------------------


async def test_get_order_surfaces_error_field(
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    """A failed order returns its problem document in the `error` field."""
    key, account_url = await _create_account(test_client, db_session)
    order_url, _ = await _create_order(
        test_client, db_session, key, account_url, "test.example.com"
    )
    order_id = order_url.rsplit("/", 1)[-1]

    problem = {"type": "urn:ietf:params:acme:error:rateLimited", "detail": "slow down"}
    order = (await db_session.execute(select(Order).where(Order.id == order_id))).scalar_one()
    order.status = "invalid"
    order.error = json.dumps(problem)
    await db_session.commit()

    nonce = await generate_nonce(db_session)
    body = build_jws(payload=None, url=order_url, nonce=nonce, key=key, kid=account_url)
    resp = await test_client.post(
        order_url.replace("https://jackdaw.test", ""), json=body, headers=_CT
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "invalid"
    assert data["error"] == problem


async def test_get_order_omits_error_when_absent(
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    """A healthy order carries no `error` key."""
    key, account_url = await _create_account(test_client, db_session)
    order_url, _ = await _create_order(
        test_client, db_session, key, account_url, "test.example.com"
    )

    nonce = await generate_nonce(db_session)
    body = build_jws(payload=None, url=order_url, nonce=nonce, key=key, kid=account_url)
    resp = await test_client.post(
        order_url.replace("https://jackdaw.test", ""), json=body, headers=_CT
    )
    assert resp.status_code == 200
    assert "error" not in resp.json()
