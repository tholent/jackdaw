"""Tests for surfacing HTTP-01 validation failures:

- ``run_challenge`` persists an RFC 8555 §7.1.6 problem document on the
  authorization (instead of silently marking it ``invalid``);
- that problem surfaces to the client via the challenge's ``error`` field.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from jackdaw.db.engine import AsyncSessionLocal
from jackdaw.db.models import Account, Authorization, Order
from jackdaw.services.http01 import Http01ValidationError
from jackdaw.services.nonce import generate_nonce
from tests.conftest import build_jws, jwk_for_key, make_ec_key
from tests.test_order import _CT, _create_account, _create_order

# ---------------------------------------------------------------------------
# run_challenge persistence
# ---------------------------------------------------------------------------


async def _seed_authz() -> tuple[str, str]:
    """Insert account + order + authz (both 'processing') into the module DB.

    Returns ``(authz_id, order_id)``.  The account carries a real public JWK so
    ``run_challenge``'s key-authorization computation succeeds before it reaches
    the (patched) network validation.
    """
    key = make_ec_key()
    token = "tok"
    acct_id = f"ce-acct-{uuid.uuid4()}"
    order_id = f"ce-ord-{uuid.uuid4()}"
    authz_id = f"ce-authz-{uuid.uuid4()}"
    async with AsyncSessionLocal() as db:
        db.add(
            Account(
                id=acct_id,
                public_key=json.dumps(jwk_for_key(key)),
                status="valid",
                created_at=datetime.now(UTC),
            )
        )
        db.add(
            Order(
                id=order_id,
                account_id=acct_id,
                status="processing",
                identifiers=json.dumps([{"type": "dns", "value": "x.test"}]),
                created_at=datetime.now(UTC),
            )
        )
        db.add(
            Authorization(
                id=authz_id,
                order_id=order_id,
                identifier="x.test",
                status="processing",
                challenge_token=token,
                created_at=datetime.now(UTC),
            )
        )
        await db.commit()
    return authz_id, order_id


async def test_run_challenge_persists_validation_problem() -> None:
    """A DNS-resolution failure marks the authz invalid and records the problem."""
    from jackdaw import worker

    authz_id, order_id = await _seed_authz()
    with patch(
        "jackdaw.worker.validate_http01",
        new=AsyncMock(
            side_effect=Http01ValidationError(
                "DNS resolution failed for 'x.test': Name or service not known",
                acme_type="urn:ietf:params:acme:error:dns",
            )
        ),
    ):
        await worker.run_challenge(authz_id, order_id)

    async with AsyncSessionLocal() as db:
        authz = await db.get(Authorization, authz_id)
        order = await db.get(Order, order_id)
    assert authz is not None and order is not None
    assert authz.status == "invalid"
    assert order.status == "invalid"
    problem = json.loads(authz.error)
    assert problem["type"] == "urn:ietf:params:acme:error:dns"
    assert "DNS resolution failed" in problem["detail"]


async def test_run_challenge_unexpected_error_records_generic_problem() -> None:
    """A non-validation bug still fails the authz with a generic problem doc."""
    from jackdaw import worker

    authz_id, order_id = await _seed_authz()
    with patch(
        "jackdaw.worker.validate_http01",
        new=AsyncMock(side_effect=RuntimeError("kaboom")),
    ):
        await worker.run_challenge(authz_id, order_id)

    async with AsyncSessionLocal() as db:
        authz = await db.get(Authorization, authz_id)
    assert authz is not None
    assert authz.status == "invalid"
    problem = json.loads(authz.error)
    assert problem["type"] == "urn:ietf:params:acme:error:serverInternal"
    # Must not leak the raw exception text for an unexpected error.
    assert "kaboom" not in problem["detail"]


async def test_run_challenge_success_records_no_error() -> None:
    """A successful validation advances to valid/ready and records no error."""
    from jackdaw import worker

    authz_id, order_id = await _seed_authz()
    with patch("jackdaw.worker.validate_http01", new=AsyncMock(return_value=None)):
        await worker.run_challenge(authz_id, order_id)

    async with AsyncSessionLocal() as db:
        authz = await db.get(Authorization, authz_id)
        order = await db.get(Order, order_id)
    assert authz is not None and order is not None
    assert authz.status == "valid"
    assert authz.error is None
    assert order.status == "ready"


# ---------------------------------------------------------------------------
# error surfaced to the client via get_authz
# ---------------------------------------------------------------------------


async def test_get_authz_surfaces_challenge_error(
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    """A failed authz returns its problem document in the challenge `error`."""
    key, account_url = await _create_account(test_client, db_session)
    order_url, order_data = await _create_order(
        test_client, db_session, key, account_url, "test.example.com"
    )
    order_id = order_url.rsplit("/", 1)[-1]
    authz = (
        await db_session.execute(select(Authorization).where(Authorization.order_id == order_id))
    ).scalar_one()

    problem = {"type": "urn:ietf:params:acme:error:dns", "detail": "no such host"}
    authz.status = "invalid"
    authz.error = json.dumps(problem)
    await db_session.commit()

    authz_url = order_data["authorizations"][0]
    path = authz_url.replace("https://jackdaw.test", "")
    nonce = await generate_nonce(db_session)
    body = build_jws(payload=None, url=authz_url, nonce=nonce, key=key, kid=account_url)
    resp = await test_client.post(path, json=body, headers=_CT)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "invalid"
    assert data["challenges"][0]["error"] == problem


async def test_get_authz_omits_error_when_absent(
    test_client: AsyncClient, db_session: AsyncSession
) -> None:
    """A pending authz carries no `error` key on its challenge."""
    key, account_url = await _create_account(test_client, db_session)
    _, order_data = await _create_order(
        test_client, db_session, key, account_url, "test.example.com"
    )
    authz_url = order_data["authorizations"][0]
    path = authz_url.replace("https://jackdaw.test", "")
    nonce = await generate_nonce(db_session)
    body = build_jws(payload=None, url=authz_url, nonce=nonce, key=key, kid=account_url)
    resp = await test_client.post(path, json=body, headers=_CT)
    assert resp.status_code == 200
    assert "error" not in resp.json()["challenges"][0]
