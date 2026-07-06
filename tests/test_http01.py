"""Tests for C1: HTTP-01 challenge validation.

Covers:
- key_authorization() format correctness
- SSRF guard (loopback, link-local rejected)
- validate_http01() success, wrong key-auth, HTTP error, timeout
- worker.run_challenge() integration (authz/order state transitions)
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from jackdaw.db.models import Account, Authorization, Order
from jackdaw.services.http01 import (
    Http01ValidationError,
    _attempt_validation,
    _fetch_and_compare,
    _is_blocked,
    _resolve_and_check,
    key_authorization,
    validate_http01,
)
from jackdaw.services.nonce import generate_nonce
from tests.conftest import build_jws, jwk_for_key, make_ec_key

_CT = {"Content-Type": "application/jose+json"}

# ---------------------------------------------------------------------------
# key_authorization()
# ---------------------------------------------------------------------------


def _make_account_jwk_json() -> str:
    """Build a canonical JWK JSON string for a fresh EC key."""
    from jackdaw._util import canonical_jwk

    key = make_ec_key()
    return canonical_jwk(jwk_for_key(key))


def test_key_authorization_format() -> None:
    """key_authorization() must return 'token.thumbprint' (no newline, no padding)."""
    token = "abc123"
    jwk_json = _make_account_jwk_json()
    result = key_authorization(token, jwk_json)

    assert result.startswith(f"{token}.")
    parts = result.split(".")
    assert len(parts) == 2
    # Thumbprint is base64url without padding.
    thumb = parts[1]
    assert "=" not in thumb
    assert " " not in thumb
    assert "\n" not in thumb


def test_key_authorization_is_deterministic() -> None:
    """Same token + key always produces the same key authorization."""
    token = "my-token"
    jwk_json = _make_account_jwk_json()
    assert key_authorization(token, jwk_json) == key_authorization(token, jwk_json)


def test_key_authorization_differs_by_key() -> None:
    """Different account keys produce different key authorizations for the same token."""
    token = "shared-token"
    jwk1 = _make_account_jwk_json()
    jwk2 = _make_account_jwk_json()
    assert key_authorization(token, jwk1) != key_authorization(token, jwk2)


# ---------------------------------------------------------------------------
# SSRF guard (_resolve_and_check)
# ---------------------------------------------------------------------------


def test_ssrf_loopback_rejected() -> None:
    """Hostnames resolving to 127.x addresses must be rejected."""
    with patch("jackdaw.services.http01.socket.getaddrinfo") as mock_gai:
        mock_gai.return_value = [
            (2, 1, 6, "", ("127.0.0.1", 0)),
        ]
        with pytest.raises(Http01ValidationError, match="blocked"):
            _resolve_and_check("localhost")


def test_ssrf_link_local_rejected() -> None:
    """169.254.x.x (cloud metadata) addresses must be rejected."""
    with patch("jackdaw.services.http01.socket.getaddrinfo") as mock_gai:
        mock_gai.return_value = [
            (2, 1, 6, "", ("169.254.169.254", 0)),
        ]
        with pytest.raises(Http01ValidationError, match="blocked"):
            _resolve_and_check("metadata.internal")


def test_ssrf_private_range_allowed() -> None:
    """RFC 1918 addresses must NOT be blocked (internal clients live there)."""
    with patch("jackdaw.services.http01.socket.getaddrinfo") as mock_gai:
        mock_gai.return_value = [
            (2, 1, 6, "", ("10.0.0.5", 0)),
        ]
        ip = _resolve_and_check("internal-service.local")
        assert ip == "10.0.0.5"


def test_ssrf_dns_failure_raises() -> None:
    """DNS resolution failure must raise Http01ValidationError."""

    with patch("jackdaw.services.http01.socket.getaddrinfo", side_effect=OSError("NXDOMAIN")):
        with pytest.raises(Http01ValidationError, match="DNS resolution failed"):
            _resolve_and_check("nonexistent.invalid")


# ---------------------------------------------------------------------------
# validate_http01() — mocked httpx transport
# ---------------------------------------------------------------------------


def _make_client_factory(status: int, body: str) -> Any:
    """Return a client_factory that always responds with *status* and *body*."""

    def factory():
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_response = MagicMock()
        mock_response.status_code = status
        mock_response.content = body.encode()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        return mock_client

    return factory


async def test_validate_http01_success() -> None:
    """validate_http01 must not raise when the response matches the expected key auth."""
    jwk_json = _make_account_jwk_json()
    token = "valid-token"
    expected = key_authorization(token, jwk_json)

    await validate_http01(
        "service.internal",
        token,
        expected,
        client_factory=_make_client_factory(200, expected),
    )


async def test_validate_http01_wrong_key_auth_raises() -> None:
    """validate_http01 must raise Http01ValidationError when key auth doesn't match."""
    jwk_json = _make_account_jwk_json()
    token = "token"
    expected = key_authorization(token, jwk_json)

    with pytest.raises(Http01ValidationError, match="mismatch"):
        await validate_http01(
            "service.internal",
            token,
            expected,
            client_factory=_make_client_factory(200, "wrong-value"),
        )


async def test_validate_http01_http_error_raises() -> None:
    """A non-200 HTTP status must raise Http01ValidationError."""
    jwk_json = _make_account_jwk_json()
    token = "token"
    expected = key_authorization(token, jwk_json)

    with pytest.raises(Http01ValidationError, match="status 404"):
        await validate_http01(
            "service.internal",
            token,
            expected,
            client_factory=_make_client_factory(404, "Not Found"),
        )


async def test_validate_http01_empty_body_raises() -> None:
    """An empty response body must raise Http01ValidationError."""
    jwk_json = _make_account_jwk_json()
    token = "token"
    expected = key_authorization(token, jwk_json)

    with pytest.raises(Http01ValidationError, match="empty"):
        await validate_http01(
            "service.internal",
            token,
            expected,
            client_factory=_make_client_factory(200, ""),
        )


async def test_validate_http01_timeout_raises() -> None:
    """A connection timeout must raise Http01ValidationError."""
    jwk_json = _make_account_jwk_json()
    token = "token"
    expected = key_authorization(token, jwk_json)

    def timeout_factory():
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timed out"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        return mock_client

    with pytest.raises(Http01ValidationError, match="timed out"):
        await validate_http01(
            "service.internal",
            token,
            expected,
            client_factory=timeout_factory,
        )


# ---------------------------------------------------------------------------
# worker.run_challenge() — state machine integration
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture()
async def challenge_setup():
    """Insert account + order + authz into the module-level DB (used by the worker).

    The worker calls ``AsyncSessionLocal()`` directly, so test data must live
    in the same engine the worker accesses, not in the per-test ``db_session``.
    Unique UUIDs are used so concurrent fixture invocations don't collide.
    Rows are cleaned up after the test.
    """
    import uuid
    from datetime import UTC, datetime

    from jackdaw._util import canonical_jwk
    from jackdaw.db.engine import AsyncSessionLocal

    acct_id = f"acct-{uuid.uuid4()}"
    ord_id = f"ord-{uuid.uuid4()}"
    authz_id = f"authz-{uuid.uuid4()}"
    token = "test-token-abc"

    key = make_ec_key()
    jwk_json = canonical_jwk(jwk_for_key(key))

    async with AsyncSessionLocal() as db:
        db.add(
            Account(
                id=acct_id,
                public_key=jwk_json,
                status="valid",
                created_at=datetime.now(UTC),
            )
        )
        db.add(
            Order(
                id=ord_id,
                account_id=acct_id,
                status="pending",
                identifiers=json.dumps([{"type": "dns", "value": "svc.internal"}]),
                created_at=datetime.now(UTC),
            )
        )
        db.add(
            Authorization(
                id=authz_id,
                order_id=ord_id,
                identifier="svc.internal",
                status="pending",
                challenge_token=token,
                created_at=datetime.now(UTC),
            )
        )
        await db.commit()

    expected = key_authorization(token, jwk_json)
    yield {"acct_id": acct_id, "ord_id": ord_id, "authz_id": authz_id, "expected": expected}

    # Cleanup.
    from sqlalchemy import delete

    from jackdaw.db.engine import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        await db.execute(delete(Authorization).where(Authorization.id == authz_id))
        await db.execute(delete(Order).where(Order.id == ord_id))
        await db.execute(delete(Account).where(Account.id == acct_id))
        await db.commit()


async def test_run_challenge_success_advances_status(challenge_setup: dict) -> None:
    """On HTTP-01 success, authz→valid and order→ready."""
    from jackdaw import worker
    from jackdaw.db.engine import AsyncSessionLocal

    authz_id = challenge_setup["authz_id"]
    ord_id = challenge_setup["ord_id"]

    with patch("jackdaw.worker.validate_http01", new=AsyncMock(return_value=None)):
        await worker.run_challenge(authz_id=authz_id, order_id=ord_id)

    async with AsyncSessionLocal() as db:
        authz = await db.get(Authorization, authz_id)
        order = await db.get(Order, ord_id)

    assert authz is not None and authz.status == "valid"
    assert order is not None and order.status == "ready"


async def test_run_challenge_failure_sets_invalid(challenge_setup: dict) -> None:
    """On HTTP-01 validation failure, authz→invalid and order→invalid."""
    from jackdaw import worker
    from jackdaw.db.engine import AsyncSessionLocal

    authz_id = challenge_setup["authz_id"]
    ord_id = challenge_setup["ord_id"]

    with patch(
        "jackdaw.worker.validate_http01",
        new=AsyncMock(side_effect=Http01ValidationError("key auth mismatch")),
    ):
        await worker.run_challenge(authz_id=authz_id, order_id=ord_id)

    async with AsyncSessionLocal() as db:
        authz = await db.get(Authorization, authz_id)
        order = await db.get(Order, ord_id)

    assert authz is not None and authz.status == "invalid"
    assert order is not None and order.status == "invalid"


async def test_run_challenge_waits_for_all_authz_before_ready() -> None:
    """An order with two authorizations only becomes ready once both validate.

    Multi-identifier orders are rejected at new-order, but the order-state
    invariant must hold even if such rows exist: validating one authz must not
    prematurely flip the whole order to ``ready``.
    """
    import uuid
    from datetime import UTC, datetime

    from sqlalchemy import delete

    from jackdaw import worker
    from jackdaw._util import canonical_jwk
    from jackdaw.db.engine import AsyncSessionLocal

    acct_id = f"multi-acct-{uuid.uuid4()}"
    ord_id = f"multi-ord-{uuid.uuid4()}"
    authz1 = f"multi-authz1-{uuid.uuid4()}"
    authz2 = f"multi-authz2-{uuid.uuid4()}"

    key = make_ec_key()
    jwk_json = canonical_jwk(jwk_for_key(key))

    async with AsyncSessionLocal() as db:
        db.add(
            Account(id=acct_id, public_key=jwk_json, status="valid", created_at=datetime.now(UTC))
        )
        db.add(
            Order(
                id=ord_id,
                account_id=acct_id,
                status="processing",
                identifiers=json.dumps(
                    [{"type": "dns", "value": "a.test"}, {"type": "dns", "value": "b.test"}]
                ),
                created_at=datetime.now(UTC),
            )
        )
        for aid, ident in ((authz1, "a.test"), (authz2, "b.test")):
            db.add(
                Authorization(
                    id=aid,
                    order_id=ord_id,
                    identifier=ident,
                    status="pending",
                    challenge_token="tok",
                    created_at=datetime.now(UTC),
                )
            )
        await db.commit()

    try:
        with patch("jackdaw.worker.validate_http01", new=AsyncMock(return_value=None)):
            # First authz validated — order must stay out of "ready".
            await worker.run_challenge(authz_id=authz1, order_id=ord_id)
            async with AsyncSessionLocal() as db:
                order = await db.get(Order, ord_id)
                assert order is not None and order.status != "ready"

            # Second authz validated — now all are valid, order becomes ready.
            await worker.run_challenge(authz_id=authz2, order_id=ord_id)
            async with AsyncSessionLocal() as db:
                order = await db.get(Order, ord_id)
                a1 = await db.get(Authorization, authz1)
                a2 = await db.get(Authorization, authz2)
                assert order is not None and order.status == "ready"
                assert a1 is not None and a1.status == "valid"
                assert a2 is not None and a2.status == "valid"
    finally:
        async with AsyncSessionLocal() as db:
            await db.execute(delete(Authorization).where(Authorization.order_id == ord_id))
            await db.execute(delete(Order).where(Order.id == ord_id))
            await db.execute(delete(Account).where(Account.id == acct_id))
            await db.commit()


# ---------------------------------------------------------------------------
# Challenge route — processing state set before task launches
# ---------------------------------------------------------------------------


async def test_challenge_route_returns_processing(
    test_client: Any, db_session: AsyncSession
) -> None:
    """POST /acme/challenge/{id} must return status=processing immediately."""
    from httpx import AsyncClient

    assert isinstance(test_client, AsyncClient)

    from datetime import UTC, datetime

    from jackdaw._util import canonical_jwk
    from jackdaw.db.models import Account, Authorization, Order

    # Set up account+order+authz directly in the test DB.
    key = make_ec_key()
    jwk_json = canonical_jwk(jwk_for_key(key))
    account = Account(
        id="chrt-acct", public_key=jwk_json, status="valid", created_at=datetime.now(UTC)
    )
    order = Order(
        id="chrt-ord",
        account_id="chrt-acct",
        status="pending",
        identifiers=json.dumps([{"type": "dns", "value": "svc.internal"}]),
        created_at=datetime.now(UTC),
    )
    authz = Authorization(
        id="chrt-authz",
        order_id="chrt-ord",
        identifier="svc.internal",
        status="pending",
        challenge_token="chrt-token",
        created_at=datetime.now(UTC),
    )
    db_session.add_all([account, order, authz])
    await db_session.commit()

    challenge_url = "https://jackdaw.test/acme/challenge/chrt-authz"
    nonce = await generate_nonce(db_session)
    body = build_jws(
        payload={},
        url=challenge_url,
        nonce=nonce,
        key=key,
        kid="https://jackdaw.test/acme/account/chrt-acct",
    )

    # Patch the background task so it doesn't make real HTTP calls.
    with patch("jackdaw.worker.validate_http01", new=AsyncMock(return_value=None)):
        resp = await test_client.post("/acme/challenge/chrt-authz", json=body, headers=_CT)

    assert resp.status_code == 200
    assert resp.json()["status"] == "processing"


async def test_authz_route_maps_processing_to_pending(
    test_client: Any, db_session: AsyncSession
) -> None:
    """GET /acme/authz/{id} must never report status=processing on the authorization
    itself (RFC 8555 §7.1.6 only allows it on the nested challenge) — a real ACME
    client (e.g. Caddy/acmez) rejects "processing" as an authorization status."""
    from httpx import AsyncClient

    assert isinstance(test_client, AsyncClient)

    from datetime import UTC, datetime

    from jackdaw._util import canonical_jwk
    from jackdaw.db.models import Account, Authorization, Order

    key = make_ec_key()
    jwk_json = canonical_jwk(jwk_for_key(key))
    account = Account(
        id="authzproc-acct", public_key=jwk_json, status="valid", created_at=datetime.now(UTC)
    )
    order = Order(
        id="authzproc-ord",
        account_id="authzproc-acct",
        status="processing",
        identifiers=json.dumps([{"type": "dns", "value": "svc.internal"}]),
        created_at=datetime.now(UTC),
    )
    authz = Authorization(
        id="authzproc-authz",
        order_id="authzproc-ord",
        identifier="svc.internal",
        status="processing",
        challenge_token="authzproc-token",
        created_at=datetime.now(UTC),
    )
    db_session.add_all([account, order, authz])
    await db_session.commit()

    authz_url = "https://jackdaw.test/acme/authz/authzproc-authz"
    nonce = await generate_nonce(db_session)
    body = build_jws(
        payload=None,
        url=authz_url,
        nonce=nonce,
        key=key,
        kid="https://jackdaw.test/acme/account/authzproc-acct",
    )

    resp = await test_client.post("/acme/authz/authzproc-authz", json=body, headers=_CT)

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "pending"
    assert data["challenges"][0]["status"] == "processing"


# ---------------------------------------------------------------------------
# worker.run_challenge — error paths (authz/order not found, no token, no account)
# ---------------------------------------------------------------------------


async def test_run_challenge_missing_rows_exits_early() -> None:
    """run_challenge must exit without crashing when the authz/order rows don't exist."""
    from jackdaw import worker

    # Passing non-existent IDs — function should return None without raising.
    result = await worker.run_challenge(authz_id="nonexistent-authz", order_id="nonexistent-order")
    assert result is None


async def test_run_challenge_no_challenge_token_sets_invalid() -> None:
    """run_challenge must mark authz+order invalid when challenge_token is None."""
    import uuid
    from datetime import UTC, datetime

    from jackdaw import worker
    from jackdaw.db.engine import AsyncSessionLocal

    acct_id = f"notoken-acct-{uuid.uuid4()}"
    ord_id = f"notoken-ord-{uuid.uuid4()}"
    authz_id = f"notoken-authz-{uuid.uuid4()}"

    async with AsyncSessionLocal() as db:
        db.add(Account(id=acct_id, public_key="{}", status="valid", created_at=datetime.now(UTC)))
        db.add(
            Order(
                id=ord_id,
                account_id=acct_id,
                status="pending",
                identifiers="[]",
                created_at=datetime.now(UTC),
            )
        )
        db.add(
            Authorization(
                id=authz_id,
                order_id=ord_id,
                identifier="x.test",
                status="pending",
                challenge_token=None,  # intentionally missing
                created_at=datetime.now(UTC),
            )
        )
        await db.commit()

    await worker.run_challenge(authz_id=authz_id, order_id=ord_id)

    from sqlalchemy import delete

    async with AsyncSessionLocal() as db:
        authz = await db.get(Authorization, authz_id)
        order = await db.get(Order, ord_id)
        assert authz is not None and authz.status == "invalid"
        assert order is not None and order.status == "invalid"
        await db.execute(delete(Authorization).where(Authorization.id == authz_id))
        await db.execute(delete(Order).where(Order.id == ord_id))
        await db.execute(delete(Account).where(Account.id == acct_id))
        await db.commit()


async def test_run_challenge_account_not_found_sets_invalid() -> None:
    """run_challenge must mark authz+order invalid when the account row is missing."""
    import uuid
    from datetime import UTC, datetime

    from jackdaw import worker
    from jackdaw.db.engine import AsyncSessionLocal

    ord_id = f"noacct-ord-{uuid.uuid4()}"
    authz_id = f"noacct-authz-{uuid.uuid4()}"

    # Insert order with a non-existent account_id (no Account row).
    async with AsyncSessionLocal() as db:
        db.add(
            Order(
                id=ord_id,
                account_id="nonexistent-account",
                status="pending",
                identifiers="[]",
                created_at=datetime.now(UTC),
            )
        )
        db.add(
            Authorization(
                id=authz_id,
                order_id=ord_id,
                identifier="x.test",
                status="pending",
                challenge_token="tok",
                created_at=datetime.now(UTC),
            )
        )
        await db.commit()

    await worker.run_challenge(authz_id=authz_id, order_id=ord_id)

    from sqlalchemy import delete

    async with AsyncSessionLocal() as db:
        authz = await db.get(Authorization, authz_id)
        order = await db.get(Order, ord_id)
        assert authz is not None and authz.status == "invalid"
        assert order is not None and order.status == "invalid"
        await db.execute(delete(Authorization).where(Authorization.id == authz_id))
        await db.execute(delete(Order).where(Order.id == ord_id))
        await db.commit()


# ---------------------------------------------------------------------------
# worker.process_finalize — error paths
# ---------------------------------------------------------------------------


async def test_process_finalize_order_not_found_exits_early() -> None:
    """process_finalize must exit silently when the order row doesn't exist."""
    from unittest.mock import MagicMock

    from jackdaw import worker

    result = await worker.process_finalize(
        order_id="nonexistent-order",
        domain="x.test",
        csr_der=b"fake",
        acme_client=MagicMock(),
    )
    assert result is None


async def test_process_finalize_le_failure_sets_invalid() -> None:
    """process_finalize must mark the order invalid when LE cert issuance fails."""
    import uuid
    from datetime import UTC, datetime
    from unittest.mock import MagicMock, patch

    from jackdaw import worker
    from jackdaw.db.engine import AsyncSessionLocal

    acct_id = f"pf-acct-{uuid.uuid4()}"
    ord_id = f"pf-ord-{uuid.uuid4()}"

    async with AsyncSessionLocal() as db:
        db.add(Account(id=acct_id, public_key="{}", status="valid", created_at=datetime.now(UTC)))
        db.add(
            Order(
                id=ord_id,
                account_id=acct_id,
                status="ready",
                identifiers='[{"type":"dns","value":"x.test"}]',
                created_at=datetime.now(UTC),
            )
        )
        await db.commit()

    with patch(
        "jackdaw.worker.le.order_cert",
        new=AsyncMock(side_effect=RuntimeError("LE down")),
    ):
        await worker.process_finalize(
            order_id=ord_id,
            domain="x.test",
            csr_der=b"fake",
            acme_client=MagicMock(),
        )

    from sqlalchemy import delete

    async with AsyncSessionLocal() as db:
        order = await db.get(Order, ord_id)
        assert order is not None and order.status == "invalid"
        await db.execute(delete(Order).where(Order.id == ord_id))
        await db.execute(delete(Account).where(Account.id == acct_id))
        await db.commit()


# ---------------------------------------------------------------------------
# _is_blocked — unparsable IP address (lines 68-69)
# ---------------------------------------------------------------------------


def test_is_blocked_unparsable_address_returns_true() -> None:
    """_is_blocked must return True for strings that are not valid IP addresses."""
    assert _is_blocked("not-an-ip-address") is True


# ---------------------------------------------------------------------------
# _resolve_and_check — empty DNS results (line 88)
# ---------------------------------------------------------------------------


def test_resolve_and_check_empty_results_raises() -> None:
    """_resolve_and_check must raise Http01ValidationError when getaddrinfo returns []."""
    with patch("jackdaw.services.http01.socket.getaddrinfo") as mock_gai:
        mock_gai.return_value = []
        with pytest.raises(Http01ValidationError, match="No DNS records"):
            _resolve_and_check("empty.test")


# ---------------------------------------------------------------------------
# _resolve_and_check — multiple IPs (branch 95->91)
# ---------------------------------------------------------------------------


def test_resolve_and_check_multiple_ips_returns_first() -> None:
    """With multiple non-blocked records, the first IP is selected (exercises 95->91 branch)."""
    with patch("jackdaw.services.http01.socket.getaddrinfo") as mock_gai:
        mock_gai.return_value = [
            (2, 1, 6, "", ("192.168.1.10", 0)),
            (2, 1, 6, "", ("192.168.1.11", 0)),
        ]
        ip = _resolve_and_check("multi.internal")
    assert ip == "192.168.1.10"


def test_resolve_and_check_prefers_ipv4_over_ipv6() -> None:
    """When both families resolve, the IPv4 address is preferred even if IPv6 is first."""
    import socket

    with patch("jackdaw.services.http01.socket.getaddrinfo") as mock_gai:
        mock_gai.return_value = [
            (socket.AF_INET6, 1, 6, "", ("2001:db8::1", 0, 0, 0)),
            (socket.AF_INET, 1, 6, "", ("192.168.1.10", 0)),
        ]
        ip = _resolve_and_check("dual.internal")
    assert ip == "192.168.1.10"


def test_resolve_and_check_ipv6_only_returns_ipv6() -> None:
    """With no IPv4 record available, the IPv6 address is returned."""
    import socket

    with patch("jackdaw.services.http01.socket.getaddrinfo") as mock_gai:
        mock_gai.return_value = [
            (socket.AF_INET6, 1, 6, "", ("2001:db8::1", 0, 0, 0)),
        ]
        ip = _resolve_and_check("v6.internal")
    assert ip == "2001:db8::1"


def test_resolve_and_check_blocked_ipv6_still_rejected_when_ipv4_present() -> None:
    """Every resolved address is SSRF-checked; a blocked IPv6 fails the whole lookup
    even when a safe IPv4 is also present (DNS-rebinding defense)."""
    import socket

    with patch("jackdaw.services.http01.socket.getaddrinfo") as mock_gai:
        mock_gai.return_value = [
            (socket.AF_INET, 1, 6, "", ("192.168.1.10", 0)),
            (socket.AF_INET6, 1, 6, "", ("::1", 0, 0, 0)),  # loopback — blocked
        ]
        with pytest.raises(Http01ValidationError, match="blocked"):
            _resolve_and_check("mixed.internal")


# ---------------------------------------------------------------------------
# _attempt_validation — production path without client_factory (lines 196-214)
# ---------------------------------------------------------------------------


async def test_attempt_validation_known_dns_error_propagates() -> None:
    """Http01ValidationError raised by DNS resolution must propagate unchanged (line 199)."""
    with patch(
        "jackdaw.services.http01.asyncio.to_thread",
        new=AsyncMock(side_effect=Http01ValidationError("blocked address")),
    ):
        with pytest.raises(Http01ValidationError, match="blocked address"):
            await _attempt_validation(
                "blocked.test", 80, "/.well-known/acme-challenge/tok", "expected", 5, None
            )


async def test_attempt_validation_unexpected_dns_exception_wraps() -> None:
    """An unexpected (non-Http01ValidationError) exception from asyncio.to_thread is wrapped."""
    with patch(
        "jackdaw.services.http01.asyncio.to_thread",
        new=AsyncMock(side_effect=RuntimeError("system error")),
    ):
        with pytest.raises(Http01ValidationError, match="Unexpected error"):
            await _attempt_validation(
                "example.com", 80, "/.well-known/acme-challenge/tok", "expected", 5, None
            )


async def test_attempt_validation_production_ipv4_path() -> None:
    """Production path (no client_factory): resolves IPv4, creates client, calls fetch."""
    with patch(
        "jackdaw.services.http01.asyncio.to_thread",
        new=AsyncMock(return_value="192.168.1.1"),
    ):
        with patch(
            "jackdaw.services.http01._fetch_and_compare",
            new=AsyncMock(return_value=None),
        ) as mock_fetch:
            await _attempt_validation(
                "service.internal", 80, "/.well-known/acme-challenge/tok", "expected", 5, None
            )
    mock_fetch.assert_awaited_once()


async def test_attempt_validation_production_ipv6_path() -> None:
    """IPv6 resolved IP must be wrapped in brackets in the target URL."""
    with patch(
        "jackdaw.services.http01.asyncio.to_thread",
        new=AsyncMock(return_value="2001:db8::1"),
    ):
        with patch(
            "jackdaw.services.http01._fetch_and_compare",
            new=AsyncMock(return_value=None),
        ) as mock_fetch:
            await _attempt_validation(
                "ipv6.example.com", 80, "/.well-known/acme-challenge/tok", "expected", 5, None
            )
    target_url = mock_fetch.call_args[0][1]
    assert "[2001:db8::1]" in target_url


async def test_attempt_validation_nondefault_port_in_target() -> None:
    """A non-default CHALLENGE_HTTP_PORT must be part of the connection target URL.

    Regression: previously the port only reached the Host header, so the actual
    connection always went to :80 and any non-default port silently failed.
    """
    with patch(
        "jackdaw.services.http01.asyncio.to_thread",
        new=AsyncMock(return_value="192.168.1.1"),
    ):
        with patch(
            "jackdaw.services.http01._fetch_and_compare",
            new=AsyncMock(return_value=None),
        ) as mock_fetch:
            await _attempt_validation(
                "service.internal", 8080, "/.well-known/acme-challenge/tok", "expected", 5, None
            )
    target_url = mock_fetch.call_args[0][1]
    assert target_url == "http://192.168.1.1:8080/.well-known/acme-challenge/tok"


async def test_attempt_validation_nondefault_port_ipv6_target() -> None:
    """Non-default port must sit after the bracketed IPv6 literal in the target URL."""
    with patch(
        "jackdaw.services.http01.asyncio.to_thread",
        new=AsyncMock(return_value="2001:db8::1"),
    ):
        with patch(
            "jackdaw.services.http01._fetch_and_compare",
            new=AsyncMock(return_value=None),
        ) as mock_fetch:
            await _attempt_validation(
                "ipv6.internal", 8080, "/.well-known/acme-challenge/tok", "expected", 5, None
            )
    target_url = mock_fetch.call_args[0][1]
    assert target_url == "http://[2001:db8::1]:8080/.well-known/acme-challenge/tok"


async def test_attempt_validation_default_port_omitted_from_target() -> None:
    """Port 80 must stay implicit in the target URL (no ':80' suffix)."""
    with patch(
        "jackdaw.services.http01.asyncio.to_thread",
        new=AsyncMock(return_value="192.168.1.1"),
    ):
        with patch(
            "jackdaw.services.http01._fetch_and_compare",
            new=AsyncMock(return_value=None),
        ) as mock_fetch:
            await _attempt_validation(
                "service.internal", 80, "/.well-known/acme-challenge/tok", "expected", 5, None
            )
    target_url = mock_fetch.call_args[0][1]
    assert target_url == "http://192.168.1.1/.well-known/acme-challenge/tok"


# ---------------------------------------------------------------------------
# _fetch_and_compare — httpx.RequestError (lines 231-232)
# ---------------------------------------------------------------------------


async def test_fetch_and_compare_request_error_raises() -> None:
    """httpx.RequestError (not a timeout) must be wrapped as Http01ValidationError."""
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get = AsyncMock(side_effect=httpx.ConnectError("connection refused"))

    with pytest.raises(Http01ValidationError, match="request failed"):
        await _fetch_and_compare(
            mock_client,
            "http://192.168.1.1/.well-known/acme-challenge/tok",
            "example.com",
            "expected",
            5,
        )


# ---------------------------------------------------------------------------
# worker.process_finalize — success
# ---------------------------------------------------------------------------


def _make_self_signed_pem(not_after: Any) -> str:
    """Build a self-signed leaf certificate PEM with a specific notAfter."""
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    key = generate_private_key(SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x.test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.PEM).decode()


def test_cert_expiry_from_pem_parses_real_notafter() -> None:
    """_cert_expiry_from_pem returns the leaf's notAfter as naive UTC."""
    from datetime import UTC, datetime, timedelta

    from jackdaw.worker import _cert_expiry_from_pem

    not_after = (datetime.now(UTC) + timedelta(days=90)).replace(microsecond=0)
    result = _cert_expiry_from_pem(_make_self_signed_pem(not_after))
    assert result.tzinfo is None
    assert result == not_after.replace(tzinfo=None)


def test_cert_expiry_from_pem_falls_back_on_garbage() -> None:
    """An unparseable chain falls back to a ~89-day naive-UTC estimate."""
    from datetime import UTC, datetime, timedelta

    from jackdaw.worker import _cert_expiry_from_pem

    result = _cert_expiry_from_pem("not a certificate")
    assert result.tzinfo is None
    expected = datetime.now(UTC).replace(tzinfo=None) + timedelta(days=89)
    assert abs((result - expected).total_seconds()) < 60


async def test_process_finalize_stores_real_cert_expiry() -> None:
    """process_finalize must persist the leaf certificate's actual notAfter."""
    import uuid
    from datetime import UTC, datetime, timedelta
    from unittest.mock import MagicMock, patch

    from sqlalchemy import delete

    from jackdaw import worker
    from jackdaw.db.engine import AsyncSessionLocal
    from jackdaw.db.models import Certificate

    acct_id = f"pf-exp-acct-{uuid.uuid4()}"
    ord_id = f"pf-exp-ord-{uuid.uuid4()}"
    not_after = (datetime.now(UTC) + timedelta(days=90)).replace(microsecond=0)
    pem = _make_self_signed_pem(not_after)

    async with AsyncSessionLocal() as db:
        db.add(Account(id=acct_id, public_key="{}", status="valid", created_at=datetime.now(UTC)))
        db.add(
            Order(
                id=ord_id,
                account_id=acct_id,
                status="ready",
                identifiers='[{"type":"dns","value":"x.test"}]',
                created_at=datetime.now(UTC),
            )
        )
        await db.commit()

    try:
        with patch("jackdaw.worker.le.order_cert", new=AsyncMock(return_value=pem)):
            await worker.process_finalize(
                order_id=ord_id, domain="x.test", csr_der=b"fake", acme_client=MagicMock()
            )
        async with AsyncSessionLocal() as db:
            order = await db.get(Order, ord_id)
            assert order is not None and order.cert_id is not None
            cert = await db.get(Certificate, order.cert_id)
            assert cert is not None
            assert cert.expires_at == not_after.replace(tzinfo=None)
    finally:
        async with AsyncSessionLocal() as db:
            await db.execute(delete(Certificate).where(Certificate.order_id == ord_id))
            await db.execute(delete(Order).where(Order.id == ord_id))
            await db.execute(delete(Account).where(Account.id == acct_id))
            await db.commit()


async def test_process_finalize_success_stores_cert() -> None:
    """process_finalize must store the cert and mark order valid on success."""
    import uuid
    from datetime import UTC, datetime
    from unittest.mock import MagicMock, patch

    from jackdaw import worker
    from jackdaw.db.engine import AsyncSessionLocal

    acct_id = f"pf-ok-acct-{uuid.uuid4()}"
    ord_id = f"pf-ok-ord-{uuid.uuid4()}"
    fake_pem = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"

    async with AsyncSessionLocal() as db:
        db.add(Account(id=acct_id, public_key="{}", status="valid", created_at=datetime.now(UTC)))
        db.add(
            Order(
                id=ord_id,
                account_id=acct_id,
                status="ready",
                identifiers='[{"type":"dns","value":"x.test"}]',
                created_at=datetime.now(UTC),
            )
        )
        await db.commit()

    with patch("jackdaw.worker.le.order_cert", new=AsyncMock(return_value=fake_pem)):
        await worker.process_finalize(
            order_id=ord_id,
            domain="x.test",
            csr_der=b"fake",
            acme_client=MagicMock(),
        )

    from sqlalchemy import delete

    async with AsyncSessionLocal() as db:
        order = await db.get(Order, ord_id)
        assert order is not None and order.status == "valid"
        assert order.cert_id is not None
        await db.execute(delete(Order).where(Order.id == ord_id))
        await db.execute(delete(Account).where(Account.id == acct_id))
        await db.commit()
