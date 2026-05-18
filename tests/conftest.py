"""Shared pytest fixtures: in-memory database, test client, and JWS helpers.

Environment variables that jackdaw reads at import time must be set before
any jackdaw module is imported.  This conftest sets sensible test defaults
via ``os.environ`` at the very top.
"""

from __future__ import annotations

import base64
import json
import os
from collections.abc import AsyncGenerator
from typing import Any

# ---------------------------------------------------------------------------
# Set required env vars before any jackdaw import so that get_settings() and
# the module-level create_async_engine() see the test values.
# ---------------------------------------------------------------------------
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("DNS_PROVIDER", "porkbun")
os.environ.setdefault("RELAY_DOMAIN", "jackdaw.test")
os.environ.setdefault("ACME_EMAIL", "test@example.com")
os.environ.setdefault("PORKBUN_API_KEY", "pk1_test")
os.environ.setdefault("PORKBUN_SECRET_API_KEY", "sk1_test")

import pytest_asyncio  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ec import (  # noqa: E402
    ECDSA,
    SECP256R1,
    EllipticCurvePrivateKey,
    generate_private_key,
)
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from jackdaw.db.engine import get_db  # noqa: E402
from jackdaw.db.models import Base  # noqa: E402
from jackdaw.main import app  # noqa: E402

# ---------------------------------------------------------------------------
# Module-level DB bootstrap (needed by the Replay-Nonce middleware in tests)
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(autouse=True)
async def _init_module_db() -> None:
    """Ensure the module-level engine has tables before each test.

    The ACME header middleware writes nonces via ``AsyncSessionLocal()``
    (not via the ``get_db`` dependency override).  With StaticPool, all
    sessions on the module-level engine share one connection; calling
    ``init_db()`` is idempotent (SQLite CREATE TABLE IF NOT EXISTS) and
    fast, so running it per test is safe.
    """
    from jackdaw.db.engine import init_db

    await init_db()


# ---------------------------------------------------------------------------
# Database fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture()
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Provide a fresh in-memory SQLite session per test (tables recreated).

    Each test gets its own engine and database so there is no inter-test state.
    StaticPool ensures all sessions on this engine share one connection
    (and therefore one in-memory database).
    """
    from sqlalchemy.pool import StaticPool

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
        engine, expire_on_commit=False
    )
    async with session_factory() as session:
        yield session

    await engine.dispose()


# ---------------------------------------------------------------------------
# HTTP test client
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture()
async def test_client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Return an httpx AsyncClient backed by the FastAPI app with an in-memory DB.

    The application lifespan is *not* run, avoiding DNS/LE side-effects.
    Tests that need ``app.state`` values should set them directly before
    making requests.

    The ``get_db`` dependency is overridden to inject *db_session* so that
    route handlers and the test share a single consistent database view.
    Note: the ``_AcmeHeaderMiddleware`` generates nonces via a separate
    ``AsyncSessionLocal``; those nonce rows will land in the module-level
    engine (which also points to ``sqlite+aiosqlite:///:memory:`` via the
    env var set above), not in *db_session*.  Tests should not rely on
    middleware-generated nonces being visible in *db_session*.
    """

    async def _override_db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    app.dependency_overrides[get_db] = _override_db  # type: ignore[assignment]

    async with AsyncClient(
        transport=ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="https://jackdaw.test",
    ) as client:
        yield client

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Cryptographic helpers (used by multiple test modules)
# ---------------------------------------------------------------------------


def _b64url(data: bytes) -> str:
    """Encode *data* as URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_ec_key() -> EllipticCurvePrivateKey:
    """Generate a fresh P-256 private key for use in tests."""
    return generate_private_key(SECP256R1())


def jwk_for_key(key: EllipticCurvePrivateKey) -> dict[str, Any]:
    """Return a minimal ES256 public JWK dict for *key*.

    Uses the X9.62 uncompressed-point encoding to extract raw x / y values.
    """
    pub = key.public_key()
    # 65 bytes: 0x04 || x (32 bytes) || y (32 bytes)
    raw = pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(raw[1:33]),
        "y": _b64url(raw[33:65]),
    }


def build_jws(
    *,
    payload: dict[str, Any] | str | None,
    url: str,
    nonce: str,
    key: EllipticCurvePrivateKey,
    jwk: dict[str, Any] | None = None,
    kid: str | None = None,
) -> dict[str, Any]:
    """Build a flat-JSON JWS suitable for POSTing to an ACME endpoint.

    Exactly one of *jwk* or *kid* must be provided (``None`` for the other).
    Pass ``payload=None`` or ``payload=""`` for an empty challenge-ack body.

    Args:
        payload: Request payload as a dict (JSON-serialised) or a pre-encoded
                 string.  ``None`` / ``""`` → empty base64url field.
        url:     Full request URL placed in the protected header.
        nonce:   A previously issued nonce value.
        key:     EC P-256 private key used to sign the input.
        jwk:     Public JWK dict — required for ``newAccount`` (no kid yet).
        kid:     Account URL string — required for all other signed requests.

    Returns:
        Dict with ``protected``, ``payload``, ``signature`` keys.
    """
    if jwk is None and kid is None:
        raise ValueError("build_jws: supply exactly one of 'jwk' or 'kid'")

    protected_obj: dict[str, Any] = {"alg": "ES256", "nonce": nonce, "url": url}
    if jwk is not None:
        protected_obj["jwk"] = jwk
    else:
        protected_obj["kid"] = kid

    protected_b64 = _b64url(json.dumps(protected_obj).encode())

    if not payload:
        payload_b64 = ""
    elif isinstance(payload, dict):
        payload_b64 = _b64url(json.dumps(payload).encode())
    else:
        payload_b64 = _b64url(payload.encode())

    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")

    # ES256: DER-encoded ECDSA signature → fixed-length R ∥ S (32 bytes each).
    der_sig = key.sign(signing_input, ECDSA(hashes.SHA256()))
    r_int, s_int = decode_dss_signature(der_sig)
    sig_bytes = r_int.to_bytes(32, "big") + s_int.to_bytes(32, "big")

    return {
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": _b64url(sig_bytes),
    }
