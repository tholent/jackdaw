"""Unit tests for le_client pure helper functions and DNS failure paths."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import (
    CertificateSigningRequestBuilder,
    DNSName,
    Name,
    NameAttribute,
    SubjectAlternativeName,
)
from cryptography.x509.oid import NameOID

from jackdaw.services.le_client import (
    JackdawAcmeClient,
    _apex_domain,
    _der_to_pem_csr,
    _dns01_txt_value,
    _is_order_already_finalized,
    _load_or_create_account_key,
)

# ---------------------------------------------------------------------------
# _apex_domain
# ---------------------------------------------------------------------------


def test_apex_domain_two_labels() -> None:
    assert _apex_domain("example.com") == "example.com"


def test_apex_domain_subdomain() -> None:
    assert _apex_domain("sub.example.com") == "example.com"


def test_apex_domain_deep_subdomain() -> None:
    assert _apex_domain("a.b.c.example.com") == "example.com"


def test_apex_domain_trailing_dot_stripped() -> None:
    assert _apex_domain("sub.example.com.") == "example.com"


def test_apex_domain_override_multi_label_tld() -> None:
    # Without the override, the naive heuristic would wrongly return "co.uk".
    assert _apex_domain("a.example.co.uk", ["example.co.uk"]) == "example.co.uk"


def test_apex_domain_override_exact_match() -> None:
    assert _apex_domain("example.co.uk", ["example.co.uk"]) == "example.co.uk"


def test_apex_domain_override_longest_zone_wins() -> None:
    assert _apex_domain("x.a.example.co.uk", ["co.uk", "example.co.uk"]) == "example.co.uk"


def test_apex_domain_non_matching_override_falls_back() -> None:
    assert _apex_domain("sub.example.com", ["other.co.uk"]) == "example.com"


# ---------------------------------------------------------------------------
# _dns01_txt_value — RFC 8555 §8.4
# ---------------------------------------------------------------------------


def test_dns01_txt_value_matches_spec() -> None:
    """Verify against the manually computed digest for a known input."""
    key_auth = b"token.thumbprint"
    digest = hashlib.sha256(key_auth).digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    assert _dns01_txt_value(key_auth) == expected


def test_dns01_txt_value_no_padding() -> None:
    """Result must never contain '=' padding characters."""
    result = _dns01_txt_value(b"anything")
    assert "=" not in result


# ---------------------------------------------------------------------------
# _der_to_pem_csr
# ---------------------------------------------------------------------------


def _make_csr_der() -> bytes:
    key = generate_private_key(SECP256R1())
    csr = (
        CertificateSigningRequestBuilder()
        .subject_name(Name([NameAttribute(NameOID.COMMON_NAME, "test.example.com")]))
        .add_extension(SubjectAlternativeName([DNSName("test.example.com")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(Encoding.DER)


def test_der_to_pem_csr_produces_pem_header() -> None:
    der = _make_csr_der()
    pem = _der_to_pem_csr(der)
    assert pem.startswith(b"-----BEGIN CERTIFICATE REQUEST-----")


def test_der_to_pem_csr_round_trips() -> None:
    """DER → PEM should be parseable back as a CSR."""
    from cryptography.x509 import load_pem_x509_csr

    der = _make_csr_der()
    pem = _der_to_pem_csr(der)
    csr = load_pem_x509_csr(pem)
    assert csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "test.example.com"


# ---------------------------------------------------------------------------
# _load_or_create_account_key
# ---------------------------------------------------------------------------


def test_load_or_create_creates_key_file(tmp_path: Path) -> None:
    key_path = tmp_path / "account.key"
    assert not key_path.exists()
    jwk = _load_or_create_account_key(key_path)
    assert key_path.exists()
    assert oct(key_path.stat().st_mode)[-3:] == "600"
    assert jwk is not None


def test_load_or_create_loads_existing_key(tmp_path: Path) -> None:
    key_path = tmp_path / "account.key"
    jwk1 = _load_or_create_account_key(key_path)
    jwk2 = _load_or_create_account_key(key_path)
    # Both calls should return a key with the same public component.
    assert jwk1.public_key().key == jwk2.public_key().key


# ---------------------------------------------------------------------------
# JackdawAcmeClient.fulfill_dns_01 — DNS failure path
# ---------------------------------------------------------------------------


async def test_fulfill_dns_01_returns_false_on_dns_error(tmp_path: Path) -> None:
    """fulfill_dns_01 must return False when the DNS provider raises."""
    from josepy.jwa import ES256

    key_path = tmp_path / "account.key"
    acme_key = _load_or_create_account_key(key_path)

    failing_dns = MagicMock()
    failing_dns.set_txt = AsyncMock(side_effect=RuntimeError("DNS API unavailable"))

    client = JackdawAcmeClient(
        "https://acme-staging-v02.api.letsencrypt.org/directory",
        dns_provider=failing_dns,
        propagation_wait=0,
        verify_ssl=False,
        key=acme_key,
        alg=ES256,
    )

    # Provide a minimal mock challenge with the fields fulfill_dns_01 uses.
    mock_challenge = MagicMock()
    client.get_key_authorization = MagicMock(return_value=b"token.thumbprint")  # type: ignore[method-assign]

    result = await client.fulfill_dns_01("sub.example.com", mock_challenge)

    assert result is False
    failing_dns.set_txt.assert_awaited_once()


# ---------------------------------------------------------------------------
# JackdawAcmeClient.new_order — per-order URL capture (concurrency safety)
# ---------------------------------------------------------------------------


async def test_new_order_keys_order_url_per_finalize(tmp_path: Path) -> None:
    """Each order's URL is stored under its own finalize key so concurrent
    orders on the shared client never clobber each other's order URL."""
    import json as _json

    from josepy.jwa import ES256

    key_path = tmp_path / "account.key"
    acme_key = _load_or_create_account_key(key_path)

    client = JackdawAcmeClient(
        "https://acme-staging-v02.api.letsencrypt.org/directory",
        dns_provider=MagicMock(),
        propagation_wait=0,
        verify_ssl=False,
        key=acme_key,
        alg=ES256,
    )
    client._check_bound = MagicMock()  # type: ignore[method-assign]
    directory = MagicMock()
    directory.new_order = "https://ca/new-order"
    client._get_directory = AsyncMock(return_value=directory)  # type: ignore[method-assign]
    client._domain_to_identifiers = MagicMock(  # type: ignore[method-assign]
        side_effect=lambda d: [{"type": "dns", "value": d}]
    )

    def _resp(order_url: str, finalize: str, authz_url: str) -> MagicMock:
        resp = MagicMock()
        resp.headers = {"Location": order_url.encode()}
        resp.content = _json.dumps({"authorizations": [authz_url], "finalize": finalize}).encode()
        return resp

    client._post = AsyncMock(  # type: ignore[method-assign]
        side_effect=[
            _resp("https://ca/order/1", "https://ca/order/1/finalize", "https://ca/authz/1"),
            _resp("https://ca/order/2", "https://ca/order/2/finalize", "https://ca/authz/2"),
        ]
    )

    order1 = await client.new_order("a.example.com")
    order2 = await client.new_order("b.example.com")

    assert order1.finalize != order2.finalize
    assert client._order_urls[order1.finalize] == "https://ca/order/1"
    assert client._order_urls[order2.finalize] == "https://ca/order/2"


# ---------------------------------------------------------------------------
# _is_order_already_finalized
# ---------------------------------------------------------------------------


def test_is_order_already_finalized_matches_order_not_ready() -> None:
    from gufo.acme.error import AcmeError

    exc = AcmeError(
        '[403] urn:ietf:params:acme:error:orderNotReady Order\'s status ("valid") '
        "is not acceptable for finalization"
    )
    assert _is_order_already_finalized(exc) is True


def test_is_order_already_finalized_ignores_other_errors() -> None:
    from gufo.acme.error import AcmeError

    exc = AcmeError("[429] urn:ietf:params:acme:error:rateLimited too many requests")
    assert _is_order_already_finalized(exc) is False


# ---------------------------------------------------------------------------
# JackdawAcmeClient.finalize_and_wait — idempotent recovery of a finalized order
# ---------------------------------------------------------------------------


def _finalize_client(tmp_path: Path) -> JackdawAcmeClient:
    from josepy.jwa import ES256

    acme_key = _load_or_create_account_key(tmp_path / "account.key")
    client = JackdawAcmeClient(
        "https://acme-staging-v02.api.letsencrypt.org/directory",
        dns_provider=MagicMock(),
        propagation_wait=0,
        verify_ssl=False,
        key=acme_key,
        alg=ES256,
    )
    # sign()'s CSR handling is not under test here; the finalize POST is mocked.
    client._pem_to_der = MagicMock(return_value=b"der")  # type: ignore[method-assign]
    return client


async def test_finalize_recovers_when_order_already_finalized(tmp_path: Path) -> None:
    """A finalize rejected with orderNotReady (the order is already valid)
    recovers the issued certificate by polling instead of failing."""
    import json as _json

    from gufo.acme.clients.base import AcmeOrder
    from gufo.acme.error import AcmeError

    client = _finalize_client(tmp_path)
    finalize_url = "https://ca/order/1/finalize"
    client._order_urls[finalize_url] = "https://ca/order/1"

    valid_resp = MagicMock()
    valid_resp.content = _json.dumps(
        {"status": "valid", "certificate": "https://ca/cert/1"}
    ).encode()
    cert_resp = MagicMock()
    cert_resp.content = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"

    client._post = AsyncMock(  # type: ignore[method-assign]
        side_effect=[
            AcmeError(
                '[403] urn:ietf:params:acme:error:orderNotReady Order\'s status ("valid") '
                "is not acceptable for finalization"
            ),
            valid_resp,  # poll → valid
            cert_resp,  # download certificate
        ]
    )

    order = AcmeOrder(authorizations=[], finalize=finalize_url)
    with patch("jackdaw.services.le_client.asyncio.sleep", new=AsyncMock()):
        result = await client.finalize_and_wait(order, csr=b"pem")

    assert result == cert_resp.content
    # The order URL is popped so the shared map never grows.
    assert finalize_url not in client._order_urls


async def test_finalize_reraises_order_not_ready_without_order_url(tmp_path: Path) -> None:
    """Without a captured order URL there is nothing to recover, so the
    orderNotReady error propagates."""
    from gufo.acme.clients.base import AcmeOrder
    from gufo.acme.error import AcmeError

    client = _finalize_client(tmp_path)
    client._post = AsyncMock(  # type: ignore[method-assign]
        side_effect=AcmeError("[403] urn:ietf:params:acme:error:orderNotReady not ready")
    )

    order = AcmeOrder(authorizations=[], finalize="https://ca/order/1/finalize")
    with pytest.raises(AcmeError):
        await client.finalize_and_wait(order, csr=b"pem")


async def test_finalize_reraises_non_order_not_ready_errors(tmp_path: Path) -> None:
    """A different finalize failure (e.g. rate limiting) is never swallowed,
    even when an order URL is available to poll."""
    from gufo.acme.clients.base import AcmeOrder
    from gufo.acme.error import AcmeError

    client = _finalize_client(tmp_path)
    finalize_url = "https://ca/order/1/finalize"
    client._order_urls[finalize_url] = "https://ca/order/1"
    client._post = AsyncMock(  # type: ignore[method-assign]
        side_effect=AcmeError("[429] urn:ietf:params:acme:error:rateLimited slow down")
    )

    order = AcmeOrder(authorizations=[], finalize=finalize_url)
    with pytest.raises(AcmeError):
        await client.finalize_and_wait(order, csr=b"pem")


# ---------------------------------------------------------------------------
# JackdawAcmeClient.domain_lock — per-domain issuance serialization
# ---------------------------------------------------------------------------


def test_domain_lock_is_stable_per_domain(tmp_path: Path) -> None:
    client = _finalize_client(tmp_path)
    lock_a = client.domain_lock("a.example.com")
    lock_a2 = client.domain_lock("a.example.com")
    lock_b = client.domain_lock("b.example.com")
    assert lock_a is lock_a2
    assert lock_a is not lock_b
