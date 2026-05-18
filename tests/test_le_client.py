"""Unit tests for le_client pure helper functions and DNS failure paths."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

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
