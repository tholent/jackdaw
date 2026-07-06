"""Let's Encrypt ACME client built on gufo-acme.

Jackdaw maintains a single shared LE account whose keypair lives on the
data volume.  This module:

- Subclasses ``AcmeClient`` to fulfil DNS-01 challenges via a ``DNSProvider``.
- Loads (or creates) the account key on disk.
- Registers the account with LE on first run.
- Exposes ``order_cert()`` which submits a client-supplied CSR and returns
  the PEM certificate chain.

The ``JackdawAcmeClient`` constructor accepts ``dns_provider`` and
``propagation_wait`` in addition to all standard ``AcmeClient`` kwargs.
"""

import asyncio
import base64
import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from cryptography.x509 import load_der_x509_csr
from gufo.acme.clients.base import (  # type: ignore[attr-defined]
    AcmeAuthorizationStatus,
    AcmeClient,
    AcmeOrder,
)
from gufo.acme.error import (
    AcmeCertificateError,
    AcmeConnectError,
    AcmeError,
    AcmeFulfillmentFailed,
    AcmeRateLimitError,
    AcmeTimeoutError,
    AcmeUnauthorizedError,
)
from gufo.acme.types import AcmeAuthorization, AcmeChallenge
from gufo.http.async_client import HttpClient
from josepy.json_util import encode_b64jose
from josepy.jwa import ES256
from josepy.jwk import JWKEC

from jackdaw.config import get_settings
from jackdaw.dns.base import DNSProvider

log = logging.getLogger(__name__)

# Bound the finalize polling loop so a stuck/never-valid order cannot loop
# forever holding a task reference and an open connection to the CA.
_FINALIZE_POLL_INTERVAL = 2.0  # seconds between order-status polls
_FINALIZE_POLL_ATTEMPTS = 60  # ~2 minutes total before giving up


def _apex_domain(domain: str, overrides: list[str] | None = None) -> str:
    """Return the apex (registrable) domain of *domain*.

    If *overrides* contains a zone that *domain* falls under, the longest such
    zone is returned — this is the escape hatch for multi-label public suffixes
    (e.g. configuring ``example.co.uk`` so ``a.example.co.uk`` resolves
    correctly instead of the wrong ``co.uk``).

    Otherwise falls back to the last two labels, which is correct for the common
    case (``sub.example.com`` → ``example.com``).
    """
    d = domain.rstrip(".")
    if overrides:
        matches = [z for z in overrides if d == z or d.endswith(f".{z}")]
        if matches:
            return max(matches, key=len)
    return ".".join(d.split(".")[-2:])


def _dns01_txt_value(key_authorization: bytes) -> str:
    """Compute the DNS TXT record value for a DNS-01 challenge.

    Per RFC 8555 §8.4: ``base64url(SHA-256(keyAuthorization))``.
    """
    digest = hashlib.sha256(key_authorization).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _der_to_pem_csr(csr_der: bytes) -> bytes:
    """Convert a DER-encoded CSR to PEM format for gufo-acme."""
    csr = load_der_x509_csr(csr_der)
    return csr.public_bytes(Encoding.PEM)


class JackdawAcmeClient(AcmeClient):
    """gufo-acme client that fulfils DNS-01 challenges via a ``DNSProvider``.

    Override ``fulfill_dns_01`` (and the cleanup hook ``clear_dns_01``) to
    delegate record management to the configured provider.  A configurable
    propagation delay is inserted after setting the record so that public
    resolvers have time to reflect the change before LE queries them.
    """

    def __init__(
        self,
        directory_url: str,
        *,
        dns_provider: DNSProvider,
        propagation_wait: int,
        verify_ssl: bool = True,
        zone_overrides: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(directory_url, **kwargs)
        self._dns = dns_provider
        self._propagation_wait = propagation_wait
        self._verify_ssl = verify_ssl
        self._zone_overrides = zone_overrides or []
        # Map of finalize-URL → order-URL captured in new_order().  Keyed per
        # order (finalize URLs are unique) so concurrent orders on this shared
        # client instance never clobber each other's order URL.
        self._order_urls: dict[str, str] = {}

    def _get_client(self, auth: Any = None) -> HttpClient:
        return HttpClient(
            headers={"User-Agent": self._user_agent.encode()},
            auth=auth,
            validate_cert=self._verify_ssl,
        )

    async def get_authorization_status(self, auth: AcmeAuthorization) -> AcmeAuthorizationStatus:
        # gufo-acme 0.6.0 crashes on challenge types that have no `token` field
        # (e.g. Pebble's device-attest-01). Filter those out before constructing
        # AcmeChallenge objects so gufo-acme only sees the standard challenge types.
        resp = await self._post(auth.url, None)
        data = json.loads(resp.content)
        return AcmeAuthorizationStatus(
            status=data["status"],
            challenges=[
                AcmeChallenge(type=d["type"], url=d["url"], token=d["token"])
                for d in data["challenges"]
                if "token" in d
            ],
        )

    async def new_order(self, domain: str) -> AcmeOrder:  # type: ignore[override]
        """Override to capture the order URL from the Location header.

        gufo-acme's new_order() discards Location, but we need it as a fallback
        for finalize_and_wait() when the CA omits Location there (Pebble does).
        """
        identifiers = self._domain_to_identifiers(domain)
        self._check_bound()
        d = await self._get_directory()
        resp = await self._post(d.new_order, {"identifiers": identifiers})
        data = json.loads(resp.content)
        loc = resp.headers.get("Location", None)
        if loc is not None:
            self._order_urls[data["finalize"]] = loc.decode()
        return AcmeOrder(
            authorizations=[
                AcmeAuthorization(domain=i["value"], url=a)
                for i, a in zip(identifiers, data["authorizations"], strict=True)
            ],
            finalize=data["finalize"],
        )

    async def finalize_and_wait(self, order: AcmeOrder, *, csr: bytes) -> bytes:
        """Override to handle CAs that omit Location from the finalize response.

        RFC 8555 §7.4 says Location SHOULD be present, not MUST. Pebble omits
        it from finalize but does include it in new_order, which we capture in
        our new_order() override above.
        """
        resp = await self._post(order.finalize, {"csr": encode_b64jose(self._pem_to_der(csr))})
        self._get_order_status(resp)

        location = resp.headers.get("Location", None)
        # Pop our captured URL for this order regardless, so the map never grows.
        stored_order_url = self._order_urls.pop(order.finalize, None)
        if location is not None:
            order_uri = location.decode()
        elif stored_order_url is not None:
            order_uri = stored_order_url
        else:
            # Last resort: cert may already be in the finalize response body.
            data = json.loads(resp.content)
            if data.get("status") == "valid" and "certificate" in data:
                cert_resp = await self._post(data["certificate"], None)
                return cert_resp.content
            raise AcmeCertificateError(
                "Finalize response missing Location header and no order URL available"
            )

        # Poll until the CA marks the order valid, bounded so a stuck order
        # cannot loop forever.
        await asyncio.sleep(1)
        for _ in range(_FINALIZE_POLL_ATTEMPTS):
            resp = await self._post(order_uri, None)
            status = self._get_order_status(resp)
            if status == "valid":
                data = json.loads(resp.content)
                cert_resp = await self._post(data["certificate"], None)
                return cert_resp.content
            if status == "invalid":
                raise AcmeCertificateError(f"Order {order_uri} became invalid during finalization")
            await asyncio.sleep(_FINALIZE_POLL_INTERVAL)
        raise AcmeCertificateError(
            f"Order {order_uri} did not become valid within "
            f"{_FINALIZE_POLL_ATTEMPTS * _FINALIZE_POLL_INTERVAL:.0f}s"
        )

    async def fulfill_dns_01(self, domain: str, challenge: AcmeChallenge) -> bool:
        """Set ``_acme-challenge.<domain>`` TXT record, then wait for propagation.

        Args:
            domain:    The domain being challenged (e.g. ``"host.example.com"``).
            challenge: gufo-acme challenge object.

        Returns:
            ``True`` on success, ``False`` if the DNS call failed.
        """
        apex = _apex_domain(domain, self._zone_overrides)
        name = f"_acme-challenge.{domain}"
        value = _dns01_txt_value(self.get_key_authorization(challenge))

        try:
            await self._dns.set_txt(apex, name, value)
        except Exception:
            log.exception("DNS-01 set_txt failed for domain %s", domain)
            return False

        if self._propagation_wait:
            log.debug("Waiting %ds for DNS propagation…", self._propagation_wait)
            await asyncio.sleep(self._propagation_wait)

        return True

    async def clear_dns_01(self, domain: str, challenge: AcmeChallenge) -> None:
        """Remove ``_acme-challenge.<domain>`` TXT record after LE validation.

        Failure is logged as a warning but does not propagate — a lingering
        TXT record is harmless.
        """
        apex = _apex_domain(domain, self._zone_overrides)
        name = f"_acme-challenge.{domain}"

        try:
            await self._dns.delete_txt(apex, name)
        except Exception:
            log.warning("DNS-01 delete_txt failed for %s (non-fatal)", domain)


def _load_or_create_account_key(key_path: Path) -> JWKEC:
    """Return a josepy JWKEC wrapping a P-256 key, creating the file on first call.

    The key file is stored as PEM-encoded PKCS8 with mode 0o600.
    """
    if key_path.exists():
        raw = load_pem_private_key(key_path.read_bytes(), password=None)
        return JWKEC(key=raw)

    key_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = generate_private_key(SECP256R1())
    pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    key_path.write_bytes(pem)
    key_path.chmod(0o600)
    log.info("Created new LE account key at %s", key_path)
    return JWKEC(key=private_key)


async def init_account(dns_provider: DNSProvider) -> JackdawAcmeClient:
    """Initialise and return a ``JackdawAcmeClient`` with a registered LE account.

    Loads the account key from ``settings.le_account_key_path`` (creating it
    if absent) and registers the account with Let's Encrypt if not already
    done.

    Args:
        dns_provider: The active DNS provider for challenge fulfilment.

    Returns:
        An initialised, ready-to-use ``JackdawAcmeClient``.
    """
    settings = get_settings()
    key = _load_or_create_account_key(Path(settings.le_account_key_path))

    client = JackdawAcmeClient(
        settings.le_directory,
        dns_provider=dns_provider,
        propagation_wait=settings.dns_propagation_wait,
        verify_ssl=settings.le_verify_ssl,
        zone_overrides=settings.dns_zone_override_list,
        key=key,
        alg=ES256,
    )

    # new_account is idempotent — safe to call even if already registered.
    await client.new_account(settings.acme_email)
    log.info("LE account registered/verified at %s", settings.le_directory)

    return client


async def order_cert(
    client: JackdawAcmeClient,
    domain: str,
    csr_der: bytes,
) -> str:
    """Run the full ACME flow for *domain* using the supplied CSR.

    gufo-acme handles: new-order → DNS-01 challenge → ``fulfill_dns_01``
    (set TXT) → notify LE → wait for validation → ``clear_dns_01`` (delete
    TXT) → finalize with CSR → fetch cert.

    Args:
        client:  Initialised ``JackdawAcmeClient``.
        domain:  The domain to certify (must be in the CSR SAN).
        csr_der: DER-encoded certificate signing request from the ACME client.

    Returns:
        PEM-encoded certificate chain (leaf + intermediates).
    """
    # gufo-acme sign() expects a PEM-format CSR; convert from DER.
    csr_pem = _der_to_pem_csr(csr_der)
    result = await client.sign(domain, csr_pem)
    return result.decode()


# Map gufo-acme exception types to the ACME problem type + a human-readable
# detail.  gufo raises bare exception classes for the specific cases below
# (the upstream LE detail string is not preserved on the exception), so we
# reconstruct a meaningful problem document from the exception type.
_ACME_PROBLEMS: list[tuple[type[AcmeError], str, str]] = [
    (
        AcmeRateLimitError,
        "urn:ietf:params:acme:error:rateLimited",
        "Let's Encrypt rejected the request due to its rate limits; retry later.",
    ),
    (
        AcmeUnauthorizedError,
        "urn:ietf:params:acme:error:unauthorized",
        "Let's Encrypt refused to authorize issuance for this domain.",
    ),
    (
        AcmeFulfillmentFailed,
        "urn:ietf:params:acme:error:dns",
        "The relay could not fulfil the DNS-01 challenge with Let's Encrypt.",
    ),
    (
        AcmeTimeoutError,
        "urn:ietf:params:acme:error:connection",
        "The relay timed out talking to Let's Encrypt.",
    ),
    (
        AcmeConnectError,
        "urn:ietf:params:acme:error:connection",
        "The relay could not connect to Let's Encrypt.",
    ),
]


def acme_problem(exc: BaseException) -> dict[str, str]:
    """Return an RFC 8555 problem document describing an issuance failure.

    Used to populate an order's ``error`` field so the ACME client learns why
    issuance failed instead of seeing a bare ``invalid`` status.  Known
    gufo-acme error types map to a specific ACME error type; a generic
    ``AcmeError`` carries its own message (gufo formats it as
    ``[status] type detail``); anything else is reported as an internal error.
    """
    for exc_type, problem_type, detail in _ACME_PROBLEMS:
        if isinstance(exc, exc_type):
            return {"type": problem_type, "detail": detail}
    if isinstance(exc, AcmeError):
        detail = str(exc).strip() or "Let's Encrypt rejected the certificate request."
        return {"type": "urn:ietf:params:acme:error:serverInternal", "detail": detail}
    return {
        "type": "urn:ietf:params:acme:error:serverInternal",
        "detail": "An unexpected error occurred while issuing the certificate.",
    }


def is_known_acme_error(exc: BaseException) -> bool:
    """True if *exc* is an expected ACME protocol error (vs. an unexpected bug).

    Lets callers log expected operational failures (rate limits, DNS issues)
    as clean warnings while still emitting full tracebacks for real bugs.
    """
    return isinstance(exc, AcmeError)
