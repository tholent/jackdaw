"""HTTP-01 challenge validation for the client-facing ACME leg.

Jackdaw acts as a two-leg ACME bridge:
  - Client ↔ Jackdaw: standard HTTP-01 (this module validates it).
  - Jackdaw ↔ Let's Encrypt: DNS-01 using the relay's DNS provider credentials.

Validation fetches ``http://<domain>:<port>/.well-known/acme-challenge/<token>``
and compares the response body to the expected key authorization:

    key_auth = token + "." + base64url(SHA-256(RFC 7638 JWK thumbprint))

SSRF protection is applied before every fetch:
  - The domain is resolved via getaddrinfo and all resulting IP addresses are
    checked against blocked ranges (loopback, link-local, multicast, etc.).
  - The resolved IP is used as the connection target with the original hostname
    sent as the HTTP ``Host`` header, pinning the connection to the pre-checked
    address and defeating DNS-rebinding attacks.
"""

import asyncio
import base64
import hmac
import ipaddress
import json
import logging
import socket
from collections.abc import Callable
from typing import Any

import httpx
from josepy.jwk import JWK

from jackdaw.config import Settings, get_settings

log = logging.getLogger(__name__)

# Response body size cap — key authorizations are short; reject large responses.
_MAX_RESPONSE_BYTES = 4096

# IP ranges that must never be contacted.
# RFC 1918 private ranges are intentionally NOT blocked: clients are internal
# services whose IPs live in those ranges.  What we block is the relay's own
# loopback, link-local (cloud metadata), and other non-routable/protocol ranges.
_BLOCKED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.IPv4Network("127.0.0.0/8"),  # loopback
    ipaddress.IPv4Network("169.254.0.0/16"),  # link-local / cloud metadata (e.g. 169.254.169.254)
    ipaddress.IPv4Network("0.0.0.0/8"),  # unspecified
    ipaddress.IPv4Network("224.0.0.0/4"),  # multicast
    ipaddress.IPv4Network("240.0.0.0/4"),  # reserved
    ipaddress.IPv6Network("::1/128"),  # loopback
    ipaddress.IPv6Network("fe80::/10"),  # link-local
    ipaddress.IPv6Network("ff00::/8"),  # multicast
)


class Http01ValidationError(Exception):
    """Raised when HTTP-01 validation fails for any reason."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


def _is_blocked(ip_str: str) -> bool:
    """Return True if *ip_str* falls within any blocked network range."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparsable → block
    return any(addr in net for net in _BLOCKED_NETWORKS)


def _resolve_and_check(hostname: str) -> str:
    """Resolve *hostname* and return a safe IP string, or raise Http01ValidationError.

    Resolves all addresses and rejects the hostname if *any* resolved address
    falls in a blocked range.  Returns the first non-blocked IPv4 address, or
    IPv6 if no IPv4 is available.

    This function is synchronous and should be called via asyncio.to_thread.
    """
    try:
        results = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise Http01ValidationError(f"DNS resolution failed for {hostname!r}: {exc}") from exc

    if not results:
        raise Http01ValidationError(f"No DNS records found for {hostname!r}")

    # Every resolved address must clear the SSRF check — this is the DNS-rebinding
    # defense, so we cannot short-circuit on the first usable one.  Among those
    # that pass, prefer IPv4 (per the docstring), falling back to IPv6.
    chosen_ipv4: str | None = None
    chosen_any: str | None = None
    for family, _type, _proto, _canonname, sockaddr in results:
        ip = str(sockaddr[0])
        if _is_blocked(ip):
            raise Http01ValidationError(f"Domain {hostname!r} resolves to blocked address {ip!r}")
        if chosen_any is None:
            chosen_any = ip
        if family == socket.AF_INET and chosen_ipv4 is None:
            chosen_ipv4 = ip

    chosen_ip = chosen_ipv4 or chosen_any
    assert chosen_ip is not None  # guaranteed: results non-empty and all passed
    return chosen_ip


def key_authorization(token: str, account_public_key_json: str) -> str:
    """Compute the HTTP-01 key authorization string.

    Per RFC 8555 §8.3: ``token + "." + base64url(SHA-256(JWK thumbprint))``.
    The JWK thumbprint is computed per RFC 7638 using the josepy library.

    Args:
        token:                   The challenge token (stored in Authorization.challenge_token).
        account_public_key_json: Canonical JSON of the account's public JWK
                                 (stored in Account.public_key).

    Returns:
        The key authorization string the client must serve.
    """
    from typing import cast

    jwk = JWK.from_json(json.loads(account_public_key_json))
    # josepy thumbprint() returns raw SHA-256 bytes (RFC 7638); base64url-encode them.
    # Cast via Any because josepy's stub doesn't expose thumbprint() on the base type.
    thumb_bytes: bytes = cast(Any, jwk).thumbprint()
    thumbprint_b64 = base64.urlsafe_b64encode(thumb_bytes).rstrip(b"=").decode("ascii")
    return f"{token}.{thumbprint_b64}"


async def validate_http01(
    domain: str,
    token: str,
    expected_key_auth: str,
    *,
    settings: Settings | None = None,
    client_factory: Callable[..., Any] | None = None,
) -> None:
    """Fetch the HTTP-01 challenge response and verify it matches *expected_key_auth*.

    Resolves *domain* over the network (using the relay's DNS resolver, which
    may be an internal resolver), pins the connection to the resolved IP to
    prevent DNS rebinding, and verifies the response body is the expected key
    authorization string.

    Args:
        domain:            The domain name being challenged.
        token:             The challenge token.
        expected_key_auth: The value the client must serve.
        settings:          Settings instance (defaults to get_settings()).
        client_factory:    Optional httpx.AsyncClient factory — used in tests
                           to inject a mock transport without real DNS/network.

    Raises:
        Http01ValidationError: Validation failed for any reason.
    """
    cfg = settings or get_settings()
    url_path = f"/.well-known/acme-challenge/{token}"

    for attempt in range(1, cfg.challenge_retries + 1):
        try:
            await _attempt_validation(
                domain,
                cfg.challenge_http_port,
                url_path,
                expected_key_auth,
                cfg.challenge_timeout,
                client_factory,
            )
            return  # success
        except Http01ValidationError:
            if attempt == cfg.challenge_retries:
                raise
            log.debug(
                "HTTP-01 validation attempt %d/%d failed for %s — retrying in %ds",
                attempt,
                cfg.challenge_retries,
                domain,
                cfg.challenge_retry_delay,
            )
            await asyncio.sleep(cfg.challenge_retry_delay)


async def _attempt_validation(  # noqa: ASYNC109
    domain: str,
    port: int,
    url_path: str,
    expected: str,
    request_timeout: int,
    client_factory: Callable[..., Any] | None,
) -> None:
    """Single validation attempt — resolve, SSRF-check, fetch, compare."""
    if client_factory is not None:
        # Test path: caller supplies a pre-configured mock client; skip real DNS.
        url = f"http://{domain}{url_path}"
        async with client_factory() as client:
            await _fetch_and_compare(client, url, domain, expected, request_timeout)
        return

    # Production path: resolve hostname and pin connection to the checked IP.
    try:
        ip = await asyncio.to_thread(_resolve_and_check, domain)
    except Http01ValidationError:
        raise
    except Exception as exc:
        raise Http01ValidationError(f"Unexpected error resolving {domain!r}: {exc}") from exc

    # Build the URL against the pinned IP address; keep original domain as Host header.
    # The configured challenge port must be part of the connection target — it
    # governs where we actually connect, not just what we advertise in Host.
    host_port = "" if port == 80 else f":{port}"
    if ":" in ip:  # IPv6 — must be bracketed
        target = f"http://[{ip}]{host_port}{url_path}"
    else:
        target = f"http://{ip}{host_port}{url_path}"

    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(request_timeout),
        headers={"Host": f"{domain}:{port}" if port != 80 else domain},
    ) as client:
        await _fetch_and_compare(client, target, domain, expected, request_timeout)


async def _fetch_and_compare(  # noqa: ASYNC109
    client: httpx.AsyncClient,
    url: str,
    domain: str,
    expected: str,
    request_timeout: int,
) -> None:
    """Perform the GET and compare the response body to *expected*."""
    try:
        resp = await client.get(url)
    except httpx.TimeoutException as exc:
        raise Http01ValidationError(
            f"HTTP-01 request timed out for {domain!r} after {request_timeout}s"
        ) from exc
    except httpx.RequestError as exc:
        raise Http01ValidationError(f"HTTP-01 request failed for {domain!r}: {exc}") from exc

    if resp.status_code != 200:
        raise Http01ValidationError(
            f"HTTP-01 challenge URL returned status {resp.status_code} for {domain!r}"
        )

    body = resp.content[:_MAX_RESPONSE_BYTES].decode("ascii", errors="replace").strip()
    if not body:
        raise Http01ValidationError(f"HTTP-01 response body is empty for {domain!r}")

    if not hmac.compare_digest(body, expected):
        raise Http01ValidationError(f"HTTP-01 key authorization mismatch for {domain!r}")
