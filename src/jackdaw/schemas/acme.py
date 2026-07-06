"""Pydantic v2 models for all ACME request and response payloads (RFC 8555)."""

from typing import Any

from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Directory
# ---------------------------------------------------------------------------


class DirectoryMeta(BaseModel):
    """Optional metadata block in the directory response."""

    termsOfService: str | None = None
    website: str | None = None
    caaIdentities: list[str] | None = None
    externalAccountRequired: bool | None = None


class DirectoryResponse(BaseModel):
    """RFC 8555 §7.1.1 — directory object returned by GET /directory."""

    newNonce: str
    newAccount: str
    newOrder: str
    revokeCert: str
    keyChange: str
    meta: DirectoryMeta | None = None


# ---------------------------------------------------------------------------
# JWS envelope
# ---------------------------------------------------------------------------


class JWSEnvelope(BaseModel):
    """Flat-JSON serialisation of a JWS object (RFC 7515 §7.2.2)."""

    protected: str  # base64url-encoded protected header
    payload: str  # base64url-encoded payload (may be empty string)
    signature: str  # base64url-encoded signature


# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------


class NewAccountRequest(BaseModel):
    """Decoded payload for POST /acme/new-account."""

    termsOfServiceAgreed: bool = False
    contact: list[str] | None = None
    onlyReturnExisting: bool = False


class AccountResponse(BaseModel):
    """Response body for account creation or lookup."""

    status: str
    contact: list[str] | None = None
    orders: str | None = None


# ---------------------------------------------------------------------------
# Orders
# ---------------------------------------------------------------------------


class Identifier(BaseModel):
    """A single ACME identifier (always type=dns for Jackdaw)."""

    type: str
    value: str


class NewOrderRequest(BaseModel):
    """Decoded payload for POST /acme/new-order."""

    identifiers: list[Identifier]


class OrderResponse(BaseModel):
    """Response body for order creation or status polling."""

    status: str
    identifiers: list[Identifier]
    authorizations: list[str]
    finalize: str
    certificate: str | None = None
    expires: str | None = None
    # RFC 8555 §7.1.3 problem document, present only on a failed ('invalid') order.
    error: dict[str, Any] | None = None


class FinalizeRequest(BaseModel):
    """Decoded payload for POST /acme/order/{id}/finalize."""

    csr: str  # base64url-encoded DER CSR


# ---------------------------------------------------------------------------
# Authorizations & challenges
# ---------------------------------------------------------------------------


class ChallengeObject(BaseModel):
    """A single challenge object nested inside an AuthzResponse."""

    type: str
    url: str
    status: str
    token: str


class AuthzResponse(BaseModel):
    """Response body for GET /acme/authz/{id}."""

    status: str
    identifier: Identifier
    challenges: list[ChallengeObject]


# ---------------------------------------------------------------------------
# ACME error (RFC 7807 + RFC 8555 §6.7)
# ---------------------------------------------------------------------------


class AcmeError(BaseModel):
    """Structured ACME error returned as the JSON body of error responses."""

    type: str
    detail: str
    status: int
    subproblems: list[dict[str, Any]] | None = None
