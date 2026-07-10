"""Canonical ACME error-type URNs (RFC 8555 §6.7 / IANA ACME error registry).

These identifiers appear in the ``type`` field of every ACME problem document
we return.  Defining them once avoids duplicating the ``urn:ietf:params:acme:
error:*`` string literals across the routes and services.
"""

_PREFIX = "urn:ietf:params:acme:error:"

ACCOUNT_DOES_NOT_EXIST = f"{_PREFIX}accountDoesNotExist"
CONNECTION = f"{_PREFIX}connection"
DNS = f"{_PREFIX}dns"
MALFORMED = f"{_PREFIX}malformed"
ORDER_NOT_READY = f"{_PREFIX}orderNotReady"
RATE_LIMITED = f"{_PREFIX}rateLimited"
REJECTED_IDENTIFIER = f"{_PREFIX}rejectedIdentifier"
SERVER_INTERNAL = f"{_PREFIX}serverInternal"
UNAUTHORIZED = f"{_PREFIX}unauthorized"
