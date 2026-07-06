"""Small internal utilities shared across modules."""

import base64
import json
from datetime import UTC, datetime
from typing import Any


def utcnow() -> datetime:
    """Return the current UTC time as a *naive* ``datetime``.

    Every ``DateTime`` column in the schema is timezone-naive because SQLite
    does not persist ``tzinfo`` — a value written as aware round-trips as naive.
    Storing and comparing naive-UTC values everywhere avoids mixing aware and
    naive datetimes, which SQLAlchemy renders as differently-formatted strings
    (``...+00:00`` vs none) and therefore compares incorrectly at the boundary
    in SQLite's lexicographic datetime comparison.
    """
    return datetime.now(UTC).replace(tzinfo=None)


def b64url_decode(s: str) -> bytes:
    """Decode a base64url string, tolerating absent padding characters."""
    rem = len(s) % 4
    if rem:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s)


def canonical_jwk(jwk_data: dict[str, Any]) -> str:
    """Return a stable, sorted-key JSON serialisation of a JWK dict.

    Storing this in the database means two clients that send the same key
    with different field orderings still match the same account row.
    """
    return json.dumps(jwk_data, sort_keys=True, separators=(",", ":"))
