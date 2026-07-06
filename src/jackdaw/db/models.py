"""SQLAlchemy 2.x ORM models for all five database tables."""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Shared declarative base for all models."""


class Account(Base):
    """ACME account registered by an internal client."""

    __tablename__ = "accounts"

    id: Mapped[str] = mapped_column(primary_key=True)
    # Canonical (sorted-key) JSON of the JWK public key.  Indexed: looked up on
    # every newAccount and on every JWS verification carrying a `kid`.
    public_key: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    # JSON array of contact URIs, e.g. ["mailto:admin@example.com"].
    contact: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(default="valid")
    created_at: Mapped[datetime] = mapped_column(DateTime)


class Order(Base):
    """Certificate order placed by a client."""

    __tablename__ = "orders"

    id: Mapped[str] = mapped_column(primary_key=True)
    # Indexed: filtered by the per-account order rate-limit count.
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), index=True)
    # pending / ready / processing / valid / invalid
    status: Mapped[str] = mapped_column(default="pending")
    # JSON array of {type, value} identifier objects.
    identifiers: Mapped[str] = mapped_column(Text)
    le_order_url: Mapped[str | None] = mapped_column(Text)
    cert_id: Mapped[str | None] = mapped_column(ForeignKey("certificates.id"))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    # JSON problem document (RFC 8555 §7.1.3) set when issuance fails, so the
    # client learns why the order became 'invalid'.  NULL while the order is
    # in flight or on success.
    error: Mapped[str | None] = mapped_column(Text)


class Authorization(Base):
    """Domain authorisation tied to a single order."""

    __tablename__ = "authorizations"

    id: Mapped[str] = mapped_column(primary_key=True)
    order_id: Mapped[str] = mapped_column(ForeignKey("orders.id"))
    identifier: Mapped[str] = mapped_column()
    # pending / valid / invalid
    status: Mapped[str] = mapped_column(default="pending")
    # Random token issued to the client for the http-01 challenge URL.
    challenge_token: Mapped[str | None] = mapped_column()
    le_authz_url: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime)


class Certificate(Base):
    """Issued PEM certificate chain, stored after successful LE finalisation."""

    __tablename__ = "certificates"

    id: Mapped[str] = mapped_column(primary_key=True)
    order_id: Mapped[str] = mapped_column(ForeignKey("orders.id"))
    pem_chain: Mapped[str] = mapped_column(Text)
    issued_at: Mapped[datetime] = mapped_column(DateTime)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    # Leaf serial as lowercase hex (serials can be 160-bit, overflowing SQLite's
    # signed-integer columns).  Indexed: revocation looks a cert up by serial.
    # Nullable for rows written before this column existed.
    serial: Mapped[str | None] = mapped_column(index=True)


class Nonce(Base):
    """Single-use replay-protection nonce."""

    __tablename__ = "nonces"

    value: Mapped[str] = mapped_column(primary_key=True)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    # Indexed: filtered by consume_nonce and prune_nonces on every request/prune.
    created_at: Mapped[datetime] = mapped_column(DateTime, index=True)
