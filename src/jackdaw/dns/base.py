"""Abstract base class for DNS provider implementations."""

from abc import ABC, abstractmethod


class DNSProvider(ABC):
    """Interface that all DNS providers must implement.

    Each concrete provider reads its own credentials from environment variables
    (via a nested ``BaseSettings`` model with an ``env_prefix``).  Providers
    that are not selected at startup never read their env vars, so missing
    credentials for unused providers do not cause startup failures.
    """

    @abstractmethod
    async def set_txt(self, domain: str, name: str, value: str) -> None:
        """Create a DNS TXT record.

        Args:
            domain: Registered apex domain (e.g. ``"example.com"``).
            name:   Full record name (e.g. ``"_acme-challenge.host.example.com"``).
            value:  TXT record value — the base64url-encoded SHA-256 digest of
                    the ACME key authorisation string.
        """

    @abstractmethod
    async def delete_txt(self, domain: str, name: str) -> None:
        """Remove the TXT record after Let's Encrypt has validated the challenge.

        Args:
            domain: Registered apex domain.
            name:   Full record name to delete.
        """
