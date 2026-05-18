"""Cloudflare DNS provider stub (not yet implemented)."""

from pydantic_settings import BaseSettings

from jackdaw.dns.base import DNSProvider


class _CloudflareSettings(BaseSettings):
    """Cloudflare API credentials read from ``CLOUDFLARE_*`` env vars."""

    api_token: str = ""

    model_config = {"env_prefix": "CLOUDFLARE_", "env_file": ".env", "extra": "ignore"}


class CloudflareDNSProvider(DNSProvider):
    """Placeholder Cloudflare DNS provider.

    Neither ``set_txt`` nor ``delete_txt`` is implemented yet.  Selecting
    ``DNS_PROVIDER=cloudflare`` will raise ``NotImplementedError`` at runtime.
    """

    def __init__(self) -> None:
        # Instantiate settings to validate env vars are readable, but do not
        # fail if the token is absent — the user will only see the error when
        # they attempt an actual DNS operation.
        _CloudflareSettings()

    async def set_txt(self, domain: str, name: str, value: str) -> None:
        """Not implemented."""
        raise NotImplementedError(
            "CloudflareDNSProvider.set_txt is not yet implemented. "
            "Contributions welcome — see dns/base.py for the required interface."
        )

    async def delete_txt(self, domain: str, name: str) -> None:
        """Not implemented."""
        raise NotImplementedError(
            "CloudflareDNSProvider.delete_txt is not yet implemented. "
            "Contributions welcome — see dns/base.py for the required interface."
        )
