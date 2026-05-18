"""No-op DNS provider for testing environments where DNS validation is skipped."""

from jackdaw.dns.base import DNSProvider


class NullDNSProvider(DNSProvider):
    async def set_txt(self, domain: str, name: str, value: str) -> None:
        pass  # intentional no-op: DNS validation is skipped in this environment

    async def delete_txt(self, domain: str, name: str) -> None:
        pass  # intentional no-op: DNS validation is skipped in this environment
