"""No-op DNS provider for testing environments where DNS validation is skipped."""

from jackdaw.dns.base import DNSProvider


class NullDNSProvider(DNSProvider):
    async def set_txt(self, domain: str, name: str, value: str) -> None:
        pass

    async def delete_txt(self, domain: str, name: str) -> None:
        pass
