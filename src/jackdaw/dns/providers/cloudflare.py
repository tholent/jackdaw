"""Cloudflare DNS provider."""

import logging

import httpx
from pydantic import Field
from pydantic_settings import BaseSettings

from jackdaw.dns.base import DNSProvider

log = logging.getLogger(__name__)


class _CloudflareSettings(BaseSettings):
    """Cloudflare API credentials read from ``CLOUDFLARE_*`` env vars."""

    # min_length=1 (and no default): a missing *or empty* token fails at startup
    # rather than silently starting and failing on the first API call.  docker
    # compose passes CLOUDFLARE_API_TOKEN as "" when unset, so a bare `str`
    # default would not catch it — the length constraint does.
    api_token: str = Field(min_length=1)

    model_config = {"env_prefix": "CLOUDFLARE_", "env_file": ".env", "extra": "ignore"}


class CloudflareDNSProvider(DNSProvider):
    """DNS provider backed by the Cloudflare API v4.

    Credentials are read from ``CLOUDFLARE_API_TOKEN`` at instantiation time.
    """

    BASE_URL = "https://api.cloudflare.com/client/v4"

    def __init__(self) -> None:
        s = _CloudflareSettings()
        self._headers = {
            "Authorization": f"Bearer {s.api_token}",
            "Content-Type": "application/json",
        }

    async def _get_zone_id(self, client: httpx.AsyncClient, domain: str) -> str:
        r = await client.get(
            f"{self.BASE_URL}/zones",
            params={"name": domain, "status": "active"},
        )
        r.raise_for_status()
        zones: list[dict[str, str]] = r.json().get("result", [])
        if not zones:
            raise ValueError(f"No active Cloudflare zone found for {domain!r}")
        return zones[0]["id"]

    async def set_txt(self, domain: str, name: str, value: str) -> None:
        """Create a TXT record on Cloudflare.

        Args:
            domain: Apex domain registered at Cloudflare (e.g. ``"example.com"``).
            name:   Full record name (e.g. ``"_acme-challenge.example.com"``).
            value:  TXT record content.
        """
        async with httpx.AsyncClient(headers=self._headers) as client:
            zone_id = await self._get_zone_id(client, domain)
            r = await client.post(
                f"{self.BASE_URL}/zones/{zone_id}/dns_records",
                json={"type": "TXT", "name": name, "content": value, "ttl": 120},
            )
            if not r.is_success:
                log.error("Cloudflare set_txt error %s: %s", r.status_code, r.text)
            r.raise_for_status()
        log.debug("Cloudflare: created TXT %s on %s", name, domain)

    async def delete_txt(self, domain: str, name: str) -> None:
        """Delete all TXT records matching *name* on Cloudflare.

        Cloudflare requires deletion by record ID, so the method first retrieves
        all matching records and deletes each one individually.

        Args:
            domain: Apex domain.
            name:   Full record name to remove.
        """
        async with httpx.AsyncClient(headers=self._headers) as client:
            zone_id = await self._get_zone_id(client, domain)
            r = await client.get(
                f"{self.BASE_URL}/zones/{zone_id}/dns_records",
                params={"type": "TXT", "name": name},
            )
            r.raise_for_status()
            records: list[dict[str, str]] = r.json().get("result", [])
            for record in records:
                dr = await client.delete(
                    f"{self.BASE_URL}/zones/{zone_id}/dns_records/{record['id']}"
                )
                if not dr.is_success:
                    log.error("Cloudflare delete_txt error %s: %s", dr.status_code, dr.text)
                dr.raise_for_status()
        log.debug("Cloudflare: deleted %d TXT record(s) for %s", len(records), name)
