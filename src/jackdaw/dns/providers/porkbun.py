"""Porkbun DNS provider implementation."""

import logging

import httpx
from pydantic_settings import BaseSettings

from jackdaw.dns.base import DNSProvider

log = logging.getLogger(__name__)


class _PorkbunSettings(BaseSettings):
    """Porkbun API credentials read from ``PORKBUN_*`` env vars."""

    api_key: str
    secret_api_key: str

    model_config = {"env_prefix": "PORKBUN_", "env_file": ".env", "extra": "ignore"}


class PorkbunDNSProvider(DNSProvider):
    """DNS provider backed by the Porkbun API v3.

    Credentials are read from ``PORKBUN_API_KEY`` and
    ``PORKBUN_SECRET_API_KEY`` at instantiation time.
    """

    BASE_URL = "https://api.porkbun.com/api/json/v3"

    def __init__(self) -> None:
        s = _PorkbunSettings()
        self._auth = {"apikey": s.api_key, "secretapikey": s.secret_api_key}

    async def set_txt(self, domain: str, name: str, value: str) -> None:
        """Create a TXT record on Porkbun.

        Args:
            domain: Apex domain registered at Porkbun (e.g. ``"example.com"``).
            name:   Full record name; the apex suffix is stripped to derive the
                    Porkbun ``name`` parameter (e.g. ``"_acme-challenge"``).
            value:  TXT record content.
        """
        subdomain = name.removesuffix(f".{domain}")
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{self.BASE_URL}/dns/create/{domain}",
                json={
                    **self._auth,
                    "name": subdomain,
                    "type": "TXT",
                    "content": value,
                    "ttl": 120,
                },
            )
            if not r.is_success:
                log.error("Porkbun set_txt error %s: %s", r.status_code, r.text)
            r.raise_for_status()
        log.debug("Porkbun: created TXT %s on %s", name, domain)

    async def delete_txt(self, domain: str, name: str) -> None:
        """Delete all TXT records matching *name* on Porkbun.

        Porkbun requires deletion by record ID, so the method first retrieves
        all matching records and deletes each one individually.

        Args:
            domain: Apex domain.
            name:   Full record name to remove.
        """
        subdomain = name.removesuffix(f".{domain}")
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{self.BASE_URL}/dns/retrieveByNameType/{domain}/TXT/{subdomain}",
                json=self._auth,
            )
            if not r.is_success:
                log.error("Porkbun delete_txt retrieve error %s: %s", r.status_code, r.text)
            r.raise_for_status()
            records: list[dict[str, str]] = r.json().get("records", [])
            for record in records:
                await client.post(
                    f"{self.BASE_URL}/dns/delete/{domain}/{record['id']}",
                    json=self._auth,
                )
        log.debug("Porkbun: deleted %d TXT record(s) for %s", len(records), name)
