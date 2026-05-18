"""Namecheap DNS provider."""

import logging
from xml.etree import ElementTree

import httpx
from pydantic_settings import BaseSettings

from jackdaw.dns.base import DNSProvider

log = logging.getLogger(__name__)

_BASE_URL = "https://api.namecheap.com/xml.response"
_NC_NS = "http://api.namecheap.com/xml.response"

_HostRecord = dict[str, str]


class _NamecheapSettings(BaseSettings):
    """Namecheap API credentials read from ``NAMECHEAP_*`` env vars."""

    api_user: str
    api_key: str
    username: str = ""
    client_ip: str

    model_config = {"env_prefix": "NAMECHEAP_", "env_file": ".env", "extra": "ignore"}


class NamecheapDNSProvider(DNSProvider):
    """DNS provider backed by the Namecheap API.

    Credentials are read from ``NAMECHEAP_*`` env vars at instantiation time.
    ``NAMECHEAP_CLIENT_IP`` must be whitelisted in your Namecheap account's
    API access settings.

    The Namecheap DNS API replaces the full host list on every write, so
    ``set_txt`` and ``delete_txt`` each perform a read-modify-write cycle.
    """

    def __init__(self) -> None:
        s = _NamecheapSettings()
        self._api_user = s.api_user
        self._api_key = s.api_key
        self._username = s.username or s.api_user
        self._client_ip = s.client_ip

    def _base_params(self, command: str, sld: str, tld: str) -> dict[str, str]:
        return {
            "ApiUser": self._api_user,
            "ApiKey": self._api_key,
            "UserName": self._username,
            "ClientIp": self._client_ip,
            "Command": command,
            "SLD": sld,
            "TLD": tld,
        }

    @staticmethod
    def _split_domain(domain: str) -> tuple[str, str]:
        sld, tld = domain.split(".", 1)
        return sld, tld

    def _check_status(self, root: ElementTree.Element) -> None:
        if root.get("Status") != "OK":
            errors = root.findall(f".//{{{_NC_NS}}}Error")
            msg = "; ".join(e.text or "" for e in errors) or "Unknown error"
            raise RuntimeError(f"Namecheap API error: {msg}")

    async def _get_hosts(self, client: httpx.AsyncClient, sld: str, tld: str) -> list[_HostRecord]:
        r = await client.get(
            _BASE_URL,
            params=self._base_params("namecheap.domains.dns.getHosts", sld, tld),
        )
        r.raise_for_status()
        root = ElementTree.fromstring(r.text)  # noqa: S314
        self._check_status(root)
        return [
            {
                "name": h.get("Name", ""),
                "type": h.get("Type", ""),
                "address": h.get("Address", ""),
                "mx_pref": h.get("MXPref", "10"),
                "ttl": h.get("TTL", "1800"),
            }
            for h in root.findall(f".//{{{_NC_NS}}}host")
        ]

    async def _set_hosts(
        self, client: httpx.AsyncClient, sld: str, tld: str, hosts: list[_HostRecord]
    ) -> None:
        params = self._base_params("namecheap.domains.dns.setHosts", sld, tld)
        for i, host in enumerate(hosts, start=1):
            params[f"HostName{i}"] = host["name"]
            params[f"RecordType{i}"] = host["type"]
            params[f"Address{i}"] = host["address"]
            params[f"MXPref{i}"] = host.get("mx_pref", "10")
            params[f"TTL{i}"] = host.get("ttl", "1800")
        r = await client.post(_BASE_URL, data=params)
        r.raise_for_status()
        self._check_status(ElementTree.fromstring(r.text))  # noqa: S314

    async def set_txt(self, domain: str, name: str, value: str) -> None:
        """Create a TXT record on Namecheap.

        Args:
            domain: Apex domain registered at Namecheap (e.g. ``"example.com"``).
            name:   Full record name; the apex suffix is stripped to derive the
                    Namecheap ``HostName`` (e.g. ``"_acme-challenge"``).
            value:  TXT record content.
        """
        sld, tld = self._split_domain(domain)
        rel_name = name.removesuffix(f".{domain}")
        async with httpx.AsyncClient() as client:
            hosts = await self._get_hosts(client, sld, tld)
            hosts.append(
                {"name": rel_name, "type": "TXT", "address": value, "mx_pref": "10", "ttl": "120"}
            )
            await self._set_hosts(client, sld, tld, hosts)
        log.debug("Namecheap: created TXT %s on %s", name, domain)

    async def delete_txt(self, domain: str, name: str) -> None:
        """Delete TXT records matching *name* on Namecheap.

        Args:
            domain: Apex domain.
            name:   Full record name to remove.
        """
        sld, tld = self._split_domain(domain)
        rel_name = name.removesuffix(f".{domain}")
        async with httpx.AsyncClient() as client:
            hosts = await self._get_hosts(client, sld, tld)
            before = len(hosts)
            hosts = [h for h in hosts if not (h["type"] == "TXT" and h["name"] == rel_name)]
            if len(hosts) < before:
                await self._set_hosts(client, sld, tld, hosts)
        log.debug("Namecheap: deleted TXT %s on %s", name, domain)
