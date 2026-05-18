"""Unit tests for the DNS provider layer."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from jackdaw.dns.base import DNSProvider
from jackdaw.dns.loader import get_provider
from jackdaw.dns.providers.porkbun import PorkbunDNSProvider

# ---------------------------------------------------------------------------
# Abstract interface contract — provider-agnostic tests
# ---------------------------------------------------------------------------


class _FakeProvider(DNSProvider):
    """Minimal concrete provider for testing the ABC."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str | None]] = []

    async def set_txt(self, domain: str, name: str, value: str) -> None:
        self.calls.append(("set", domain, value))

    async def delete_txt(self, domain: str, name: str) -> None:
        self.calls.append(("delete", domain, None))


async def test_set_txt_is_called() -> None:
    provider = _FakeProvider()
    await provider.set_txt("example.com", "_acme-challenge.example.com", "abc123")
    assert ("set", "example.com", "abc123") in provider.calls


async def test_delete_txt_is_called() -> None:
    provider = _FakeProvider()
    await provider.delete_txt("example.com", "_acme-challenge.example.com")
    assert ("delete", "example.com", None) in provider.calls


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def test_loader_rejects_unknown_provider() -> None:
    with pytest.raises(ValueError, match="Unknown DNS provider"):
        get_provider("no-such-provider")


def test_loader_returns_provider_for_null() -> None:
    provider = get_provider("null")
    assert isinstance(provider, DNSProvider)


# ---------------------------------------------------------------------------
# Porkbun provider — HTTP payload verification via respx
# ---------------------------------------------------------------------------


@respx.mock
async def test_porkbun_set_txt_posts_correct_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    """set_txt should POST to the Porkbun create endpoint with the right body."""
    monkeypatch.setenv("PORKBUN_API_KEY", "pk1_test")
    monkeypatch.setenv("PORKBUN_SECRET_API_KEY", "sk1_test")

    route = respx.post("https://api.porkbun.com/api/json/v3/dns/create/example.com").mock(
        return_value=Response(200, json={"status": "SUCCESS"})
    )

    provider = PorkbunDNSProvider()
    await provider.set_txt(
        domain="example.com",
        name="_acme-challenge.sub.example.com",
        value="testvalue",
    )

    assert route.called
    sent = route.calls[0].request
    import json

    body = json.loads(sent.content)
    assert body["type"] == "TXT"
    assert body["content"] == "testvalue"
    assert body["name"] == "_acme-challenge.sub"


@respx.mock
async def test_porkbun_delete_txt_deletes_each_record(monkeypatch: pytest.MonkeyPatch) -> None:
    """delete_txt must retrieve records then delete each one by ID."""
    monkeypatch.setenv("PORKBUN_API_KEY", "pk1_test")
    monkeypatch.setenv("PORKBUN_SECRET_API_KEY", "sk1_test")

    retrieve_route = respx.post(
        "https://api.porkbun.com/api/json/v3/dns/retrieveByNameType/example.com/TXT/_acme-challenge"
    ).mock(
        return_value=Response(
            200,
            json={"status": "SUCCESS", "records": [{"id": "111"}, {"id": "222"}]},
        )
    )
    delete_route = respx.post(
        url__regex=r"https://api\.porkbun\.com/api/json/v3/dns/delete/example\.com/\d+"
    ).mock(return_value=Response(200, json={"status": "SUCCESS"}))

    provider = PorkbunDNSProvider()
    await provider.delete_txt(
        domain="example.com",
        name="_acme-challenge.example.com",
    )

    assert retrieve_route.called
    # One DELETE call per record.
    assert delete_route.call_count == 2
