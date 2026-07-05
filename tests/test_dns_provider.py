"""Unit tests for the DNS provider layer."""

from __future__ import annotations

import asyncio
import json

import pytest
import respx
from httpx import Response

from jackdaw.dns.base import DNSProvider
from jackdaw.dns.loader import get_provider
from jackdaw.dns.providers.cloudflare import CloudflareDNSProvider
from jackdaw.dns.providers.namecheap import NamecheapDNSProvider
from jackdaw.dns.providers.porkbun import PorkbunDNSProvider
from jackdaw.dns.providers.route53 import Route53DNSProvider

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


# ---------------------------------------------------------------------------
# Cloudflare provider
# ---------------------------------------------------------------------------

_CF_ZONE_URL = "https://api.cloudflare.com/client/v4/zones"
_CF_RECORDS_URL = "https://api.cloudflare.com/client/v4/zones/zone123/dns_records"


@respx.mock
async def test_cloudflare_set_txt_creates_record(monkeypatch: pytest.MonkeyPatch) -> None:
    """set_txt should look up the zone then POST a TXT record."""
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cf_test_token")

    zone_route = respx.get(_CF_ZONE_URL).mock(
        return_value=Response(200, json={"result": [{"id": "zone123"}]})
    )
    create_route = respx.post(_CF_RECORDS_URL).mock(
        return_value=Response(200, json={"result": {"id": "rec1"}, "success": True})
    )

    provider = CloudflareDNSProvider()
    await provider.set_txt("example.com", "_acme-challenge.example.com", "testtoken")

    assert zone_route.called
    assert create_route.called
    body = json.loads(create_route.calls[0].request.content)
    assert body["type"] == "TXT"
    assert body["name"] == "_acme-challenge.example.com"
    assert body["content"] == "testtoken"


@respx.mock
async def test_cloudflare_delete_txt_removes_each_record(monkeypatch: pytest.MonkeyPatch) -> None:
    """delete_txt should retrieve matching records then DELETE each by ID."""
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cf_test_token")

    respx.get(_CF_ZONE_URL).mock(return_value=Response(200, json={"result": [{"id": "zone123"}]}))
    respx.get(_CF_RECORDS_URL).mock(
        return_value=Response(200, json={"result": [{"id": "r1"}, {"id": "r2"}]})
    )
    delete_route = respx.delete(url__regex=r".*/dns_records/r\d").mock(
        return_value=Response(200, json={"success": True})
    )

    provider = CloudflareDNSProvider()
    await provider.delete_txt("example.com", "_acme-challenge.example.com")

    assert delete_route.call_count == 2


# ---------------------------------------------------------------------------
# Route 53 provider
# ---------------------------------------------------------------------------

_R53_ZONES_URL = "https://route53.amazonaws.com/2013-04-01/hostedzonesbyname"
_R53_RRSET_URL_RE = r"https://route53\.amazonaws\.com/2013-04-01/hostedzone/ZONE1/rrset.*"

_ZONE_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<ListHostedZonesByNameResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">'
    "<HostedZones><HostedZone>"
    "<Id>/hostedzone/ZONE1</Id>"
    "<Name>example.com.</Name>"
    "</HostedZone></HostedZones>"
    "<IsTruncated>false</IsTruncated><MaxItems>1</MaxItems>"
    "</ListHostedZonesByNameResponse>"
)

_RRSET_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">'
    "<ResourceRecordSets><ResourceRecordSet>"
    "<Name>_acme-challenge.example.com.</Name>"
    "<Type>TXT</Type><TTL>120</TTL>"
    "<ResourceRecords><ResourceRecord>"
    "<Value>&quot;existing_token&quot;</Value>"
    "</ResourceRecord></ResourceRecords>"
    "</ResourceRecordSet></ResourceRecordSets>"
    "<IsTruncated>false</IsTruncated><MaxItems>1</MaxItems>"
    "</ListResourceRecordSetsResponse>"
)

_CHANGE_OK_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<ChangeResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">'
    "<ChangeInfo><Id>/change/ABC</Id><Status>PENDING</Status></ChangeInfo>"
    "</ChangeResourceRecordSetsResponse>"
)


@respx.mock
async def test_route53_set_txt_creates_record(monkeypatch: pytest.MonkeyPatch) -> None:
    """set_txt should look up the zone then POST a CREATE change."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testsecret")

    zone_route = respx.get(url__regex=r".*hostedzonesbyname.*").mock(
        return_value=Response(200, text=_ZONE_XML)
    )
    change_route = respx.post(url__regex=_R53_RRSET_URL_RE).mock(
        return_value=Response(200, text=_CHANGE_OK_XML)
    )

    provider = Route53DNSProvider()
    await provider.set_txt("example.com", "_acme-challenge.example.com", "newtoken")

    assert zone_route.called
    assert change_route.called
    body = change_route.calls[0].request.content.decode()
    assert "<Action>CREATE</Action>" in body
    assert '"newtoken"' in body


def test_route53_change_xml_escapes_special_chars(monkeypatch: pytest.MonkeyPatch) -> None:
    """XML metacharacters in the record name/value must be escaped, not injected."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testsecret")

    provider = Route53DNSProvider()
    xml = provider._change_xml("CREATE", "_acme-challenge.a&b<c>", ['"x&y<z>"'])

    assert "_acme-challenge.a&amp;b&lt;c&gt;" in xml
    assert '"x&amp;y&lt;z&gt;"' in xml
    # No raw, unescaped user metacharacters leaked into the body.
    assert "a&b" not in xml
    assert "x&y" not in xml


@respx.mock
async def test_route53_delete_txt_removes_record(monkeypatch: pytest.MonkeyPatch) -> None:
    """delete_txt should fetch existing values then POST a DELETE change."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testsecret")

    respx.get(url__regex=r".*hostedzonesbyname.*").mock(return_value=Response(200, text=_ZONE_XML))
    respx.get(url__regex=r".*hostedzone/ZONE1/rrset.*").mock(
        return_value=Response(200, text=_RRSET_XML)
    )
    change_route = respx.post(url__regex=r".*hostedzone/ZONE1/rrset").mock(
        return_value=Response(200, text=_CHANGE_OK_XML)
    )

    provider = Route53DNSProvider()
    await provider.delete_txt("example.com", "_acme-challenge.example.com")

    assert change_route.called
    body = change_route.calls[0].request.content.decode()
    assert "<Action>DELETE</Action>" in body


# ---------------------------------------------------------------------------
# Namecheap provider
# ---------------------------------------------------------------------------

_NC_URL = "https://api.namecheap.com/xml.response"

_NC_GET_HOSTS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response">
  <Errors/>
  <CommandResponse Type="namecheap.domains.dns.getHosts">
    <DomainDNSGetHostsResult Domain="example.com" IsUsingOurDNS="true">
      <host Name="@" Type="A" Address="1.2.3.4" MXPref="10" TTL="1800"/>
    </DomainDNSGetHostsResult>
  </CommandResponse>
</ApiResponse>"""

_NC_SET_HOSTS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response">
  <Errors/>
  <CommandResponse Type="namecheap.domains.dns.setHosts">
    <DomainDNSSetHostsResult Domain="example.com" IsSuccess="true"/>
  </CommandResponse>
</ApiResponse>"""


def _nc_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NAMECHEAP_API_USER", "ncuser")
    monkeypatch.setenv("NAMECHEAP_API_KEY", "nckey")
    monkeypatch.setenv("NAMECHEAP_CLIENT_IP", "1.2.3.4")


@respx.mock
async def test_namecheap_set_txt_appends_record(monkeypatch: pytest.MonkeyPatch) -> None:
    """set_txt should read existing hosts and POST setHosts with the new TXT added."""
    _nc_env(monkeypatch)

    get_route = respx.get(_NC_URL).mock(return_value=Response(200, text=_NC_GET_HOSTS_XML))
    set_route = respx.post(_NC_URL).mock(return_value=Response(200, text=_NC_SET_HOSTS_XML))

    provider = NamecheapDNSProvider()
    await provider.set_txt("example.com", "_acme-challenge.example.com", "tok123")

    assert get_route.called
    assert set_route.called
    body = set_route.calls[0].request.content.decode()
    assert "namecheap.domains.dns.setHosts" in body
    assert "_acme-challenge" in body
    assert "tok123" in body
    # Existing A record must be preserved
    assert "1.2.3.4" in body


@respx.mock
async def test_namecheap_delete_txt_removes_record(monkeypatch: pytest.MonkeyPatch) -> None:
    """delete_txt should remove only the matching TXT record and preserve others."""
    _nc_env(monkeypatch)

    get_xml = """<?xml version="1.0" encoding="UTF-8"?>
<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response">
  <Errors/>
  <CommandResponse Type="namecheap.domains.dns.getHosts">
    <DomainDNSGetHostsResult Domain="example.com" IsUsingOurDNS="true">
      <host Name="@" Type="A" Address="1.2.3.4" MXPref="10" TTL="1800"/>
      <host Name="_acme-challenge" Type="TXT" Address="tok123" MXPref="10" TTL="120"/>
    </DomainDNSGetHostsResult>
  </CommandResponse>
</ApiResponse>"""

    respx.get(_NC_URL).mock(return_value=Response(200, text=get_xml))
    set_route = respx.post(_NC_URL).mock(return_value=Response(200, text=_NC_SET_HOSTS_XML))

    provider = NamecheapDNSProvider()
    await provider.delete_txt("example.com", "_acme-challenge.example.com")

    assert set_route.called
    body = set_route.calls[0].request.content.decode()
    assert "_acme-challenge" not in body
    assert "tok123" not in body
    # A record must be preserved
    assert "1.2.3.4" in body


async def test_namecheap_set_txt_serializes_concurrent_writes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The per-apex lock must prevent lost updates on concurrent same-domain writes.

    Namecheap's setHosts replaces the entire host list, so two overlapping
    read-modify-write cycles would drop one record.  The lock serializes them.
    """
    _nc_env(monkeypatch)
    provider = NamecheapDNSProvider()

    state: list[dict[str, str]] = []
    active = 0
    max_concurrent = 0

    async def fake_get(client: object, sld: str, tld: str) -> list[dict[str, str]]:
        nonlocal active, max_concurrent
        active += 1
        max_concurrent = max(max_concurrent, active)
        await asyncio.sleep(0)  # yield: an unlocked impl would let the peer read stale state
        return list(state)

    async def fake_set(client: object, sld: str, tld: str, hosts: list[dict[str, str]]) -> None:
        nonlocal active
        await asyncio.sleep(0)
        state[:] = hosts
        active -= 1

    monkeypatch.setattr(provider, "_get_hosts", fake_get)
    monkeypatch.setattr(provider, "_set_hosts", fake_set)

    await asyncio.gather(
        provider.set_txt("example.com", "_acme-challenge.a.example.com", "tokA"),
        provider.set_txt("example.com", "_acme-challenge.b.example.com", "tokB"),
    )

    # Both records survived — neither write was lost.
    assert {h["address"] for h in state} == {"tokA", "tokB"}
    # Read-modify-write cycles never overlapped.
    assert max_concurrent == 1
