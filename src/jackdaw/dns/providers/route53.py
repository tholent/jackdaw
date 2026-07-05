"""Amazon Route 53 DNS provider."""

import hashlib
import hmac
import logging
import urllib.parse
from datetime import UTC, datetime
from xml.etree import ElementTree
from xml.sax.saxutils import escape

import httpx
from pydantic_settings import BaseSettings

from jackdaw.dns.base import DNSProvider

log = logging.getLogger(__name__)

_NS = "https://route53.amazonaws.com/doc/2013-04-01/"
_BASE = "https://route53.amazonaws.com"
_REGION = "us-east-1"
_SERVICE = "route53"


class _Route53Settings(BaseSettings):
    """AWS credentials read from standard ``AWS_*`` env vars."""

    access_key_id: str
    secret_access_key: str
    session_token: str = ""

    model_config = {"env_prefix": "AWS_", "env_file": ".env", "extra": "ignore"}


def _mac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def _derive_key(secret: str, date: str) -> bytes:
    k = _mac(f"AWS4{secret}".encode(), date)
    k = _mac(k, _REGION)
    k = _mac(k, _SERVICE)
    return _mac(k, "aws4_request")


def _canonical_qs(params: dict[str, str]) -> str:
    return "&".join(
        f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}"
        for k, v in sorted(params.items())
    )


def _sigv4_headers(
    method: str,
    path: str,
    query: str,
    body: str,
    access_key: str,
    secret_key: str,
    session_token: str,
) -> dict[str, str]:
    now = datetime.now(tz=UTC)
    date = now.strftime("%Y%m%d")
    amzdate = now.strftime("%Y%m%dT%H%M%SZ")
    host = "route53.amazonaws.com"
    body_hash = hashlib.sha256(body.encode()).hexdigest()

    if session_token:
        canonical_headers = (
            f"host:{host}\nx-amz-date:{amzdate}\nx-amz-security-token:{session_token}\n"
        )
        signed_headers = "host;x-amz-date;x-amz-security-token"
    else:
        canonical_headers = f"host:{host}\nx-amz-date:{amzdate}\n"
        signed_headers = "host;x-amz-date"

    canonical = "\n".join([method, path, query, canonical_headers, signed_headers, body_hash])
    scope = f"{date}/{_REGION}/{_SERVICE}/aws4_request"
    string_to_sign = "\n".join(
        ["AWS4-HMAC-SHA256", amzdate, scope, hashlib.sha256(canonical.encode()).hexdigest()]
    )
    sig = hmac.new(
        _derive_key(secret_key, date), string_to_sign.encode(), hashlib.sha256
    ).hexdigest()

    headers: dict[str, str] = {
        "X-Amz-Date": amzdate,
        "Authorization": (
            f"AWS4-HMAC-SHA256 Credential={access_key}/{scope},"
            f" SignedHeaders={signed_headers}, Signature={sig}"
        ),
    }
    if session_token:
        headers["X-Amz-Security-Token"] = session_token
    return headers


class Route53DNSProvider(DNSProvider):
    """DNS provider backed by the Amazon Route 53 API.

    Standard AWS credentials are read at instantiation time from:

    - ``AWS_ACCESS_KEY_ID``
    - ``AWS_SECRET_ACCESS_KEY``
    - ``AWS_SESSION_TOKEN`` (optional — supports IAM role temporary credentials)
    """

    def __init__(self) -> None:
        s = _Route53Settings()
        self._access_key = s.access_key_id
        self._secret_key = s.secret_access_key
        self._token = s.session_token

    def _auth(self, method: str, path: str, query: str = "", body: str = "") -> dict[str, str]:
        return _sigv4_headers(
            method, path, query, body, self._access_key, self._secret_key, self._token
        )

    async def _zone_id(self, client: httpx.AsyncClient, domain: str) -> str:
        path = "/2013-04-01/hostedzonesbyname"
        params = {"dnsname": domain, "maxitems": "1"}
        query = _canonical_qs(params)
        r = await client.get(
            f"{_BASE}{path}?{query}",
            headers=self._auth("GET", path, query),
        )
        r.raise_for_status()
        root = ElementTree.fromstring(r.text)  # noqa: S314
        id_el = root.find(f".//{{{_NS}}}HostedZone/{{{_NS}}}Id")
        if id_el is None or id_el.text is None:
            raise ValueError(f"No Route 53 hosted zone found for {domain!r}")
        return id_el.text.rsplit("/", 1)[-1]

    def _change_xml(self, action: str, name: str, values: list[str]) -> str:
        # Escape all user-influenced values (record name and TXT contents) so
        # XML metacharacters cannot break out of or manipulate the request body.
        rr = "".join(f"<ResourceRecord><Value>{escape(v)}</Value></ResourceRecord>" for v in values)
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<ChangeResourceRecordSetsRequest xmlns="{_NS}">'
            f"<ChangeBatch><Changes><Change>"
            f"<Action>{action}</Action>"
            f"<ResourceRecordSet>"
            f"<Name>{escape(name)}.</Name>"
            f"<Type>TXT</Type><TTL>120</TTL>"
            f"<ResourceRecords>{rr}</ResourceRecords>"
            f"</ResourceRecordSet>"
            f"</Change></Changes></ChangeBatch>"
            f"</ChangeResourceRecordSetsRequest>"
        )

    async def set_txt(self, domain: str, name: str, value: str) -> None:
        """Create a TXT record on Route 53.

        Args:
            domain: Apex domain of the Route 53 hosted zone (e.g. ``"example.com"``).
            name:   Full record name (e.g. ``"_acme-challenge.example.com"``).
            value:  TXT record content (quoted automatically as Route 53 requires).
        """
        async with httpx.AsyncClient() as client:
            zone_id = await self._zone_id(client, domain)
            path = f"/2013-04-01/hostedzone/{zone_id}/rrset"
            body = self._change_xml("CREATE", name, [f'"{value}"'])
            r = await client.post(
                f"{_BASE}{path}",
                content=body,
                headers={**self._auth("POST", path, "", body), "Content-Type": "text/xml"},
            )
            if not r.is_success:
                log.error("Route53 set_txt error %s: %s", r.status_code, r.text)
            r.raise_for_status()
        log.debug("Route53: created TXT %s on %s", name, domain)

    async def delete_txt(self, domain: str, name: str) -> None:
        """Delete TXT records matching *name* on Route 53.

        Fetches the current record set to obtain exact values, which Route 53
        requires for the DELETE action.

        Args:
            domain: Apex domain.
            name:   Full record name to remove.
        """
        async with httpx.AsyncClient() as client:
            zone_id = await self._zone_id(client, domain)
            rrset_path = f"/2013-04-01/hostedzone/{zone_id}/rrset"
            list_params = {"maxitems": "1", "name": name, "type": "TXT"}
            list_query = _canonical_qs(list_params)
            r = await client.get(
                f"{_BASE}{rrset_path}?{list_query}",
                headers=self._auth("GET", rrset_path, list_query),
            )
            r.raise_for_status()
            root = ElementTree.fromstring(r.text)  # noqa: S314
            rrs = root.find(f".//{{{_NS}}}ResourceRecordSet")
            if rrs is None:
                log.debug("Route53: no TXT records found for %s", name)
                return
            rrset_name = (rrs.findtext(f"{{{_NS}}}Name") or "").rstrip(".")
            if rrset_name.lower() != name.lower():
                log.debug("Route53: no TXT records found for %s", name)
                return
            values = [
                el.text or "" for el in rrs.findall(f".//{{{_NS}}}ResourceRecord/{{{_NS}}}Value")
            ]
            body = self._change_xml("DELETE", name, values)
            r2 = await client.post(
                f"{_BASE}{rrset_path}",
                content=body,
                headers={**self._auth("POST", rrset_path, "", body), "Content-Type": "text/xml"},
            )
            if not r2.is_success:
                log.error("Route53 delete_txt error %s: %s", r2.status_code, r2.text)
            r2.raise_for_status()
        log.debug("Route53: deleted TXT %s", name)
