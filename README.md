# Jackdaw

[![Ruff](https://github.com/tholent/jackdaw/actions/workflows/ruff.yml/badge.svg)](https://github.com/tholent/jackdaw/actions/workflows/ruff.yml) [![Mypy](https://github.com/tholent/jackdaw/actions/workflows/mypy.yml/badge.svg)](https://github.com/tholent/jackdaw/actions/workflows/mypy.yml) [![Pytest](https://github.com/tholent/jackdaw/actions/workflows/pytest.yml/badge.svg)](https://github.com/tholent/jackdaw/actions/workflows/pytest.yml) [![Build](https://github.com/tholent/jackdaw/actions/workflows/ci.yml/badge.svg)](https://github.com/tholent/jackdaw/actions/workflows/ci.yml) [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=tholent_jackdaw&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=tholent_jackdaw) [![Coverage](https://sonarcloud.io/api/project_badges/measure?project=tholent_jackdaw&metric=coverage)](https://sonarcloud.io/summary/new_code?id=tholent_jackdaw)

A self-hosted ACME relay that lets internal clients obtain publicly trusted TLS
certificates from Let's Encrypt without needing direct DNS API access.

## Why

The standard way to automate TLS certificates for internal services is to run
an ACME client (certbot, acme.sh, Caddy, etc.) on each host and let it talk
directly to Let's Encrypt. This works well in public infrastructure, but breaks
down in a few common scenarios:

- **Centralised DNS credentials.** DNS-01 challenges require API keys for your
  DNS provider. Distributing those keys to every host that needs a certificate
  is a poor security posture — any compromise of any host exposes your entire
  DNS zone.

- **Internal or air-gapped hosts.** Hosts that cannot reach Let's Encrypt
  directly, or that should not be individually registered with LE, need a
  proxy.

- **Wildcard certificates.** DNS-01 is the only challenge type that can issue
  wildcard certificates. Jackdaw centralises that capability.

Jackdaw solves this by acting as a standard ACME server for your internal
clients while proxying real certificate issuance to Let's Encrypt. Clients
point their ACME client at Jackdaw's URL and receive publicly trusted
certificates — they never see a DNS API key, and Jackdaw is the only host
that needs LE connectivity.

## How it works

Jackdaw is a **two-leg ACME bridge**:

```
Internal client (certbot / acme.sh / Caddy / any ACME client)
    │  Leg 1 — Standard ACMEv2 HTTP-01 (RFC 8555) over HTTPS
    │  Client serves /.well-known/acme-challenge/<token> on :80
    ▼
┌─────────────────────────────────────────────────────────┐
│                        Jackdaw                          │
│                                                         │
│  FastAPI ACME server          gufo-acme LE client       │
│  /directory                   new-order → LE            │
│  /nonce          Leg 1 ──▶    DNS-01 fulfillment        │
│  /newAccount     HTTP-01      finalize → LE             │
│  /newOrder       validation   fetch cert ← LE           │
│  /authz/{id}                       │                    │
│  /challenge/{id}          DNS provider (pluggable)      │
│  /order/{id}              set_txt / delete_txt          │
│  /cert/{id}                        │                    │
│  SQLite (orders / accounts / certs / nonces)            │
└─────────────────────────────────────────────────────────┘
    │  Leg 2 — ACMEv2 + DNS-01
    ▼
Let's Encrypt  ──▶  Porkbun / Cloudflare / ...
```

**Leg 1 (client ↔ Jackdaw):** standard ACME HTTP-01. The client serves a
challenge token at `http://<domain>/.well-known/acme-challenge/<token>`.
Jackdaw fetches it over the internal network and verifies the key authorization
before advancing the order. Any ACME client (certbot, acme.sh, Caddy) works
unmodified — just point it at Jackdaw's directory URL.

**Leg 2 (Jackdaw ↔ Let's Encrypt):** DNS-01, using the relay's centralised
DNS provider credentials. The client never needs DNS API access.

> **Important:** client domains must be reachable from the relay over HTTP on
> port 80 (configurable via `CHALLENGE_HTTP_PORT`) at the time a certificate
> is requested. The relay validates from its own vantage point using the
> internal DNS resolver.

The relay maintains a **single shared Let's Encrypt account** and handles all
DNS-01 challenge fulfillment. Clients generate their own keypairs and CSRs —
private key material for issued certificates never touches Jackdaw.

## Requirements

- Docker and Docker Compose
- A registered domain you control, with DNS hosted at a [supported provider](#dns-providers)
- API credentials for that DNS provider

## Quick start

```bash
git clone https://github.com/yourname/jackdaw
cd jackdaw
cp .env.example .env
```

Edit `.env` and fill in the required values:

```bash
# The public hostname this relay will be reachable at
RELAY_DOMAIN=jackdaw.example.com

# Let's Encrypt contact email
ACME_EMAIL=admin@example.com

# DNS provider and credentials
DNS_PROVIDER=porkbun
PORKBUN_API_KEY=pk1_...
PORKBUN_SECRET_API_KEY=sk1_...
```

Then start the stack:

```bash
docker compose up -d
```

On first boot Jackdaw goes through a self-bootstrapping sequence:

1. Jackdaw registers a Let's Encrypt account and requests a certificate for
   `RELAY_DOMAIN` using its own DNS-01 solver. The public HTTPS listener stays
   offline until that certificate is on disk — there is no self-signed
   placeholder, so clients see a clean "connection refused" rather than a TLS
   error while issuance is in flight.
2. Jackdaw then terminates TLS itself and serves the ACME API directly on
   port 443. If issuance fails (bad DNS credentials, propagation issues), it
   retries with backoff and logs each attempt.

The relay is ready once `GET https://jackdaw.example.com/directory` returns
200. Check progress with `docker compose logs -f jackdaw`.

## Pointing a client at the relay

Any RFC 8555-compliant ACME client works. Point it at Jackdaw's directory URL
and configure it to use **HTTP-01** challenge validation. Jackdaw validates
HTTP-01 from its own vantage point (over the internal network) before
forwarding to Let's Encrypt via DNS-01 — clients never need DNS API access.

> **Prerequisite:** the client's domain must be resolvable from the relay over
> HTTP on port 80 at issuance time. This is standard for internal services on
> the same network as the relay.

**certbot**
```bash
certbot certonly \
  --server https://jackdaw.example.com/directory \
  --standalone \
  -d myservice.example.com \
  --email admin@example.com \
  --agree-tos --non-interactive
```
_(`--standalone` starts a temporary HTTP server on :80 to serve the challenge.)_

**acme.sh**
```bash
acme.sh --issue \
  --server https://jackdaw.example.com/directory \
  -d myservice.example.com \
  --standalone
```

**Caddy** (`Caddyfile`)
```
myservice.example.com {
    acme_ca https://jackdaw.example.com/directory
    reverse_proxy localhost:8080
}
```
_(Caddy handles HTTP-01 automatically when it is already serving the domain.)_

## Configuration

All configuration is via environment variables. Copy `.env.example` for a
complete reference.

| Variable | Required | Default | Description |
|---|---|---|---|
| `RELAY_DOMAIN` | Yes | — | Public hostname of this relay |
| `ACME_EMAIL` | Yes | — | Let's Encrypt account contact email |
| `DNS_PROVIDER` | Yes | — | `porkbun`, `cloudflare`, `route53`, `namecheap`, or `null` |
| `PORKBUN_API_KEY` | Porkbun | — | Porkbun API key |
| `PORKBUN_SECRET_API_KEY` | Porkbun | — | Porkbun secret API key |
| `CLOUDFLARE_API_TOKEN` | Cloudflare | — | Cloudflare API token |
| `AWS_ACCESS_KEY_ID` | Route 53 | — | AWS access key ID |
| `AWS_SECRET_ACCESS_KEY` | Route 53 | — | AWS secret access key |
| `AWS_SESSION_TOKEN` | No | — | AWS session token (for temporary IAM credentials) |
| `NAMECHEAP_API_USER` | Namecheap | — | Namecheap API user |
| `NAMECHEAP_API_KEY` | Namecheap | — | Namecheap API key |
| `NAMECHEAP_CLIENT_IP` | Namecheap | — | Whitelisted client IP for Namecheap API access |
| `NAMECHEAP_USERNAME` | No | `NAMECHEAP_API_USER` | Namecheap account username |
| `LE_DIRECTORY` | No | LE production | Let's Encrypt directory URL |
| `DNS_PROPAGATION_WAIT` | No | `30` | Seconds to wait after setting TXT record |
| `ALLOWED_DOMAINS` | No | _(all)_ | Comma-separated base domains for extra restriction; HTTP-01 proof is always required |
| `LOG_LEVEL` | No | `INFO` | `DEBUG`, `INFO`, `WARNING`, or `ERROR` |
| `CHALLENGE_HTTP_PORT` | No | `80` | Port the relay connects to on the client for HTTP-01 validation |
| `CHALLENGE_TIMEOUT` | No | `5` | Seconds before an HTTP-01 fetch attempt times out |
| `CHALLENGE_RETRIES` | No | `3` | Number of fetch attempts before failing the challenge |
| `CHALLENGE_RETRY_DELAY` | No | `2` | Seconds between retry attempts |
| `DATABASE_URL` | No | `sqlite+aiosqlite:////data/relay.db` | SQLite path; must point at a persistent volume. Override when running outside Docker |
| `SERVE_TLS` | No | `true` | Terminate TLS on port 443. Set `false` to serve plain HTTP on port 8000 (tests, or behind an external TLS proxy) |
| `DNS_ZONE_OVERRIDES` | No | _(none)_ | Comma-separated apex zones for multi-label TLDs (e.g. `example.co.uk`) |
| `ORDER_RATE_LIMIT` | No | `0` | Max orders per account within the window; `0` disables |
| `ORDER_RATE_WINDOW` | No | `604800` | Rate-limit window in seconds (default 7 days) |

Orders that are not finalized within **24 hours** expire and can no longer be
completed (the client must submit a fresh order). This expiry is currently
fixed. See `.env.example` for the complete list of settings.

### Restricting which domains can be issued

HTTP-01 proof of control is always enforced — it is the primary authorization
gate. `ALLOWED_DOMAINS` is an optional additional restriction: set it to limit
issuance to specific base domains and their subdomains:

```bash
ALLOWED_DOMAINS=example.com,example.org
```

Requests for domains outside the allowlist are rejected with an ACME
`rejectedIdentifier` error.

### Rate limiting

By default any authorized client can create unlimited orders. To guard against
exhausting Let's Encrypt's own [rate limits](#security-notes), set a per-account
cap:

```bash
ORDER_RATE_LIMIT=50        # max orders per account within the window
ORDER_RATE_WINDOW=604800   # window in seconds (default: 7 days)
```

When an account exceeds the cap, further orders are rejected with an ACME
`rateLimited` error (HTTP 429). `ORDER_RATE_LIMIT=0` (the default) disables the
check.

### Multi-label TLDs

Jackdaw derives the DNS zone for a domain from its last two labels
(`sub.example.com` → `example.com`). For domains registered under a multi-label
public suffix — e.g. `example.co.uk` — list the apex zones explicitly so the
`_acme-challenge` record is written to the correct zone:

```bash
DNS_ZONE_OVERRIDES=example.co.uk,example.com.au
```

The longest configured zone a domain falls under wins; domains matching no
override fall back to the last-two-labels heuristic.

### Using Let's Encrypt staging

During initial setup, use the LE staging environment to avoid hitting
production rate limits:

```bash
LE_DIRECTORY=https://acme-staging-v02.api.letsencrypt.org/directory
```

Staging issues "Fake LE" certificates that are not publicly trusted but go
through the same protocol flow as production. Switch to the production URL
once everything is working.

## Certificate renewal

**Relay certificate** (`RELAY_DOMAIN`): renewed automatically. A background
task checks daily and renews when fewer than 30 days remain; the live TLS
context is reloaded in place, so new connections pick up the renewed
certificate without a restart.

**Client certificates**: renewal is the responsibility of each client's ACME
implementation — certbot's systemd timer, Caddy's built-in renewal, etc.
Jackdaw behaves identically to any other ACME server from the client's
perspective.

## Health checks

The relay exposes an unauthenticated liveness endpoint at **`GET /healthz`**
that returns `200 OK` when the app is up — the endpoint to point external load
balancers or uptime monitors at. It performs no dependency checks — it only
confirms the process is serving requests.

Inside the container a plain-HTTP copy of the liveness endpoint is also served
on `127.0.0.1:8000`; the bundled `docker-compose.yml` healthcheck uses it so
the container reports healthy from process start, including while the
first-boot certificate issuance still has the public HTTPS listener offline.

The relay also exposes **`GET /version`**, which returns the running release as
`{"version": "X.Y.Z"}` — handy for confirming which image is deployed.

## Versioning & Releasing

Jackdaw follows [Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`,
where a **MAJOR** bump signals a breaking change, **MINOR** adds functionality in
a backward-compatible way, and **PATCH** is a backward-compatible bug fix. The
version lives in one place — `pyproject.toml` — and the running app reports it via
`jackdaw.__version__` and the `GET /version` endpoint.

Releases are cut from git tags named `vX.Y.Z`. Pushing such a tag triggers the
[`Release`](.github/workflows/release.yml) workflow, which builds the Docker image
and publishes it to `ghcr.io/tholent/jackdaw` with the tags `X.Y.Z`, `X.Y`,
`latest`, and `sha-<commit>`. Ordinary branch and PR pushes never publish.

To cut a release:

```bash
# 1. Bump the version in pyproject.toml (and refresh the lockfile if needed)
uv lock
git commit -am "chore: release vX.Y.Z"

# 2. Tag it (the tag must match the pyproject.toml version, or the workflow fails)
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin main --tags
```

Pull the published image with:

```bash
docker pull ghcr.io/tholent/jackdaw:X.Y.Z
```

## DNS providers

| Provider | `DNS_PROVIDER` value | Status |
|---|---|---|
| [Porkbun](https://porkbun.com) | `porkbun` | Supported |
| [Cloudflare](https://cloudflare.com) | `cloudflare` | Supported |
| [Amazon Route 53](https://aws.amazon.com/route53/) | `route53` | Supported |
| [Namecheap](https://www.namecheap.com) | `namecheap` | Supported |
| _(none)_ | `null` | No-op provider for testing; skips DNS validation entirely |

### Adding a provider

The interface requires two methods. Create
`src/jackdaw/dns/providers/myprovider.py`:

```python
from pydantic_settings import BaseSettings
from jackdaw.dns.base import DNSProvider

class _Settings(BaseSettings):
    api_token: str
    model_config = {"env_prefix": "MYPROVIDER_", "env_file": ".env", "extra": "ignore"}

class MyProvider(DNSProvider):
    def __init__(self) -> None:
        self._token = _Settings().api_token

    async def set_txt(self, domain: str, name: str, value: str) -> None:
        ...  # create _acme-challenge TXT record via provider API

    async def delete_txt(self, domain: str, name: str) -> None:
        ...  # delete the TXT record
```

Then add one entry to `_REGISTRY` in `src/jackdaw/dns/loader.py`:

```python
"myprovider": "jackdaw.dns.providers.myprovider.MyProvider",
```

No other files need to change.

## Development

```bash
uv sync           # install all dependencies including dev tools
uv run pytest     # unit tests (no external services needed)
```

**Integration tests** against [Pebble](https://github.com/letsencrypt/pebble)
(Let's Encrypt's own lightweight test CA):

```bash
docker compose -f docker-compose.test.yml up -d pebble
uv run pytest tests/test_order_flow.py -v
```

**Linting and type checking:**

```bash
uv run ruff check src/ tests/
uv run ruff format src/ tests/
uv run mypy src/
```

CI runs all three on every push.

## Security notes

- **No client authentication.** Any client that can reach port 443 can request
  a certificate. Restrict access with firewall rules or a VPN — do not expose
  Jackdaw to the public internet unless `ALLOWED_DOMAINS` is set.
- **DNS API keys.** The configured provider credentials grant full control over
  your DNS zone. In production, use Docker secrets or a secrets manager rather
  than plain environment variables.
- **Client private keys never touch the relay.** Clients generate their own
  keypair and send only a CSR — this is a fundamental ACME property that the
  relay preserves.
- **Let's Encrypt rate limits.** LE enforces 50 certificates per registered
  domain per week. In a homelab context this is unlikely to be reached, and it
  surfaces as a clear error in the Jackdaw logs if it is. To proactively cap
  issuance per account, set `ORDER_RATE_LIMIT` (see [Rate limiting](#rate-limiting)).
