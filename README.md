# Jackdaw

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

```
Internal client (certbot / acme.sh / Caddy / any ACME client)
    │  Standard ACMEv2 (RFC 8555) over HTTPS
    ▼
┌─────────────────────────────────────────────────────────┐
│                        Jackdaw                          │
│                                                         │
│  FastAPI ACME server          gufo-acme LE client       │
│  /directory                   new-order → LE            │
│  /nonce                  ───▶ DNS-01 fulfillment        │
│  /newAccount                  finalize → LE             │
│  /newOrder                    fetch cert ← LE           │
│  /authz/{id}                       │                    │
│  /challenge/{id}          DNS provider (pluggable)      │
│  /order/{id}              set_txt / delete_txt          │
│  /cert/{id}                        │                    │
│  SQLite (orders / accounts / certs / nonces)            │
└─────────────────────────────────────────────────────────┘
    │  ACMEv2 + DNS-01
    ▼
Let's Encrypt  ──▶  Porkbun / Cloudflare / ...
```

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

1. An init container generates a self-signed certificate so nginx can start
   immediately.
2. Jackdaw registers a Let's Encrypt account and requests a real certificate
   for `RELAY_DOMAIN` using its own DNS-01 solver.
3. The certificate is written to the shared data volume and nginx reloads it
   via `SIGHUP`.

The relay is ready once `GET https://jackdaw.example.com/directory` returns
200. Check progress with `docker compose logs -f jackdaw`.

## Pointing a client at the relay

Any RFC 8555-compliant ACME client works. Pass the relay's directory URL as the
ACME server endpoint.

**certbot**
```bash
certbot certonly \
  --server https://jackdaw.example.com/directory \
  --manual --preferred-challenges dns \
  -d myservice.example.com \
  --email admin@example.com \
  --agree-tos --non-interactive \
  --manual-auth-hook /bin/true
```

**acme.sh**
```bash
acme.sh --issue \
  --server https://jackdaw.example.com/directory \
  -d myservice.example.com \
  --dns
```

**Caddy** (`Caddyfile`)
```
myservice.example.com {
    acme_ca https://jackdaw.example.com/directory
    reverse_proxy localhost:8080
}
```

## Configuration

All configuration is via environment variables. Copy `.env.example` for a
complete reference.

| Variable | Required | Default | Description |
|---|---|---|---|
| `RELAY_DOMAIN` | Yes | — | Public hostname of this relay |
| `ACME_EMAIL` | Yes | — | Let's Encrypt account contact email |
| `DNS_PROVIDER` | Yes | — | `porkbun` or `cloudflare` |
| `PORKBUN_API_KEY` | Porkbun | — | Porkbun API key |
| `PORKBUN_SECRET_API_KEY` | Porkbun | — | Porkbun secret API key |
| `CLOUDFLARE_API_TOKEN` | Cloudflare | — | Cloudflare API token |
| `LE_DIRECTORY` | No | LE production | Let's Encrypt directory URL |
| `DNS_PROPAGATION_WAIT` | No | `30` | Seconds to wait after setting TXT record |
| `ALLOWED_DOMAINS` | No | _(all)_ | Comma-separated base domains; empty means no restriction |
| `LOG_LEVEL` | No | `INFO` | `DEBUG`, `INFO`, `WARNING`, or `ERROR` |

### Restricting which domains can be issued

By default Jackdaw will issue certificates for any domain. Set
`ALLOWED_DOMAINS` to restrict issuance to specific base domains and their
subdomains:

```bash
ALLOWED_DOMAINS=example.com,example.org
```

Requests for domains outside the allowlist are rejected with an ACME
`rejectedIdentifier` error.

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
task checks daily and renews when fewer than 30 days remain, reloading nginx
after each renewal.

**Client certificates**: renewal is the responsibility of each client's ACME
implementation — certbot's systemd timer, Caddy's built-in renewal, etc.
Jackdaw behaves identically to any other ACME server from the client's
perspective.

## DNS providers

| Provider | `DNS_PROVIDER` value | Status |
|---|---|---|
| [Porkbun](https://porkbun.com) | `porkbun` | Supported |
| [Cloudflare](https://cloudflare.com) | `cloudflare` | Contributions welcome |

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
  domain per week. In a homelab context this is unlikely to be reached, but
  it will surface as a clear error in the Jackdaw logs if it is.
