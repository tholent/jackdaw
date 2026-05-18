# Jackdaw — Project Handoff Document

## Overview

**Jackdaw** is a self-hosted ACME protocol relay that acts as a certificate authority
to internal clients while proxying real certificate issuance to Let's Encrypt via
DNS-01 challenges. Internal clients use any standard ACME client (certbot, acme.sh,
Caddy, npm, etc.) pointed at Jackdaw's URL — Jackdaw handles all LE interaction
transparently, returning publicly trusted certificates. The DNS provider used for
DNS-01 challenge fulfilment is pluggable; Porkbun ships as the first implementation.

```
Internal Client (certbot / acme.sh / Caddy / NPM)
    │  Standard ACMEv2 (RFC 8555) over HTTPS
    ▼
┌──────────────────────────────────────────────────────┐
│                     Jackdaw                          │
│                                                      │
│  FastAPI ACME Server          gufo-acme LE Client    │
│  ┌──────────────────┐         ┌──────────────────┐   │
│  │  /directory      │         │  newOrder → LE   │   │
│  │  /nonce          │────────▶│  DNS-01 fulfil   │   │
│  │  /newAccount     │         │  finalize → LE   │   │
│  │  /newOrder       │         │  fetch cert      │   │
│  │  /authz/{id}     │         └────────┬─────────┘   │
│  │  /challenge/{id} │                  │              │
│  │  /order/{id}     │    ┌─────────────▼──────────┐  │
│  │  /cert/{id}      │    │    DNSProvider (ABC)    │  │
│  └──────────────────┘    │  set_txt / delete_txt   │  │
│                          └─────────────┬───────────┘  │
│                    ┌────────────────────┼────────────┐ │
│                    ▼                   ▼             ▼ │
│             PorkbunProvider    CloudflareProvider  ...  │
│  SQLite (orders / accounts / certs / nonces)           │
└──────────────────────────────────────────────────────┘
    │  ACMEv2 + DNS-01 via configured provider
    ▼
Let's Encrypt
```

---

## Goals & Non-Goals

### Goals
- Full ACMEv2 (RFC 8555) server compliance for the client-facing side
- Any subdomain of configured domain(s) can be requested
- DNS-01 only (relay handles challenge; client does nothing with it)
- Pluggable DNS provider architecture; Porkbun ships as the first implementation
- Publicly trusted certs (issued by Let's Encrypt, not a private CA)
- Docker image; configured entirely via environment variables
- No private key material for the end cert ever touches the relay (client generates CSR)

### Non-Goals (v1)
- HTTP-01 or TLS-ALPN-01 challenge support
- External Account Binding (EAB / client authentication)
- Certificate revocation (OCSP/CRL)
- Account key rollover
- Clustering / HA (single instance with SQLite)

---

## Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.12 | Specified |
| Web framework | FastAPI | Async-native, auto OpenAPI docs, Pydantic validation |
| Data validation | Pydantic v2 | Specified; models ACME request/response payloads |
| LE client | `gufo-acme` | Pure Python, asyncio-native, fully typed, actively maintained |
| Crypto | `cryptography` (PyCA) | JWS, nonce signing, CSR handling |
| DNS providers | Pluggable via `DNSProvider` ABC; Porkbun built-in | `httpx` for async HTTP; new providers need only two methods |
| Database | SQLite via `aiosqlite` + `SQLAlchemy` async | Simple, single-file, zero-ops |
| TLS termination | nginx (sidecar container) | Handles HTTPS for FastAPI; bootstraps Jackdaw's own cert |
| Container | Docker + Docker Compose | Specified |
| Process manager | `uvicorn` | Standard FastAPI runner |
| Dependency management | `uv` | Fast, lockfile-based, replaces pip + venv + pip-tools |
| Testing | `pytest` + `pytest-asyncio` + `pebble` | Pebble is LE's own ACME test CA |
| Linting | `ruff` | Single tool replacing flake8 + isort + pyupgrade |
| Type checking | `mypy` | Static analysis; strict mode enforced in CI |

---

## Repository Layout

```
jackdaw/
├── docker-compose.yml
├── Dockerfile
├── nginx/
│   ├── nginx.conf
│   └── bootstrap/            # Temp self-signed cert used before LE cert exists
├── pyproject.toml            # Single source of truth: deps, ruff, mypy, pytest config
├── uv.lock                   # Committed lockfile; guarantees reproducible installs
├── src/
│   └── jackdaw/
│       ├── main.py           # FastAPI app, lifespan, router registration
│       ├── config.py         # Settings (Pydantic BaseSettings, env vars)
│       ├── db/
│       │   ├── engine.py     # aiosqlite engine + session factory
│       │   └── models.py     # SQLAlchemy ORM models
│       ├── routes/
│       │   ├── directory.py  # GET /directory
│       │   ├── nonce.py      # HEAD+POST /nonce
│       │   ├── account.py    # POST /newAccount
│       │   ├── order.py      # POST /newOrder, GET /order/{id}, POST /order/{id}/finalize
│       │   ├── authz.py      # GET /authz/{id}
│       │   ├── challenge.py  # POST /challenge/{id}
│       │   └── cert.py       # GET /cert/{id}
│       ├── dns/
│       │   ├── base.py       # DNSProvider abstract base class
│       │   ├── loader.py     # get_provider(name) -> DNSProvider
│       │   └── providers/
│       │       ├── __init__.py
│       │       ├── porkbun.py    # PorkbunDNSProvider
│       │       └── cloudflare.py # CloudflareDNSProvider (stub / future)
│       ├── services/
│       │   ├── nonce.py      # Nonce generation + validation (in-memory + DB)
│       │   ├── jws.py        # JWS verification (client request signatures)
│       │   ├── le_client.py  # gufo-acme wrapper; newOrder → DNS-01 → finalize
│       │   └── cert_store.py # Store + retrieve issued certs
│       ├── schemas/
│       │   └── acme.py       # Pydantic models for all ACME payloads
│       └── worker.py         # Background task: poll pending orders, retry logic
├── tests/
│   ├── conftest.py           # Pebble fixture, test DB
│   ├── test_directory.py
│   ├── test_nonce.py
│   ├── test_account.py
│   ├── test_order_flow.py    # Full happy path via pebble
│   └── test_dns_provider.py  # DNSProvider mock tests (provider-agnostic)
├── pyproject.toml
└── .env.example
```

---

## ACME Protocol Flow (Detailed)

This is the sequence the relay must correctly implement server-side. Understanding
this fully is the key to a correct implementation.

```
Client                    Jackdaw (FastAPI)               Let's Encrypt (gufo-acme)
  │                            │                                │
  │── HEAD /nonce ────────────▶│                                │
  │◀─ 200 (Replay-Nonce hdr) ──│                                │
  │                            │                                │
  │── POST /newAccount ────────▶│ (JWS-signed)                 │
  │   {termsOfServiceAgreed}   │ verify JWS sig                │
  │                            │ create account record          │
  │◀─ 201 account obj ─────────│                                │
  │                            │                                │
  │── POST /newOrder ──────────▶│ (JWS-signed)                 │
  │   {identifiers: [dns:x]}   │ verify JWS sig                │
  │                            │ create Order + Authz records   │
  │                            │── newOrder ───────────────────▶│
  │                            │◀─ LE order + authz urls ───────│
  │◀─ 201 order obj ───────────│                                │
  │   {status:pending,         │                                │
  │    authorizations:[url]}   │                                │
  │                            │                                │
  │── GET /authz/{id} ─────────▶│                               │
  │◀─ authz obj ───────────────│                                │
  │   {challenges:[            │                                │
  │     {type:dns-01,          │                                │
  │      token:XYZ,            │  (token is relay-generated;    │
  │      url:/challenge/{id}}  │   client never uses it)        │
  │   ]}                       │                                │
  │                            │                                │
  │── POST /challenge/{id} ────▶│ (client signals "ready")     │
  │   {} (empty payload)       │                                │
  │                            │ [background task kicks off]    │
  │                            │── fulfill DNS-01 ─────────────▶Porkbun API
  │                            │   (set _acme-challenge TXT)    │
  │                            │── notify LE challenge ready ──▶│
  │                            │◀─ LE polls DNS, validates ─────│
  │                            │── delete TXT record ──────────▶Porkbun API
  │                            │                                │
  │── GET /order/{id} ─────────▶│ (client polls)               │
  │◀─ {status:ready} ──────────│                                │
  │                            │                                │
  │── POST /order/{id}/finalize▶│ (JWS-signed)                 │
  │   {csr: <base64url DER>}   │ verify JWS + CSR              │
  │                            │── finalize(CSR) ──────────────▶│
  │                            │◀─ signed cert (PEM chain) ─────│
  │                            │ store cert, mark order valid   │
  │◀─ {status:valid,           │                                │
  │    certificate: url} ──────│                                │
  │                            │                                │
  │── GET /cert/{id} ──────────▶│                               │
  │◀─ PEM cert chain ──────────│                                │
```

### Key Protocol Constraints

- **Every request except GET /directory and HEAD /nonce must be JWS-signed** by the
  client's account key. The relay must verify every signature.
- **Nonces are single-use.** The relay issues a fresh nonce in the `Replay-Nonce`
  response header on every request, and must reject reused nonces.
- **Content-Type for POST requests must be** `application/jose+json`.
- **Responses must include a `Replay-Nonce` header** on all POST responses.
- **The `Link` header** must point to the directory URL on relevant responses.
- **Order and authz resources must be pollable** — clients retry GET on these URLs
  until status transitions (pending → ready → valid).

---

## Data Model

### `accounts` table
```
id            TEXT PRIMARY KEY  (UUID)
public_key    TEXT NOT NULL     (JWK JSON)
contact       TEXT              (email, JSON array)
status        TEXT              (valid / deactivated)
created_at    DATETIME
```

### `orders` table
```
id            TEXT PRIMARY KEY  (UUID)
account_id    TEXT FOREIGN KEY
status        TEXT              (pending / ready / processing / valid / invalid)
identifiers   TEXT              (JSON: [{type,value}])
le_order_url  TEXT              (LE's order URL, stored for finalization)
cert_id       TEXT FOREIGN KEY  (set when valid)
expires_at    DATETIME
created_at    DATETIME
```

### `authorizations` table
```
id            TEXT PRIMARY KEY  (UUID)
order_id      TEXT FOREIGN KEY
identifier    TEXT              (domain name)
status        TEXT              (pending / valid / invalid)
challenge_token TEXT            (random token issued to client)
le_authz_url  TEXT              (LE's authz URL)
created_at    DATETIME
```

### `certificates` table
```
id            TEXT PRIMARY KEY  (UUID)
order_id      TEXT FOREIGN KEY
pem_chain     TEXT              (full chain PEM)
issued_at     DATETIME
expires_at    DATETIME
```

### `nonces` table
```
value         TEXT PRIMARY KEY
used          BOOLEAN DEFAULT FALSE
created_at    DATETIME
```
Nonces expire after 10 minutes whether used or not. A background task prunes them.

---

## Services Detail

### `jws.py` — JWS Verification
All client POST bodies are JWS (JSON Web Signature) objects. This service:
- Decodes the protected header to extract `alg`, `nonce`, `url`, `jwk`/`kid`
- Verifies the nonce is valid and unused, then marks it used
- Verifies the URL matches the request URL (anti-replay)
- Verifies the signature against the account's public key
- Returns the decoded payload

Library: `cryptography` (PyCA) + `josepy` (used by certbot, well-tested JWS/JWK handling)

### `dns/base.py` — DNSProvider Abstract Base Class

```python
from abc import ABC, abstractmethod

class DNSProvider(ABC):

    @abstractmethod
    async def set_txt(self, domain: str, name: str, value: str) -> None:
        """
        Create a DNS TXT record.

        domain: registered apex domain (e.g. 'example.com')
        name:   full record name (e.g. '_acme-challenge.host.example.com')
        value:  base64url-encoded SHA-256 digest of the key authorization
        """
        ...

    @abstractmethod
    async def delete_txt(self, domain: str, name: str) -> None:
        """Remove the TXT record after LE has validated the challenge."""
        ...
```

The `le_client.py` service depends only on this interface. No route, worker, or
service module imports any concrete provider class directly.

### `dns/loader.py` — Provider Registry

```python
import importlib
from jackdaw.dns.base import DNSProvider

_REGISTRY: dict[str, str] = {
    "porkbun":    "jackdaw.dns.providers.porkbun.PorkbunDNSProvider",
    "cloudflare": "jackdaw.dns.providers.cloudflare.CloudflareDNSProvider",
}

def get_provider(name: str) -> DNSProvider:
    if name not in _REGISTRY:
        raise ValueError(
            f"Unknown DNS provider: {name!r}. Available: {sorted(_REGISTRY)}"
        )
    module_path, class_name = _REGISTRY[name].rsplit(".", 1)
    module = importlib.import_module(module_path)
    cls = getattr(module, class_name)
    return cls()  # each provider reads its own env vars in __init__
```

The provider is instantiated once at app startup (lifespan) and injected into the
worker via FastAPI dependency injection.

### `dns/providers/porkbun.py` — Porkbun Implementation

Each provider's `__init__` uses a nested Pydantic `BaseSettings` model to read its
own env vars — unconfigured providers do not fail at startup unless selected.

```python
from pydantic_settings import BaseSettings
from jackdaw.dns.base import DNSProvider
import httpx

class _PorkbunSettings(BaseSettings):
    api_key: str
    secret_api_key: str

    model_config = {"env_prefix": "PORKBUN_"}

class PorkbunDNSProvider(DNSProvider):
    BASE_URL = "https://api.porkbun.com/api/json/v3"

    def __init__(self) -> None:
        s = _PorkbunSettings()
        self._auth = {"apikey": s.api_key, "secretapikey": s.secret_api_key}

    async def set_txt(self, domain: str, name: str, value: str) -> None:
        subdomain = name.removesuffix(f".{domain}")
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{self.BASE_URL}/dns/create/{domain}",
                json={**self._auth, "name": subdomain,
                      "type": "TXT", "content": value, "ttl": "120"},
            )
            r.raise_for_status()

    async def delete_txt(self, domain: str, name: str) -> None:
        # Retrieve record ID then delete by ID
        subdomain = name.removesuffix(f".{domain}")
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{self.BASE_URL}/dns/retrieveByNameType/{domain}/TXT/{subdomain}",
                json=self._auth,
            )
            r.raise_for_status()
            records = r.json().get("records", [])
            for record in records:
                await client.post(
                    f"{self.BASE_URL}/dns/delete/{domain}/{record['id']}",
                    json=self._auth,
                )
```

### Adding a New Provider

To add a provider a contributor needs to:

1. Create `src/jackdaw/dns/providers/newprovider.py` implementing `DNSProvider`
2. Add one entry to `_REGISTRY` in `loader.py`
3. Document the required env vars (following the `env_prefix` pattern)

No changes to routes, worker, schemas, or any other module.

### `le_client.py` — gufo-acme Wrapper
The relay maintains a **single shared LE account** (keypair stored in a volume-mounted
file). This service:
- Initializes `AcmeClient` with the LE directory URL
- Creates/loads the LE account on startup (lifespan event)
- On order finalization: calls `client.sign(domain, csr_der)` with a subclassed client
  that overrides `fulfill_dns_01` to call `dns_solver.set_txt`
- Returns the issued PEM cert chain

### `worker.py` — Background Order Processor
When a client POSTs to `/challenge/{id}`, the relay marks the challenge as triggered
and queues the DNS-01 work as an `asyncio` background task. The worker:
1. Calls `dns_solver.set_txt`
2. Waits for propagation
3. Notifies LE the challenge is ready
4. Polls LE until authz is valid
5. Marks the relay's authz + order as ready
6. On finalize: submits CSR, fetches cert, stores it, marks order valid

---

## Configuration (Environment Variables)

```bash
# Required
DNS_PROVIDER=porkbun                    # selects the active provider
RELAY_DOMAIN=jackdaw.yourdomain.com        # the relay's own public hostname
ACME_EMAIL=admin@yourdomain.com         # LE account contact email

# Porkbun provider (required when DNS_PROVIDER=porkbun)
PORKBUN_API_KEY=pk1_...
PORKBUN_SECRET_API_KEY=sk1_...

# Cloudflare provider (required when DNS_PROVIDER=cloudflare)
# CLOUDFLARE_API_TOKEN=...

# Optional
LE_DIRECTORY=https://acme-v02.api.letsencrypt.org/directory
# Use staging for testing:
# LE_DIRECTORY=https://acme-staging-v02.api.letsencrypt.org/directory

DNS_PROPAGATION_WAIT=30                 # seconds to wait after setting TXT record
DATABASE_URL=sqlite+aiosqlite:///data/relay.db
LE_ACCOUNT_KEY_PATH=/data/le_account.key
NONCE_TTL=600                           # seconds before unused nonces expire
LOG_LEVEL=INFO
```

Each provider reads only its own env vars via a nested `BaseSettings` model with an
`env_prefix`. A provider that isn't selected never attempts to read its vars, so
missing keys for unselected providers do not cause startup failures.

---

## Docker Setup

### Dockerfile
```dockerfile
FROM python:3.12-slim

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Copy lockfile and project metadata first for layer caching
COPY pyproject.toml uv.lock ./

# Install dependencies from lockfile — no network calls at runtime
RUN uv sync --frozen --no-dev

COPY src/ src/

EXPOSE 8000
CMD ["uv", "run", "uvicorn", "jackdaw.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### docker-compose.yml
```yaml
services:
  jackdaw:
    build: .
    environment:
      - DNS_PROVIDER=${DNS_PROVIDER:-porkbun}
      - PORKBUN_API_KEY=${PORKBUN_API_KEY}
      - PORKBUN_SECRET_API_KEY=${PORKBUN_SECRET_API_KEY}
      - RELAY_DOMAIN=${RELAY_DOMAIN}
      - ACME_EMAIL=${ACME_EMAIL}
      - LE_DIRECTORY=${LE_DIRECTORY:-https://acme-v02.api.letsencrypt.org/directory}
    volumes:
      - jackdaw-data:/data
    expose:
      - "8000"
    depends_on:
      - nginx

  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - jackdaw-data:/data:ro        # nginx reads certs from same volume
    depends_on:
      - jackdaw

volumes:
  jackdaw-data:
```

### nginx.conf (sketch)
nginx terminates TLS and proxies to uvicorn. On first boot, a self-signed cert is
used (written into the volume by an init container or startup script). Once the relay
has bootstrapped its own cert from LE (by requesting one for `RELAY_DOMAIN`), nginx
is signaled to reload.

---

## Bootstrap Problem & Solution

Jackdaw needs a valid TLS cert to serve ACME to clients. But to get that cert it
needs to be running. This chicken-and-egg problem is solved in two phases:

**Phase 1 — First boot:**
1. An init script generates a self-signed cert and writes it to the data volume
2. nginx starts with the self-signed cert
3. Jackdaw starts and on lifespan startup, detects no LE cert exists for `RELAY_DOMAIN`
4. Jackdaw requests a cert for itself from LE (using its own DNS-01 solver against the configured provider)
5. The cert is written to the data volume
6. nginx is sent `SIGHUP` to reload

**Phase 2 — Normal operation:**
- The cert for `RELAY_DOMAIN` is renewed automatically (90-day LE cert, renewed at 60 days)
- nginx reloads after each renewal

---

## Security Considerations

- **No client authentication in v1** — any client that can reach Jackdaw can request
  a cert. Mitigate by network access controls (VPN, firewall rules) restricting who can
  reach port 443.
- **Domain policy** — optionally enforce that only subdomains of configured base domains
  can be requested. Prevents Jackdaw from being used for arbitrary domains.
- **DNS provider API keys** — grant full DNS control over your domain. Store in Docker
  secrets or a secrets manager in production, not plain env vars.
- **LE rate limits** — LE enforces 50 certs/domain/week. Jackdaw should track issuance
  and surface errors clearly. In a homelab context this is unlikely to be hit.
- **JWS replay protection** — nonce validation is critical and must be enforced strictly.
- **Jackdaw never sees client private keys** — clients generate their own keypair and
  send only the CSR. This is a fundamental ACME property and must be preserved.

---

## Testing Strategy

### Unit Tests
- `test_nonce.py` — issue, consume, reject reuse, reject expired
- `test_jws.py` — valid sig, wrong nonce, wrong URL, bad alg
- `test_dns_provider.py` — mock `DNSProvider`; verify `set_txt`/`delete_txt` called
  correctly by the worker regardless of provider. Porkbun-specific HTTP payload tests
  use `respx` to mock the Porkbun API.

### Integration Tests (against Pebble)
[Pebble](https://github.com/letsencrypt/pebble) is LE's own lightweight ACME test
server. Run as a Docker container in the test environment. It validates the full
protocol flow without hitting real LE or DNS.

```yaml
# docker-compose.test.yml
services:
  pebble:
    image: letsencrypt/pebble
    command: pebble -config /test/config/pebble-config.json
    environment:
      - PEBBLE_VA_NOSLEEP=1       # Skip DNS propagation wait in tests
      - PEBBLE_VA_ALWAYS_VALID=1  # Skip actual DNS validation
```

### End-to-End Test
Full flow with a real Porkbun test domain against LE staging:
```bash
certbot certonly \
  --server https://jackdaw.yourdomain.com/directory \
  --standalone \
  -d test.yourdomain.com \
  --email test@yourdomain.com \
  --agree-tos \
  --non-interactive
```

---

## Implementation Phases

### Phase 1 — Skeleton (Days 1–2)
- Repo structure, `pyproject.toml`, `uv.lock`, Docker setup
- Ruff, mypy, and pytest configured in `pyproject.toml`; CI runs all three
- `config.py` with Pydantic `BaseSettings`
- SQLAlchemy models + migrations
- FastAPI app with lifespan, `/directory` endpoint returning correct URLs
- Nonce endpoint (HEAD + POST /nonce), nonce service

### Phase 2 — ACME Server Core (Days 3–5)
- JWS verification service (`jws.py`)
- Account creation (`/newAccount`)
- Order creation (`/newOrder`) + authz generation
- Authz GET endpoint
- Challenge endpoint (accept client "ready" signal, queue background task)
- Order GET + finalize endpoints
- Cert GET endpoint

### Phase 3 — LE Integration (Days 6–7)
- `dns/base.py` abstract interface + `dns/loader.py` registry
- `dns/providers/porkbun.py` — Porkbun implementation with `_PorkbunSettings`
- `le_client.py` gufo-acme subclass with `fulfill_dns_01` delegating to `DNSProvider`
- Background worker wiring order status through the LE flow
- LE account bootstrap on startup

### Phase 4 — Docker + Bootstrap (Day 8)
- nginx config + self-signed bootstrap cert
- Init script for first-boot LE cert acquisition for relay domain
- nginx SIGHUP on cert renewal
- docker-compose finalization

### Phase 5 — Testing + Hardening (Days 9–10)
- Pebble integration tests
- Domain policy enforcement
- Error handling (LE errors, DNS provider errors, DNS timeout)
- Structured logging
- LE staging end-to-end test
- Mypy strict mode passing with zero errors
- Ruff clean with no suppressions in non-test code

---

## pyproject.toml

All tooling is configured in a single `pyproject.toml`. Dependencies are managed
by `uv`; the committed `uv.lock` ensures reproducible installs in both development
and Docker.

```toml
[project]
name = "jackdaw"
version = "0.1.0"
requires-python = ">=3.12"

dependencies = [
  "fastapi>=0.115",
  "uvicorn[standard]>=0.30",
  "pydantic>=2.7",
  "pydantic-settings>=2.3",
  "gufo-acme>=0.6",
  "josepy>=1.14",           # JWK/JWS handling (shared with certbot)
  "cryptography>=42",
  "httpx>=0.27",            # Async HTTP for DNS provider API calls
  "sqlalchemy[asyncio]>=2.0",
  "aiosqlite>=0.20",
]

[tool.uv]
dev-dependencies = [
  "pytest>=8",
  "pytest-asyncio>=0.23",
  "respx>=0.21",            # Mock httpx calls (DNS provider API mocks)
  "mypy>=1.10",
  "ruff>=0.4",
  "sqlalchemy[mypy]>=2.0",  # SQLAlchemy mypy plugin
]

# ---------------------------------------------------------------------------
# pytest
# ---------------------------------------------------------------------------
[tool.pytest.ini_options]
asyncio_mode = "auto"       # all async tests run without @pytest.mark.asyncio
testpaths = ["tests"]

# ---------------------------------------------------------------------------
# ruff
# ---------------------------------------------------------------------------
[tool.ruff]
target-version = "py312"
line-length = 100

[tool.ruff.lint]
select = [
  "E",    # pycodestyle errors
  "W",    # pycodestyle warnings
  "F",    # pyflakes
  "I",    # isort
  "UP",   # pyupgrade
  "B",    # flake8-bugbear
  "S",    # flake8-bandit (security)
  "ASYNC",# flake8-async
]
ignore = [
  "S101", # assert statements (fine in tests)
]

[tool.ruff.lint.per-file-ignores]
"tests/**" = ["S101", "S106"]

# ---------------------------------------------------------------------------
# mypy
# ---------------------------------------------------------------------------
[tool.mypy]
python_version = "3.12"
strict = true
plugins = ["pydantic.mypy", "sqlalchemy.ext.mypy.plugin"]

[[tool.mypy.overrides]]
module = ["gufo_acme.*", "josepy.*"]
ignore_missing_stubs = true
```

### Common uv Commands

```bash
# Initial setup — creates venv and installs all deps including dev
uv sync

# Add a runtime dependency
uv add httpx

# Add a dev-only dependency
uv add --dev pytest-cov

# Run a command in the project venv without activating it
uv run pytest
uv run mypy src/
uv run ruff check src/
uv run ruff format src/

# Update lockfile after changing pyproject.toml
uv lock

# Install in Docker (CI / production — no dev deps, frozen lockfile)
uv sync --frozen --no-dev
```

---

## Reference Links

- RFC 8555 (ACME): https://datatracker.ietf.org/doc/html/rfc8555
- gufo-acme docs: https://docs.gufolabs.com/gufo_acme/
- Porkbun API docs: https://porkbun.com/api/json/v3/documentation
- Pebble (LE test server): https://github.com/letsencrypt/pebble
- josepy (JWK/JWS): https://josepy.readthedocs.io/
- LE rate limits: https://letsencrypt.org/docs/rate-limits/
- LE staging environment: https://letsencrypt.org/docs/staging-environment/
- uv docs: https://docs.astral.sh/uv/
- ruff docs: https://docs.astral.sh/ruff/
- mypy docs: https://mypy.readthedocs.io/
- pytest-asyncio docs: https://pytest-asyncio.readthedocs.io/
