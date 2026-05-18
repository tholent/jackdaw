# Jackdaw — Implementation Plan

## Approach

The implementation is split into four sequential phases. Within Phase 2 and Phase 3,
independent workstreams can be executed in parallel by separate agents. Each workstream
lists its inputs (what it depends on) and outputs (what later work depends on it).

---

## Phase 1 — Foundation (sequential, must complete before Phase 2)

All work here is tightly coupled; do it in order within a single agent.

### Tasks

1. **Repo skeleton**
   - Create directory tree matching the layout in the handoff doc
   - `src/jackdaw/__init__.py` and all sub-package `__init__.py` files

2. **`pyproject.toml`**
   - Copy the complete `[project]`, `[tool.uv]`, `[tool.pytest]`, `[tool.ruff]`, and
     `[tool.mypy]` blocks from the handoff doc verbatim
   - Run `uv sync` to generate `uv.lock`

3. **`.env.example`**
   - All env vars from the Configuration section of the handoff doc

4. **`src/jackdaw/config.py`**
   - Pydantic `BaseSettings` class exposing every env var in the Configuration section
   - Field defaults where the handoff doc shows defaults (e.g. `LE_DIRECTORY`, `DNS_PROPAGATION_WAIT`, `NONCE_TTL`, `LOG_LEVEL`)
   - A module-level `get_settings()` function cached with `@lru_cache`

5. **`src/jackdaw/db/models.py`**
   - SQLAlchemy 2.x mapped dataclasses (or `DeclarativeBase`) for all five tables:
     `accounts`, `orders`, `authorizations`, `certificates`, `nonces`
   - All column types exactly as specified in the Data Model section

6. **`src/jackdaw/db/engine.py`**
   - Async engine created from `settings.DATABASE_URL`
   - `AsyncSessionLocal` session factory
   - `init_db()` coroutine that calls `Base.metadata.create_all`

7. **`src/jackdaw/main.py`** (skeleton only — routes wired in Phase 3)
   - FastAPI app instance
   - Lifespan context manager that: calls `init_db()`, initialises the DNS provider
     via `get_provider()`, and initialises the LE account via `le_client.init_account()`
   - Placeholder router includes (routers themselves created in Phase 2/3)

### Phase 1 output
Installable package with `uv sync`, importable `jackdaw` module, empty DB created on
startup, no routes yet.

---

## Phase 2 — Parallel workstreams (run A, B, C simultaneously)

All three workstreams depend only on Phase 1 output. They do not depend on each other.

---

### Workstream A — ACME Schemas + Core Services + Simple Routes

**Depends on:** Phase 1 (config, db models)  
**Produces:** schemas module, nonce service, JWS service, directory/nonce/account routes

#### A1 — `src/jackdaw/schemas/acme.py`
Pydantic v2 models for every ACME request and response payload:
- `DirectoryResponse`
- `NewAccountRequest` / `AccountResponse`
- `NewOrderRequest` / `OrderResponse`
- `AuthzResponse` with nested `ChallengeObject`
- `FinalizeRequest`
- `CertResponse`
- JWS envelope model: `JWSEnvelope` with `protected`, `payload`, `signature` fields

#### A2 — `src/jackdaw/services/nonce.py`
- `generate_nonce() -> str` — cryptographically random, stores to DB with `created_at`
- `consume_nonce(value: str) -> None` — raises `HTTPException(400)` if not found, already
  used, or older than `NONCE_TTL` seconds; sets `used=True`
- `prune_nonces()` — deletes rows older than `NONCE_TTL` (called by background task in worker)

#### A3 — `src/jackdaw/services/jws.py`
Full JWS verification as described in the handoff doc:
- `verify_jws(request: Request, db: AsyncSession) -> tuple[dict, str]`
  Returns `(payload_dict, account_id)`.
- Uses `josepy` for JWK parsing and signature verification
- Calls `consume_nonce()`; verifies URL matches request URL
- On `newAccount` requests, the key is in `jwk` (no `kid` yet); on all others, `kid`
  is the account URL — resolve to the stored public key

#### A4 — `src/jackdaw/routes/directory.py`
`GET /directory` — returns `DirectoryResponse` with all endpoint URLs derived from
`settings.RELAY_DOMAIN`. No JWS required.

#### A5 — `src/jackdaw/routes/nonce.py`
- `HEAD /acme/new-nonce` → 200 with `Replay-Nonce` header
- `POST /acme/new-nonce` → 204 with `Replay-Nonce` header
Both call `generate_nonce()`.

#### A6 — `src/jackdaw/routes/account.py`
`POST /acme/new-account`:
- Verify JWS (via `verify_jws`)
- If account with this JWK already exists, return 200 + existing account
- Otherwise create account row, return 201 + `AccountResponse` with `Location` header

---

### Workstream B — DNS + LE Client

**Depends on:** Phase 1 (config)  
**Produces:** `DNSProvider` ABC, Porkbun + Cloudflare stub providers, loader, `le_client`

#### B1 — `src/jackdaw/dns/base.py`
Copy the `DNSProvider` ABC exactly from the handoff doc.

#### B2 — `src/jackdaw/dns/providers/porkbun.py`
Copy the `PorkbunDNSProvider` exactly from the handoff doc. The `delete_txt` method
must loop over all matching records and delete each by ID.

#### B3 — `src/jackdaw/dns/providers/cloudflare.py`
Stub implementation: `set_txt` and `delete_txt` both raise `NotImplementedError` with
a message explaining the provider is not yet implemented. Add a `CloudflareSettings`
placeholder with `env_prefix = "CLOUDFLARE_"` and an `api_token` field.

#### B4 — `src/jackdaw/dns/loader.py`
Copy the `get_provider()` registry function from the handoff doc verbatim.

#### B5 — `src/jackdaw/services/le_client.py`
- Subclass `gufo_acme.AcmeClient` and override `fulfill_dns_01` to call
  `dns_provider.set_txt(domain, name, value)`
- `init_account(dns_provider: DNSProvider) -> AcmeClient`:
  - Load or create the LE account key at `settings.LE_ACCOUNT_KEY_PATH`
  - Register the account with LE if it doesn't exist yet
  - Return the initialised client instance
- `order_cert(client: AcmeClient, domain: str, csr_der: bytes) -> str`:
  - Calls `client.sign(domain, csr_der)` (or equivalent gufo-acme API)
  - After `fulfill_dns_01`, sleeps `settings.DNS_PROPAGATION_WAIT` seconds before
    returning control to gufo-acme for LE validation
  - After LE validates, calls `dns_provider.delete_txt` to clean up the TXT record
  - Returns the PEM certificate chain

---

### Workstream C — Docker + nginx + Bootstrap

**Depends on:** Phase 1 (Dockerfile skeleton)  
**Produces:** Complete Docker setup, nginx config, bootstrap init script

#### C1 — `Dockerfile`
Copy from the handoff doc; no modifications needed.

#### C2 — `docker-compose.yml`
Copy from the handoff doc; no modifications needed.

#### C3 — `nginx/nginx.conf`
Full nginx config:
- Listens on 80 (redirect to 443) and 443
- TLS with cert path `/data/ssl/fullchain.pem` and key `/data/ssl/privkey.pem`
- Proxy pass to `http://jackdaw:8000`
- `proxy_set_header Host`, `X-Real-IP`, `X-Forwarded-Proto`

#### C4 — `nginx/bootstrap/generate-selfsigned.sh`
Shell script that uses `openssl` to write a self-signed cert to `/data/ssl/` if no
cert exists there. Runs as a Docker entrypoint init step before nginx starts.

#### C5 — `docker-compose.yml` init integration
Add an `init: true` + `command` override or a separate `init-certs` service that runs
the bootstrap script and exits before nginx starts (use `depends_on` + `condition: service_completed_successfully`).

---

## Phase 3 — Order Flow + Worker + Cert Routes

**Depends on:** Phase 2 (all three workstreams complete)

These tasks are mostly sequential within Phase 3 because routes depend on the worker
and cert_store. Tasks P3-A and P3-B can be done in parallel, then P3-C and P3-D are
sequential.

### P3-A — `src/jackdaw/services/cert_store.py`
- `store_cert(db, order_id, pem_chain, expires_at) -> str` — writes `certificates`
  row, returns cert UUID
- `get_cert(db, cert_id) -> str` — returns PEM chain or raises 404

### P3-B — Remaining ACME routes (can be parallelised with P3-A)

#### `src/jackdaw/routes/order.py`
- `POST /acme/new-order`: verify JWS → create `orders` + `authorizations` rows →
  return 201 `OrderResponse` with `Location` header
- `GET /acme/order/{id}`: fetch order row, return current status
- `POST /acme/order/{id}/finalize`: verify JWS → extract CSR from payload → if order
  not `ready` return 403 → enqueue `process_finalize` background task → return order

#### `src/jackdaw/routes/authz.py`
- `GET /acme/authz/{id}`: fetch authz + its challenge → return `AuthzResponse`

#### `src/jackdaw/routes/challenge.py`
- `POST /acme/challenge/{id}`: verify JWS → mark challenge triggered → launch
  `asyncio.create_task(worker.run_challenge(challenge_id))` → return challenge object

#### `src/jackdaw/routes/cert.py`
- `GET /acme/cert/{id}`: fetch cert via `cert_store.get_cert` → return PEM with
  `Content-Type: application/pem-certificate-chain`

### P3-C — `src/jackdaw/worker.py` (depends on P3-A and P3-B)

Two async task entry points:

1. `run_challenge(challenge_id, db, dns_provider, le_client)`:
   - Load authz + order rows
   - Call `le_client.order_cert(domain, csr_placeholder)` — wait for DNS validation
   - Update authz `status = valid`, order `status = ready`
   - The full cert issuance happens in `process_finalize`

2. `process_finalize(order_id, csr_der, db, dns_provider, le_client)`:
   - Update order `status = processing`
   - Call `le_client.order_cert(domain, csr_der)` for the actual finalization
   - Call `cert_store.store_cert()`, update order `cert_id` and `status = valid`
   - On any error: set order `status = invalid`, log

Background pruning: launch a recurring `asyncio` task in the lifespan to call
`nonce.prune_nonces()` every 60 seconds.

### P3-D — Wire routes into `main.py` (depends on P3-B)

Include all routers under the `/acme` prefix. Ensure every POST response includes
a fresh `Replay-Nonce` header (use a FastAPI middleware or response hook).

---

## Phase 4 — Tests + Hardening (sequential after Phase 3)

### T1 — `tests/conftest.py`
- Async SQLite test DB fixture (in-memory)
- `test_client` fixture using `httpx.AsyncClient` + `ASGITransport`
- Pebble service fixture (if running integration tests via `docker-compose.test.yml`)

### T2 — Unit tests (can run in parallel as separate files)

| File | What it tests |
|---|---|
| `tests/test_nonce.py` | issue, consume, reject reuse, reject expired |
| `tests/test_jws.py` | valid sig, wrong nonce, wrong URL, bad algorithm |
| `tests/test_directory.py` | GET /directory returns correct URL map |
| `tests/test_account.py` | new account creation, duplicate key returns 200 |
| `tests/test_dns_provider.py` | mock DNSProvider; Porkbun HTTP payloads via `respx` |

### T3 — `tests/test_order_flow.py`
Full happy-path integration test against Pebble:
1. GET /directory
2. HEAD /nonce
3. POST /newAccount
4. POST /newOrder
5. GET /authz/{id}
6. POST /challenge/{id}
7. Poll GET /order/{id} until `ready`
8. POST /order/{id}/finalize (with a real CSR generated in the test)
9. Poll GET /order/{id} until `valid`
10. GET /cert/{id} — assert PEM returned

### T4 — Hardening
- Domain policy: enforce `identifiers` are subdomains of `settings.ALLOWED_DOMAINS`
  (add `ALLOWED_DOMAINS` env var, comma-separated); reject with ACME error `rejectedIdentifier` if not
- Error handling: catch `httpx.HTTPError` in DNS providers, wrap in a loggable
  `DNSProviderError`; propagate to worker which sets order `invalid`
- Structured logging: use Python `logging` with JSON formatter when `LOG_LEVEL=INFO`

### T5 — CI / Quality gate
- `uv run ruff check src/ tests/` — zero errors
- `uv run mypy src/` — zero errors in strict mode
- `uv run pytest` — all tests pass

---

## Dependency Graph (summary)

```
Phase 1 (Foundation)
    │
    ├── Workstream A (Schemas, Services, Simple Routes)─────┐
    ├── Workstream B (DNS + LE Client)                      ├─▶ Phase 3 (Order Flow + Worker)
    └── Workstream C (Docker + nginx + Bootstrap)──(independent)     │
                                                                      ▼
                                                              Phase 4 (Tests + Hardening)
```

Workstream C (Docker) is fully independent of Phase 3 and can be merged at any time
after Phase 2-C completes. The critical path is Phase 1 → A+B (parallel) → Phase 3
→ Phase 4.

---

## Key Implementation Notes for the Agent

- **JWS `url` claim** — the value in `protected.url` must exactly match the full
  request URL including scheme. Build it from `str(request.url)`.
- **`Replay-Nonce` header** — must appear on *every* POST response, not just error
  responses. Use a middleware that appends a fresh nonce after the handler returns.
- **`Content-Type`** — all ACME POST requests must have `application/jose+json`.
  Return 415 otherwise.
- **`Link` header** — `<https://{RELAY_DOMAIN}/acme/directory>;rel="index"` must
  appear on all responses.
- **gufo-acme integration** — subclass `AcmeClient` and override the abstract method
  `dns_01` (check the gufo-acme source for the exact method name and signature; the
  handoff doc calls it `fulfill_dns_01`). The client takes care of all LE communication;
  the subclass only needs to set/delete the TXT record.
- **SQLAlchemy async** — always use `async with AsyncSessionLocal() as db` and
  `await db.commit()` after writes. Never use synchronous session methods.
- **Nonce in `newAccount`** — even for account creation, a valid nonce is required;
  do not skip nonce validation on this route.
- **Bootstrap self-renewal** — in the lifespan, after `init_account()`, check if a
  cert for `RELAY_DOMAIN` exists at `settings.LE_ACCOUNT_KEY_PATH` dir; if not,
  request one and write it to the data volume, then send `SIGHUP` to the nginx PID
  (read from `/var/run/nginx.pid`).
