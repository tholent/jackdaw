# Improvement & Execution Plan (IEP)

Goal: push Jackdaw from an overall **A−** to a solid **A** across all quality
axes (correctness, security, maintainability, testing, tooling).

Each phase independently raises the grade of its axis. Every fix lands with its
own regression test, and every phase ends with the full gate green:
`make ci` → ruff (lint + format), mypy strict, pytest.

## Status at a glance

| Phase | Axis | Target | Status |
|-------|------|--------|--------|
| 1 | Correctness | B+ → A | ✅ **Done** (merged to `main`, commit `04a5ca6`) |
| 2 | Security | A− → A | ✅ **Done** (merged to `main`, commit `afcc0e5`) |
| 3 | Maintainability | A− → A | ✅ **Done** (merged to `main`, commit `a069b85`) |
| 4 | Test coverage | A− → A | ✅ **Done** (coverage 92%, enforced floor 90%) |

---

## Phase 1 — Correctness: B+ → A  ✅ DONE

Merged to `main` (fast-forward, commit `04a5ca6`). Full suite: 196 passed,
1 skipped; ruff + mypy strict clean.

- **1.1 `CHALLENGE_HTTP_PORT` now honored** — `http01.py` builds the pinned-IP
  connection target with the configured port (IPv6 bracketed), not just the
  `Host` header. Previously any non-default port silently failed.
- **1.2 Multi-identifier orders made honest** — `_validate_identifiers`
  (`order.py`) rejects SAN orders with a `malformed` problem document.
  `run_challenge` (`worker.py`) only advances an order to `ready` once **all**
  its authorizations are valid (defensive invariant).
- **1.3 Datetime handling unified** — added `_util.utcnow()` (naive UTC) and
  routed nonce/order/account/cert-store writes and the rate-limit window
  through it, fixing the aware/naive boundary mismatch in the rate-limit query.
- **1.4 Real certificate expiry stored** — `worker.py` parses the leaf's
  `not_valid_after_utc` from the issued PEM (89-day estimate kept as a logged
  fallback).
- **1.5 Nits swept** — `_resolve_and_check` prefers IPv4 / falls back to IPv6 as
  documented while still SSRF-checking every resolved address; dropped the
  redundant `processing` re-set in `process_finalize` and a stray `json`
  re-import in `keychange.py`.

---

## Phase 2 — Security hardening: A− → A  ⬜

**2.1 Non-root container** — `Dockerfile`, `docker-compose.yml`
- Add a dedicated `jackdaw` user/group; `USER jackdaw`.
- Port 443 as non-root: add `NET_BIND_SERVICE` via `cap_add` in compose
  (recommended — no code change); document the alternative (listen high,
  publish `443:8443`).
- **Migration risk:** existing `/data` volumes are root-owned
  (`le_account.key` is 0600 root). Add an entrypoint chown step or a documented
  migration note in the CHANGELOG; verify the key/cert `chmod` calls still
  succeed as the new user.
- Verify end-to-end via the compose stack + Pebble (`docker-compose.test.yml`).

**2.2 Indexed serial lookup for revocation** — `models.py`, `revoke.py`,
`cert_store.py`
- Add `serial: Mapped[str | None]` (store as lowercase hex — SQLite integers
  can't hold 160-bit serials) with an index; populate it in `store_cert` by
  parsing the leaf.
- Rewrite the revoke lookup as a single `WHERE serial = :s AND account_id = :a`
  query; keep a fallback scan only for legacy NULL-serial rows, or backfill at
  startup.
- Schema/backfill mechanics land via the migration story from Phase 3.1.

**2.3 Bound unauthenticated nonce writes** — `main.py` (lighter touch)
- Full stateless HMAC nonces are over-engineering for an internal relay.
  Instead: skip nonce generation for non-ACME responses (`/healthz`,
  `/version`, `/directory` don't need `Replay-Nonce`), and add a cheap global
  cap — refuse to insert past N rows (evict-oldest or return nonce-less), with
  loud logging. Document the residual risk in the README deployment section.

---

## Phase 3 — Maintainability: A− → A  ⬜

**3.1 Adopt Alembic** — replaces the hand-rolled migration block in `engine.py`
- `alembic init` (async template); autogenerate an initial revision matching
  current models; a second revision adds `certificates.serial` (Phase 2.2) and
  backfills it.
- Startup: replace `init_db()`'s `create_all` + `_ensure_columns` with
  `alembic upgrade head` invoked programmatically; stamp pre-existing databases
  (detect via `PRAGMA` that tables exist but `alembic_version` doesn't → stamp
  baseline, then upgrade). Preserves the "just start the container" UX.
- Delete `_INDEX_STATEMENTS` / `_ADDED_COLUMNS`. Add a migration test: create a
  DB at the old schema, run startup, assert new columns/indexes exist.

**3.2 Contain the gufo-acme private-API surface** — `le_client.py`, `revoke.py`
- Pin `gufo-acme>=0.6,<0.7` in `pyproject.toml`.
- Add a public `revoke_cert(client, cert_b64, reason)` in `le_client.py` so the
  route stops calling `_get_directory`/`_post` directly — all underscore access
  then lives in one module, each use commented with why.
- Optional follow-up: upstream issues/PRs to gufo-acme for the Location-header
  capture and token-less challenge filtering so two of the three overrides can
  eventually be deleted.

**3.3 Extract `relay_cert.py`** — from `main.py` and `serve.py`
- Move `_write_relay_cert`, `_relay_cert_exists`, `_relay_cert_days_remaining`,
  `_issue_relay_cert`, `_renewal_loop`, and the filename/threshold constants
  into `src/jackdaw/services/relay_cert.py` with public names.
- `main.py` keeps only lifespan wiring; `serve.py` imports public functions.
  No behavior change — this is the enabler for Phase 4's tests, so it must land
  before them.

---

## Phase 4 — Test coverage: A− → A  ⬜

Target: overall ≥ 92% lines, and the current weak spot (`main.py` ~76%) ≥ 90%.
New tests, against the extracted `relay_cert.py` where possible:

- **Renewal loop** — monkeypatch `asyncio.sleep` to advance instantly; cases:
  cert fresh (no-op), < 30 days (issues + reloads SSL context), issuance raises
  (logs, retries next cycle), no ssl_context (skips reload). Use throwaway
  self-signed certs generated in-fixture.
- **`_reset_processing_orders`** — seed processing orders/authzs, run, assert
  `invalid` + the interrupted-order problem doc.
- **`_write_relay_cert`** — atomicity: temp files gone, key mode 0600, key
  renamed before cert (assert ordering via a patched `os.replace` recorder).
- **`_ensure_relay_cert` backoff** — failure → retry with doubled delay capped
  at 900s; existing-but-expiring cert → serves old cert after one failed renewal.
- Regression tests from Phases 1–2 (Phase 1's are already in place).
- Add `--cov-fail-under=90` (or 92) to the pytest coverage config so the bar is
  enforced in CI, not aspirational.

---

## Sequencing, risks, and definition of done

- **Order:** Phase 1 ✅ → 3.3 (pure refactor, unblocks Phase 4) → 4 → 3.1 →
  2.2 (needs migrations) → 2.1 → 2.3 → 3.2 anytime.
- **Biggest risks:**
  - (a) Alembic stamping logic against pre-existing DBs — mitigate with the
    old-schema migration test.
  - (b) Non-root container vs root-owned volumes — mitigate with entrypoint
    chown + CHANGELOG migration note.
  - (c) Multi-identifier rejection (Phase 1.2) is a behavior change for any
    client currently sending SAN orders — they were silently broken before,
    now loudly. CHANGELOG it.
- **Done means:** `make ci` green; coverage gate ≥ 90% enforced; Pebble
  integration flow (`make test-integration` + full compose stack as non-root)
  passes; version bumped to 0.4.0 with a CHANGELOG entry per phase; README
  updated (single-identifier limitation, non-root migration note, nonce-cap
  note).
