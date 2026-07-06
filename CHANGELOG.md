# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **Container runs as a non-root user.** The image now creates and runs as the
  unprivileged `jackdaw` user, with only the `NET_BIND_SERVICE` capability added
  in compose so it can still bind port 443. Existing deployments must fix the
  ownership of a previously root-owned `/data` volume once — see the Security
  notes in the README.

### Fixed
- `CHALLENGE_HTTP_PORT` is now honored when validating HTTP-01 challenges;
  previously the configured port only reached the `Host` header and the
  connection always went to port 80.
- Certificate `expires_at` now reflects the issued leaf's real `notAfter`
  instead of a fixed 89-day estimate.
- HTTP-01 validation now prefers an IPv4 address (falling back to IPv6) as
  documented, while still SSRF-checking every resolved address.

### Changed
- Multi-identifier (SAN) orders are rejected at `new-order` with a `malformed`
  problem document. This relay issues one domain per order; such orders were
  previously accepted but silently downgraded to the first identifier.

### Added
- `GET /version` endpoint and `jackdaw.__version__` reporting the running release.
- `Release` GitHub Actions workflow that builds and publishes the Docker image to
  `ghcr.io/tholent/jackdaw` when a `vX.Y.Z` tag is pushed.
- `SERVE_TLS` setting (default `true`) selecting between in-app TLS on port 443
  and plain HTTP on port 8000.

### Changed
- **Single-container deployment.** The app now terminates TLS itself via a new
  `python -m jackdaw` entry-point; the nginx reverse proxy and the self-signed
  certificate init container are gone, along with the proxy-header trust
  configuration and the cert-reload polling script. The public HTTPS listener
  stays offline until a real Let's Encrypt certificate is issued (retrying with
  backoff), and renewals reload the live TLS context in place. A localhost-only
  liveness listener on port 8000 serves the Docker healthcheck from process
  start.

## [0.1.0]

### Added
- Initial ACME relay: account, order, authorization, challenge, certificate,
  revocation, and key-change flows, with pluggable DNS providers.
