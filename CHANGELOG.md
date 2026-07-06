# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
