# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `GET /version` endpoint and `jackdaw.__version__` reporting the running release.
- `Release` GitHub Actions workflow that builds and publishes the Docker image to
  `ghcr.io/tholent/jackdaw` when a `vX.Y.Z` tag is pushed.

## [0.1.0]

### Added
- Initial ACME relay: account, order, authorization, challenge, certificate,
  revocation, and key-change flows, with pluggable DNS providers.
