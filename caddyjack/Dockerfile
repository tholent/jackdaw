# TODO: pin to a specific Caddy minor or digest (e.g. caddy:2.9-alpine or
# caddy:2-alpine@sha256:...) for reproducible builds instead of the floating tag.
FROM caddy:2-alpine

LABEL org.opencontainers.image.source="https://github.com/tholent/jackdaw" \
      org.opencontainers.image.description="Env-driven Caddy reverse proxy that obtains its TLS cert from a jackdaw ACME relay"

# caddyjack — a stock Caddy image whose entire config is driven by a few runtime
# environment variables, so a downstream stack needs only a compose.yml: no
# per-app Caddyfile. It is an ACME *client* that obtains its cert from a jackdaw
# relay (set LE_SERVER to the relay's /directory) and reverse-proxies to one
# backend.
#
# The committed Caddyfile uses Caddy's native {$VAR} placeholders, which are
# expanded from the *runtime* environment when Caddy loads its config. (The
# previous version generated the Caddyfile with a build-time `echo`, which baked
# the image defaults in and ignored compose `environment:` entirely.)
#
# Knobs (all optional; defaults live in the Caddyfile):
#   LE_SERVER      ACME directory URL — point at your jackdaw relay
#                  (default: Let's Encrypt production)
#   PROXY_HOST     public FQDN this proxy serves and obtains a cert for
#                  (NB: not HOSTNAME — Docker reserves that env var)
#   CONTAINER      backend host to reverse_proxy to      (default: localhost)
#   CONTAINER_PORT backend port                          (default: 80)
COPY Caddyfile /etc/caddy/Caddyfile

# 80: ACME HTTP-01 challenge — the jackdaw relay validates the client over the
#     internal network on :80 before issuing. 443: public HTTPS.
EXPOSE 80 443

# Liveness only: Caddy's admin API (localhost:2019) answers from process start,
# so this reports healthy even while first-boot cert issuance is still keeping
# the public :443 listener offline. Override in compose if you want a
# readiness-style check against the proxied site instead.
#
# Probe 127.0.0.1, not `localhost`: musl resolves localhost to ::1 first and
# busybox wget doesn't fall back to IPv4, but Caddy's admin listener binds
# localhost:2019 on 127.0.0.1 only — so `localhost` here is always refused.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:2019/config/ >/dev/null 2>&1 || exit 1
