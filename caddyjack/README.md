# caddyjack

A minimal, env-driven [Caddy](https://caddyserver.com) reverse proxy meant to sit
in front of a single application and obtain its TLS certificate from a
[jackdaw](../README.md) ACME relay.

It exists to collapse the usual two-file setup (a `compose.yml` **and** a
per-app `Caddyfile`) down to just a `compose.yml`: the Caddyfile is baked into
the image and configured entirely through a few environment variables. caddyjack
is an ACME *client* — it is the consumer side of jackdaw, not a replacement for
it.

## Configuration

All configuration is via environment variables. The image ships sensible
defaults, so only the ones that differ from your setup are required.

| Variable | Default | Description |
|---|---|---|
| `LE_SERVER` | Let's Encrypt production | ACME directory URL. Point at your relay, e.g. `https://jackdaw.example.com/directory`. |
| `PROXY_HOST` | `localhost` | Public FQDN this proxy serves and obtains a cert for. **Not** `HOSTNAME` — Docker reserves that env var. |
| `CONTAINER` | `localhost` | Backend host to reverse-proxy to (usually the app's `container_name`). |
| `CONTAINER_PORT` | `80` | Backend port. |

The mechanism is Caddy's native `{$VAR}` placeholders (see [`Caddyfile`](Caddyfile)),
which are expanded from the **runtime** environment when Caddy loads its config —
so `environment:` values in your compose file take effect with no rebuild.

## Usage

```yaml
services:
  app:
    image: my-app:latest
    container_name: my-app
    restart: unless-stopped
    networks: [default]

  proxy:
    image: ghcr.io/tholent/caddyjack:latest
    container_name: my-app-proxy
    restart: unless-stopped
    depends_on: [app]
    environment:
      LE_SERVER: https://jackdaw.example.com/directory
      PROXY_HOST: app.example.com
      CONTAINER: my-app
      CONTAINER_PORT: 8080
    networks:
      default:
      rhza-net:            # the network the relay validates over
        ipv4_address: 10.13.50.23
    volumes:
      - caddy-data:/data     # persists issued certs across restarts
      - caddy-config:/config

networks:
  default:
  rhza-net:
    external: true

volumes:
  caddy-data:
  caddy-config:
```

Persist `/data` — that is where Caddy stores issued certificates and its ACME
account key. Without it, every restart re-requests a certificate.

## Requirements & gotchas

- **`PROXY_HOST` must be reachable from the relay on port 80** at issuance time.
  jackdaw validates HTTP-01 from its own vantage point; Caddy serves the
  challenge on :80 automatically. Ensure the FQDN resolves to this proxy's IP on
  the shared network.
- **The relay's own certificate must be trusted by caddyjack.** Caddy validates
  TLS when talking to `LE_SERVER`. If jackdaw runs against Let's Encrypt
  *production*, this is automatic. If jackdaw is pointed at LE *staging*, its own
  cert is untrusted and issuance here will fail until you add the staging root to
  this container's trust store.
- **Single site by design.** One `PROXY_HOST` → one upstream. For multi-host or
  path-based routing, use a full Caddyfile instead.

## Health check

The image bakes a liveness `HEALTHCHECK` against Caddy's admin API
(`127.0.0.1:2019`), which answers from process start — so the container reports
healthy even while first-boot issuance keeps the public :443 listener offline.
Override it in compose if you want a readiness check against the site itself.

## Building & releasing

Build locally:

```bash
docker build -t caddyjack:latest ./caddyjack
```

Verify runtime env substitution (this is what the CI smoke test asserts):

```bash
docker run --rm \
  -e LE_SERVER=https://jackdaw.example.com/directory \
  -e PROXY_HOST=app.example.com -e CONTAINER=backend -e CONTAINER_PORT=8080 \
  caddyjack:latest caddy adapt --config /etc/caddy/Caddyfile --pretty
```

caddyjack versions **independently of jackdaw** on its own tag prefix. Push a
`caddyjack-vX.Y.Z` tag to build and publish to `ghcr.io/tholent/caddyjack` with
the tags `X.Y.Z`, `X.Y`, `latest`, and `sha-<commit>` (see
[`caddyjack-release.yml`](../.github/workflows/caddyjack-release.yml)):

```bash
git tag -a caddyjack-v1.0.0 -m "caddyjack v1.0.0"
git push origin caddyjack-v1.0.0
```

> The GHCR package is created private on first publish. Make it public (or grant
> pull access) in the repo's package settings so hosts can pull it without auth.
