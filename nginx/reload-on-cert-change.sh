#!/bin/sh
# Run nginx and reload it whenever Jackdaw replaces the relay TLS cert.
#
# Jackdaw writes the real Let's Encrypt cert to the shared /data volume after
# startup (replacing the self-signed bootstrap placeholder), but it runs in a
# separate container and cannot signal this one.  So nginx watches its own cert
# file and reloads when the mtime changes.
set -eu

CERT="/data/ssl/fullchain.pem"
POLL_INTERVAL="${CERT_RELOAD_POLL:-15}"

# Start nginx in the foreground-style master process, backgrounded so this
# script can supervise it and poll for cert changes.
nginx -g 'daemon off;' &
nginx_pid=$!

# Forward shutdown signals so `docker compose stop` ends nginx gracefully.
trap 'nginx -s quit 2>/dev/null || kill "$nginx_pid" 2>/dev/null; exit 0' TERM INT

# Skip the first observed mtime so nginx doesn't reload against the cert it just
# started with; only genuine changes after boot trigger a reload.
last=""
while kill -0 "$nginx_pid" 2>/dev/null; do
    cur="$(stat -c %Y "$CERT" 2>/dev/null || true)"
    if [ -n "$cur" ] && [ "$cur" != "$last" ]; then
        if [ -n "$last" ]; then
            echo "reload-on-cert-change: $CERT changed — reloading nginx"
            nginx -s reload || true
        fi
        last="$cur"
    fi
    sleep "$POLL_INTERVAL"
done
