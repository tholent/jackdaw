#!/bin/sh
# Entrypoint: optionally remap the jackdaw user to a host-supplied UID/GID, make
# the data volume writable by that user, then drop privileges before running the
# app.
#
# The image sets no USER, so this starts as root. That is deliberate and the
# only thing done as root: PUID/PGID (LinuxServer.io-style env vars) let a bind
# mount owned by an arbitrary host UID/GID stay writable without an explicit
# chown on the host, and an existing /data volume created by an older
# root-running image is root-owned — only root can hand it to the jackdaw user.
# The chown step is idempotent — safe to run on every start and a no-op once
# ownership is already correct.
#
# After the chown we drop to the jackdaw user for the actual app. We use setpriv
# rather than gosu/su-exec because a plain setuid drop clears capabilities: the
# app must keep CAP_NET_BIND_SERVICE to bind :443. setpriv re-raises it as an
# ambient capability so it survives the UID switch. When the container was not
# granted that capability (plain-HTTP mode on a high port, e.g. the test
# compose) we drop without it, since it is neither present nor needed.
set -e

if [ "$(id -u)" = "0" ]; then
    current_uid="$(id -u jackdaw)"
    current_gid="$(id -g jackdaw)"
    target_uid="${PUID:-$current_uid}"
    target_gid="${PGID:-$current_gid}"

    if [ "$target_gid" != "$current_gid" ]; then
        groupmod -o -g "$target_gid" jackdaw
    fi
    if [ "$target_uid" != "$current_uid" ]; then
        usermod -o -u "$target_uid" jackdaw
    fi
    # /app was populated at build time under the old UID/GID, so it needs a
    # sweep only when we actually remapped. -o allows a non-unique ID (e.g. a
    # host UID that collides with a base-image account).
    if [ "$target_uid" != "$current_uid" ] || [ "$target_gid" != "$current_gid" ]; then
        chown -R jackdaw:jackdaw /app
    fi
    chown -R jackdaw:jackdaw /data 2>/dev/null || true

    # Preflight: can we actually preserve CAP_NET_BIND_SERVICE across the drop?
    # This succeeds only when the container was granted the capability (cap_add)
    # and setpriv supports ambient caps. Probing with `true` (not the app) means
    # the real exec below is the single, decisive attempt — no risk of running
    # the app twice. If the probe fails (plain-HTTP mode on a high port, no cap),
    # drop without it, since it is neither present nor needed.
    if setpriv --inh-caps +net_bind_service --ambient-caps +net_bind_service \
        true 2>/dev/null; then
        exec setpriv --reuid jackdaw --regid jackdaw --init-groups \
            --inh-caps +net_bind_service --ambient-caps +net_bind_service -- "$@"
    fi
    exec setpriv --reuid jackdaw --regid jackdaw --init-groups -- "$@"
fi

# Already unprivileged (e.g. `docker run --user ...`): nothing to fix, just run.
exec "$@"
