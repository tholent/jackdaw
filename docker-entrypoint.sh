#!/bin/sh
# Entrypoint: make the data volume writable by the unprivileged user, then drop
# privileges before running the app.
#
# The image sets no USER, so this starts as root. That is deliberate and the
# only thing done as root: an existing /data volume created by an older
# root-running image is root-owned, and only root can hand it to the jackdaw
# user. The step is idempotent — safe to run on every start and a no-op once
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
