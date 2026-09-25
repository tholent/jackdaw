FROM python:3.12-slim

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Copy lockfile and project metadata first for layer caching.
COPY pyproject.toml uv.lock ./

# Install runtime *dependencies* only (not the project itself, whose source
# isn't present yet) so this heavy layer stays cached across source changes.
RUN uv sync --frozen --no-dev --no-install-project

COPY src/ src/

# Now install the project itself into the venv.  This must run after the source
# is present: the CMD invokes the venv interpreter directly (no `uv run`), so
# the project has to be importable without a runtime re-sync.  --no-editable
# builds the wheel and installs the package into site-packages, rather than a
# .pth pointer back at /app/src, so the image runs exactly what the wheel ships.
RUN uv sync --frozen --no-dev --no-editable

# Fail the build if the installed package is missing or empty (0.4.0 shipped a
# dist-info with no jackdaw/ inside it).
RUN /app/.venv/bin/python -c "import importlib.util as u, jackdaw; assert u.find_spec('jackdaw.serve')"

# Create the unprivileged runtime user and own the app + a freshly seeded /data.
# The UID/GID are pinned to deterministic defaults so the entrypoint can detect
# whether PUID/PGID at runtime differ and remap accordingly.
# setpriv (from util-linux) is used by the entrypoint to drop privileges while
# preserving CAP_NET_BIND_SERVICE (granted via `cap_add` in compose) so the
# non-root app can still bind :443.
ARG JACKDAW_UID=1000
ARG JACKDAW_GID=1000
RUN groupadd --system --gid ${JACKDAW_GID} jackdaw \
    && useradd --system --uid ${JACKDAW_UID} --gid jackdaw \
        --home-dir /app --no-create-home jackdaw \
    && mkdir -p /data \
    && chown -R jackdaw:jackdaw /data /app \
    && apt-get update \
    && apt-get install -y --no-install-recommends util-linux \
    && rm -rf /var/lib/apt/lists/*

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 443
# The container starts as root so the entrypoint can fix /data ownership
# (idempotent), then drops to the unprivileged jackdaw user — preserving the
# :443 bind capability — before exec'ing the CMD.  The CMD invokes the synced
# virtualenv interpreter directly (no `uv run`), so no uv cache/network is
# needed at runtime.  jackdaw.serve terminates TLS itself: it keeps the public
# HTTPS listener offline until a real Let's Encrypt cert is on disk, then serves
# on 443 (plus a localhost-only liveness listener on 8000 for the healthcheck).
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/app/.venv/bin/python", "-m", "jackdaw"]
