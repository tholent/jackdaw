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
# the project has to be importable without a runtime re-sync.
RUN uv sync --frozen --no-dev

# Run as an unprivileged user.  Create /data up front and hand it (and the
# synced virtualenv under /app) to the jackdaw user: Docker seeds a freshly
# created named volume from the ownership of the image path it mounts over, so
# owning /data here makes the mounted volume writable without a runtime chown.
# Binding the privileged :443 port as non-root needs the NET_BIND_SERVICE
# capability, granted via `cap_add` in docker-compose.yml.
RUN groupadd --system jackdaw \
    && useradd --system --gid jackdaw --home-dir /app --no-create-home jackdaw \
    && mkdir -p /data \
    && chown -R jackdaw:jackdaw /data /app

USER jackdaw

EXPOSE 443
# Invoke the synced virtualenv's interpreter directly (rather than `uv run`) so
# the runtime never needs uv's cache or network as a non-root user.
# jackdaw.serve terminates TLS itself: it keeps the public HTTPS listener
# offline until a real Let's Encrypt cert is on disk, then serves on 443
# (plus a localhost-only liveness listener on 8000 for the healthcheck).
CMD ["/app/.venv/bin/python", "-m", "jackdaw"]
