FROM python:3.12-slim

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Copy lockfile and project metadata first for layer caching.
COPY pyproject.toml uv.lock ./

# Install runtime dependencies from lockfile — no network calls at image runtime.
RUN uv sync --frozen --no-dev

COPY src/ src/

EXPOSE 443
# jackdaw.serve terminates TLS itself: it keeps the public HTTPS listener
# offline until a real Let's Encrypt cert is on disk, then serves on 443
# (plus a localhost-only liveness listener on 8000 for the healthcheck).
CMD ["uv", "run", "python", "-m", "jackdaw"]
