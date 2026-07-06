FROM python:3.12-slim

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Copy lockfile and project metadata first for layer caching.
COPY pyproject.toml uv.lock ./

# Install runtime dependencies from lockfile — no network calls at image runtime.
RUN uv sync --frozen --no-dev

COPY src/ src/

EXPOSE 8000
# --proxy-headers trusts nginx's X-Forwarded-Proto so request.url reflects the
# public https:// scheme (nginx terminates TLS and proxies over plain HTTP).
# Without it, request.url reconstructs as http://..., which never matches the
# https:// URLs jackdaw itself advertises via relay_base_url, and every signed
# ACME request fails JWS url-claim verification. forwarded-allow-ips='*' is
# safe here because port 8000 is only ever reachable from nginx on the compose
# network, never published to the host.
CMD ["uv", "run", "uvicorn", "jackdaw.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips=*"]
