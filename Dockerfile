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
CMD ["uv", "run", "uvicorn", "jackdaw.main:app", "--host", "0.0.0.0", "--port", "8000"]
