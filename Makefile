.DEFAULT_GOAL := help

# The devcontainer sets VIRTUAL_ENV=/usr which confuses uv into thinking the
# system directory is the project venv.  Unexport it so uv uses .venv instead.
unexport VIRTUAL_ENV

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SRC   := src
TESTS := tests

# ---------------------------------------------------------------------------
# Help — list targets with their descriptions
# ---------------------------------------------------------------------------
.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
.PHONY: install
install: ## Install all deps (including dev) from lockfile
	uv sync

.PHONY: install-prod
install-prod: ## Install runtime deps only (no dev tools)
	uv sync --frozen --no-dev

# ---------------------------------------------------------------------------
# Quality gates
# ---------------------------------------------------------------------------
.PHONY: lint
lint: ## Run ruff linter (check only, no fixes)
	uv run ruff check $(SRC) $(TESTS)

.PHONY: format
format: ## Auto-format and fix lint issues with ruff
	uv run ruff format $(SRC) $(TESTS)
	uv run ruff check --fix $(SRC) $(TESTS)

.PHONY: typecheck
typecheck: ## Run mypy in strict mode
	uv run mypy $(SRC)

.PHONY: check
check: lint typecheck ## Run all static checks (lint + typecheck)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
.PHONY: test
test: ## Run the unit test suite (skips integration tests needing Pebble)
	uv run pytest $(TESTS) -v

.PHONY: test-fast
test-fast: ## Run tests without -v, stop on first failure
	uv run pytest $(TESTS) -x -q

.PHONY: test-cov
test-cov: ## Run tests with coverage report (terminal + coverage.xml)
	uv run pytest $(TESTS) --cov --cov-report=term-missing --cov-report=xml

.PHONY: test-integration
test-integration: ## Run integration tests (requires Pebble — see docker-compose.test.yml)
	PEBBLE_URL=https://localhost:14000 uv run pytest $(TESTS)/test_order_flow.py -v

# ---------------------------------------------------------------------------
# Development
# ---------------------------------------------------------------------------
.PHONY: dev
dev: ## Start the app locally with auto-reload (needs .env)
	uv run uvicorn jackdaw.main:app --reload --host 0.0.0.0 --port 8000

# ---------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------
.PHONY: docker-build
docker-build: ## Build the jackdaw Docker image
	docker compose build jackdaw

.PHONY: docker-up
docker-up: ## Start all services in the background
	docker compose up -d

.PHONY: docker-down
docker-down: ## Stop and remove all containers
	docker compose down

.PHONY: docker-logs
docker-logs: ## Tail logs from all running containers
	docker compose logs -f

# ---------------------------------------------------------------------------
# Housekeeping
# ---------------------------------------------------------------------------
.PHONY: clean
clean: ## Remove caches and build artefacts
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .mypy_cache -exec rm -rf {} +
	find . -type d -name .ruff_cache -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +
	find . -name "*.pyc" -delete

.PHONY: ci
ci: install check test ## Full CI pipeline: install → lint → typecheck → test
