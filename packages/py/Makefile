.DEFAULT_GOAL := help

.PHONY: help install format lint lint-fix typecheck check test test-verbose test-cov docs docs-serve example-fastapi build clean

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-16s\033[0m %s\n", $$1, $$2}'

install: ## Install all deps
	uv sync --all-extras

format: ## Format with ruff
	uv run ruff format src/ tests/

lint: ## Lint with ruff
	uv run ruff check src/ tests/

lint-fix: ## Auto-fix lint issues
	uv run ruff check --fix src/ tests/

typecheck: ## Type-check with basedpyright
	uv run basedpyright src/

check: lint typecheck ## All static checks

test: ## Run tests (parallel)
	uv run pytest -n auto

test-verbose: ## Run tests (verbose, parallel)
	uv run pytest -n auto -v

test-cov: ## Run tests with coverage (parallel)
	uv run pytest -n auto --cov=urauth --cov-report=term-missing --cov-report=html

docs: ## Build docs
	uv run mkdocs build

docs-serve: ## Serve docs locally on :8041
	uv run mkdocs serve -a localhost:8041

example-fastapi: ## Run FastAPI example on :8040
	cd examples/fastapi-example && uv run uvicorn app.main:app --reload --port 8040

build: ## Build package
	uv build

clean: ## Remove build artifacts and caches
	rm -rf dist/ build/ *.egg-info .ruff_cache .pytest_cache .mypy_cache htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
