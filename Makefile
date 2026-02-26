.PHONY: build clean test coverage lint typecheck format docker-up docker-down help

PYTHON ?= python3

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

# ── Build ────────────────────────────────────────────────────

build: ## Build Cython extensions in-place
	$(PYTHON) setup.py build_ext --inplace

clean: ## Remove build artefacts
	rm -rf build/ dist/ *.egg-info .eggs
	find nexaflow_core -name '*.so' -delete
	find nexaflow_core -name '*.c' -delete
	find . -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .mypy_cache htmlcov .coverage

# ── Test ─────────────────────────────────────────────────────

test: ## Run test suite
	$(PYTHON) -m pytest tests/ -v --tb=short

coverage: ## Run tests with coverage report
	$(PYTHON) -m pytest tests/ -v --cov=nexaflow_core --cov-report=term-missing --cov-report=html

# ── Lint / Format ────────────────────────────────────────────

lint: ## Run ruff linter
	$(PYTHON) -m ruff check nexaflow_core/ nexaflow_gui/ tests/ run_node.py

format: ## Auto-format with ruff
	$(PYTHON) -m ruff format nexaflow_core/ nexaflow_gui/ tests/ run_node.py
	$(PYTHON) -m ruff check --fix nexaflow_core/ nexaflow_gui/ tests/ run_node.py

typecheck: ## Run mypy type checker
	$(PYTHON) -m mypy nexaflow_core/ --ignore-missing-imports

# ── Docker ───────────────────────────────────────────────────

docker-build: ## Build Docker image
	docker build -t nexaflow-node .

docker-up: ## Start two-node network via docker-compose
	docker compose up --build -d

docker-down: ## Stop docker-compose network
	docker compose down

# ── Benchmarks ───────────────────────────────────────────────

bench: ## Run benchmark suite
	$(PYTHON) -m pytest benchmarks/ -v --tb=short

# ── GUI ──────────────────────────────────────────────────────

gui: ## Launch the PyQt6 desktop GUI
	$(PYTHON) -m nexaflow_gui

# ── Install ──────────────────────────────────────────────────

install: ## Install in editable mode with dev extras
	pip install -e ".[dev,gui]"

install-deps: ## Install runtime + dev deps from requirements
	pip install -r requirements-dev.txt
