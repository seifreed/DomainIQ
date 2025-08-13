# DomainIQ Makefile - Code Quality and Development Tasks
# Requires Python 3.10+ and development dependencies installed

.PHONY: help install install-dev quality lint format type-check security test test-unit test-integration coverage clean build docs pre-commit all-checks

# Default target
help:  ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Installation targets
install:  ## Install package in current environment
	pip install -e .

install-dev:  ## Install package with development dependencies
	pip install -e .[dev,async,docs]

install-quality:  ## Install only quality tools
	pip install -e .[quality]

# Code quality targets
quality: lint format type-check security  ## Run all code quality checks

lint:  ## Run linting with Ruff
	@echo "🔍 Running Ruff linting..."
	ruff check domainiq/ tests/ examples/ --fix --show-fixes
	@echo "✅ Linting completed"

format:  ## Format code with Ruff
	@echo "🎨 Formatting code with Ruff..."
	ruff format domainiq/ tests/ examples/
	@echo "✅ Formatting completed"

format-check:  ## Check if code is formatted correctly
	@echo "🎨 Checking code formatting..."
	ruff format --check domainiq/ tests/ examples/
	@echo "✅ Format check completed"

type-check:  ## Run type checking with MyPy
	@echo "🔬 Running MyPy type checking..."
	mypy domainiq/ --show-error-codes --pretty
	@echo "✅ Type checking completed"

security:  ## Run security checks with Bandit
	@echo "🔒 Running Bandit security checks..."
	bandit -r domainiq/ --configfile pyproject.toml
	@echo "✅ Security checks completed"

# Testing targets
test:  ## Run all tests
	@echo "🧪 Running all tests..."
	pytest -v --tb=short
	@echo "✅ All tests completed"

test-unit:  ## Run unit tests only (no API key required)
	@echo "🧪 Running unit tests..."
	pytest -v -m "not integration" --tb=short
	@echo "✅ Unit tests completed"

test-integration:  ## Run integration tests (requires API key)
	@echo "🧪 Running integration tests..."
	pytest -v -m integration --tb=short
	@echo "✅ Integration tests completed"

test-parallel:  ## Run tests in parallel
	@echo "🧪 Running tests in parallel..."
	pytest -v -n auto --tb=short
	@echo "✅ Parallel tests completed"

coverage:  ## Run tests with coverage report
	@echo "📊 Running tests with coverage..."
	pytest --cov=domainiq --cov-report=html --cov-report=term --cov-report=xml
	@echo "✅ Coverage report generated in htmlcov/"

# Pre-commit targets
pre-commit-install:  ## Install pre-commit hooks
	@echo "⚙️  Installing pre-commit hooks..."
	pre-commit install
	@echo "✅ Pre-commit hooks installed"

pre-commit:  ## Run pre-commit hooks on all files
	@echo "🔄 Running pre-commit hooks..."
	pre-commit run --all-files
	@echo "✅ Pre-commit checks completed"

# Comprehensive quality checks
all-checks: quality test coverage security  ## Run all quality checks and tests

ci-checks: format-check lint type-check security test-unit  ## Run CI/CD checks

# Build and distribution
clean:  ## Clean build artifacts and cache files
	@echo "🧹 Cleaning build artifacts..."
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	@echo "✅ Cleanup completed"

build:  ## Build package for distribution
	@echo "📦 Building package..."
	python -m build
	@echo "✅ Package built in dist/"

build-check:  ## Check package build without building
	@echo "📦 Checking package build..."
	python -m build --check
	@echo "✅ Package build check completed"

# Documentation
docs:  ## Build documentation
	@echo "📚 Building documentation..."
	cd docs && make html
	@echo "✅ Documentation built"

docs-serve:  ## Serve documentation locally
	@echo "📚 Serving documentation..."
	cd docs/_build/html && python -m http.server 8000

# Development helpers
install-tools:  ## Install all development tools globally
	pip install --upgrade pip
	pip install ruff mypy bandit pre-commit build twine

upgrade-deps:  ## Upgrade all dependencies to latest versions
	pip install --upgrade pip
	pip install --upgrade -e .[dev,async,docs]

check-deps:  ## Check for dependency vulnerabilities
	@echo "🔍 Checking dependencies for vulnerabilities..."
	pip-audit
	@echo "✅ Dependency check completed"

# Performance and profiling
profile:  ## Run performance profiling on examples
	@echo "⚡ Running performance profiling..."
	python -m cProfile -o profile_output.prof examples/basic_usage.py
	@echo "✅ Profiling completed - see profile_output.prof"

benchmark:  ## Run performance benchmarks
	@echo "⚡ Running benchmarks..."
	python -m pytest tests/ -k "benchmark" -v
	@echo "✅ Benchmarks completed"

# Quality gates
quality-gate:  ## Quality gate - all checks must pass
	@echo "🚪 Running quality gate..."
	@$(MAKE) format-check
	@$(MAKE) lint
	@$(MAKE) type-check
	@$(MAKE) security
	@$(MAKE) test-unit
	@echo "✅ Quality gate passed!"

# Release helpers
pre-release: clean quality-gate build  ## Prepare for release
	@echo "🚀 Pre-release checks completed"

release-check:  ## Check if ready for release
	@echo "🔍 Checking release readiness..."
	python setup.py check --restructuredtext --strict
	twine check dist/*
	@echo "✅ Release check completed"

# Show versions and info
info:  ## Show environment and tool versions
	@echo "Environment Information:"
	@echo "Python: $$(python --version)"
	@echo "Pip: $$(pip --version)"
	@echo "Ruff: $$(ruff --version)"
	@echo "MyPy: $$(mypy --version)"
	@echo "Bandit: $$(bandit --version)"
	@echo "Pytest: $$(pytest --version)"

# Git helpers
git-clean:  ## Clean git repository (remove untracked files)
	git clean -fdx -e .venv -e venv

commit-quality: quality-gate  ## Run quality checks before commit
	@echo "✅ Ready to commit - all quality checks passed"

# Example targets for users
example-basic:  ## Run basic usage example
	python examples/basic_usage.py

example-async:  ## Run async usage example
	python examples/async_usage.py

example-security:  ## Run security research example
	python examples/security_research.py