.PHONY: help lint lint-fix format format-check security all-checks test test-docker clean

# Default target
help:
	@echo "🐉 DragonShard - Offensive Security Tool"
	@echo "========================================"
	@echo ""
	@echo "Available targets:"
	@echo ""
	@echo "📋 Code Quality:"
	@echo "  lint          - Run linting checks"
	@echo "  lint-fix      - Run linting with auto-fix"
	@echo "  format        - Format code"
	@echo "  format-check  - Check code formatting"
	@echo "  security      - Run security checks (Bandit + Safety)"
	@echo "  all-checks    - Run all quality checks"
	@echo ""
	@echo "🧪 Testing:"
	@echo "  test                    - Run all unit tests"
	@echo "  test-crawlers          - Run crawler tests"
	@echo "  test-fuzzer            - Run fuzzer unit tests"
	@echo "  test-fuzzer-integration - Run fuzzer integration tests"
	@echo "  test-fuzzer-manual     - Run manual fuzzer test"
	@echo "  test-visualization     - Run genetic algorithm visualization"
	@echo "  test-benchmark         - Run genetic algorithm benchmarks"
	@echo "  test-docker            - Run Docker integration tests"
	@echo ""
	@echo "🐳 Test Environment:"
	@echo "  test-env-start         - Start vulnerable test containers"
	@echo "  test-env-stop          - Stop test containers"
	@echo "  test-env-clean         - Clean up test environment"
	@echo ""
	@echo "🔧 Development:"
	@echo "  setup         - Set up development environment (install deps + Playwright)"
	@echo "  clean         - Clean up cache and temporary files"
	@echo ""

# Linting targets
lint:
	@echo "🔍 Running ruff linting checks..."
	@ruff check dragonshard/

lint-fix:
	@echo "🔧 Running ruff linting with auto-fix..."
	@ruff check dragonshard/ --fix

lint-unsafe:
	@echo "⚠️  Running ruff linting with unsafe fixes..."
	@ruff check dragonshard/ --fix --unsafe-fixes

format:
	@echo "🎨 Formatting code with ruff..."
	@ruff format dragonshard/

format-check:
	@echo "🔍 Checking code formatting..."
	@ruff format dragonshard/ --check

security:
	@echo "🔒 Running security checks..."
	@echo "📦 Running Bandit..."
	@bandit -r dragonshard/ -f txt
	@echo "🛡️ Running Safety..."
	@safety check

all-checks: lint format-check security
	@echo "✅ All checks completed!"

# Testing targets
test:
	@echo "🧪 Running unit tests..."
	@uv run pytest dragonshard/tests/ -v

test-crawlers:
	@echo "🕷️  Running crawler tests..."
	@python dragonshard/api_inference/test_crawlers.py

test-fuzzer:
	@echo "🧬 Running fuzzer tests..."
	@pytest dragonshard/tests/test_fuzzing.py dragonshard/tests/test_genetic_mutator.py dragonshard/tests/test_response_analyzer.py -v

test-fuzzer-integration:
	@echo "🧬 Running fuzzer integration tests..."
	@pytest dragonshard/tests/test_genetic_fuzzer_integration.py -v

test-fuzzer-manual:
	@echo "🧬 Running manual fuzzer test..."
	@python dragonshard/tests/test_genetic_fuzzer.py

test-visualization:
	@echo "🎨 Running genetic algorithm visualization..."
	@uv run python test_visualization.py

test-benchmark:
	@echo "📊 Running genetic algorithm benchmarks..."
	@uv run python scripts/run_benchmarks.py

test-docker:
	@echo "🐳 Running Docker integration tests..."
	@python scripts/run_docker_tests.py

# Test Environment targets
test-env-start:
	@echo "🐳 Starting vulnerable test containers..."
	@./scripts/start_test_env.sh

test-env-stop:
	@echo "🛑 Stopping vulnerable test containers..."
	@docker-compose -f docker-compose.test.yml down

test-env-clean:
	@echo "🧹 Cleaning up test environment..."
	@docker-compose -f docker-compose.test.yml down -v
	@docker system prune -f
	@echo "✅ Test environment cleaned up!"

# Development targets
setup:
	@echo "🔧 Setting up development environment..."
	@uv pip install -r requirements.lock.txt
	@echo "🎭 Installing Playwright browsers..."
	@uv run playwright install chromium
	@echo "🎨 Installing tkinter for visualization..."
	@sudo apt update && sudo apt install -y python3-tk
	@echo "✅ Setup completed!"

clean:
	@echo "🧹 Cleaning up..."
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@find . -type f -name "*.pyo" -delete 2>/dev/null || true
	@find . -type f -name ".coverage" -delete 2>/dev/null || true
	@find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "benchmark_results_*.json" -delete 2>/dev/null || true
	@echo "✅ Cleanup completed!"

# Convenience targets
dev: lint-fix format test
	@echo "🚀 Development workflow completed!"

ci: all-checks test
	@echo "🔧 CI workflow completed!" 