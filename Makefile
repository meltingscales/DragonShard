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
	@echo "🗄️  Database:"
	@echo "  db-init       - Initialize database and create tables"
	@echo "  db-status     - Check database status and table counts"
	@echo "  db-migrate    - Run database migrations"
	@echo "  db-create-migration - Create new migration"
	@echo "  db-drop       - Drop all database tables"
	@echo "  db-check      - Check database connection"
	@echo "  db-test       - Run database tests"
	@echo "  db-demo       - Run database demo"
	@echo "  db-reset      - Reset both SQLite and MySQL databases to original state"
	@echo "  db-reset-sqlite - Reset only SQLite database"
	@echo "  db-reset-mysql  - Reset only MySQL test database"
	@echo "  db-status-detailed - Show detailed database status"
	@echo "  db-test-reset   - Test database reset functionality"
	@echo ""
	@echo "🐳 Docker:"
	@echo "  docker-up     - Start DragonShard with database (docker-compose)"
	@echo "  docker-down   - Stop DragonShard containers"
	@echo "  docker-build  - Build DragonShard Docker image"
	@echo "  docker-logs   - Show Docker container logs"
	@echo ""
	@echo "🧪 Testing:"
	@echo "  test                    - Run all unit tests"
	@echo "  test-crawlers          - Run crawler tests"
	@echo "  test-fuzzer            - Run fuzzer unit tests"
	@echo "  test-fuzzer-integration - Run fuzzer integration tests"
	@echo "  test-fuzzer-manual     - Run manual fuzzer test"
	@echo "  test-visualization-api - Run visualization API test"
	@echo "  test-planner           - Run chain planner integration test"
	@echo "  test-executor          - Run executor integration test"
	@echo "  test-executor-stress   - Run executor stress test with complex vulnerabilities"
	@echo "  test-reverse-shell     - Run reverse shell handler tests"
	@echo "  test-reverse-shell-demo - Run reverse shell demo script"
	@echo "  test-live-attacks       - Run live attack tests against vulnerable containers"
	@echo "  test-full-workflow      - Run full DragonShard workflow tests"
	@echo "  test-visualization-api - Run visualization API test"
	@echo "  start-api              - Start main DragonShard API server"
	@echo "  start-visualization-api - Start visualization API server (legacy)"
	@echo "  start-frontend        - Start React development server"
	@echo "  build-frontend        - Build React frontend for production"
	@echo "  test-benchmark         - Run genetic algorithm benchmarks"
	@echo "  test-docker            - Run Docker integration tests"
	@echo "  test-websocket         - Test WebSocket support"
	@echo "  test-privileged-scanner - Test privileged scanner functionality"
	@echo ""
	@echo "🐳 Test Environment:"
	@echo "  test-env-start         - Start vulnerable test containers"
	@echo "  test-env-stop          - Stop test containers"
	@echo "  test-env-clean         - Clean up test environment"
	@echo ""
	@echo "🔧 Development:"
	@echo "  setup         - Set up development environment (install deps + Playwright)"
	@echo "  setup-nixos   - Set up development environment optimized for NixOS"
	@echo "  setup-nixos-help - Show NixOS configuration requirements"
	@echo "  clean         - Clean up cache and temporary files"
	@echo ""
	@echo "📊 Documentation:"
	@echo "  diagrams      - Generate ER and module diagrams"
	@echo "  diagrams-readme - Generate diagrams and update README"
	@echo "  demo-diagrams - Run diagram generation demo"
	@echo "  db-diagram    - Generate database ER diagram"
	@echo "  db-diagram-readme - Generate database ER diagram and update README"
	@echo ""

# Database targets
db-init:
	@echo "🗄️  Initializing database..."
	@uv run python scripts/manage_db.py init

db-status:
	@echo "📊 Checking database status..."
	@uv run python scripts/manage_db.py status

db-migrate:
	@echo "🔄 Running database migrations..."
	@uv run python scripts/manage_db.py migrate

db-create-migration:
	@echo "📝 Creating database migration..."
	@uv run python scripts/manage_db.py create-migration --message "$(message)"

db-drop:
	@echo "🗑️  Dropping database tables..."
	@uv run python scripts/manage_db.py drop-tables

db-check:
	@echo "🔍 Checking database connection..."
	@uv run python scripts/manage_db.py check

db-test:
	@echo "🧪 Running database tests..."
	@uv run python scripts/test_database.py

db-demo:
	@echo "🎭 Running database demo..."
	@uv run python scripts/demo_database.py

db-reset:
	@echo "🔄 Resetting both databases to original state..."
	@uv run python scripts/reset_databases.py

db-reset-sqlite:
	@echo "🗄️  Resetting only SQLite database..."
	@uv run python scripts/reset_databases.py --sqlite-only

db-reset-mysql:
	@echo "🐳 Resetting only MySQL test database..."
	@uv run python scripts/reset_databases.py --mysql-only

db-status-detailed:
	@echo "📊 Showing detailed database status..."
	@uv run python scripts/reset_databases.py --status-only

db-test-reset:
	@echo "🧪 Testing database reset functionality..."
	@uv run python scripts/test_reset_databases.py

# Docker targets
docker-up:
	@echo "🐳 Starting DragonShard with database..."
	@docker-compose up -d

docker-down:
	@echo "🐳 Stopping DragonShard containers..."
	@docker-compose down

docker-build:
	@echo "🔨 Building DragonShard Docker image..."
	@docker-compose build

docker-logs:
	@echo "📋 Showing Docker container logs..."
	@docker-compose logs -f

# Linting targets
lint:
	@echo "🔍 Running ruff linting checks..."
	@uv run ruff check dragonshard/

lint-fix:
	@echo "🔧 Running ruff linting with auto-fix..."
	@uv run ruff check dragonshard/ --fix

lint-unsafe:
	@echo "⚠️  Running ruff linting with unsafe fixes..."
	@uv run ruff check dragonshard/ --fix --unsafe-fixes

format:
	@echo "🎨 Formatting code with ruff..."
	@uv run ruff format dragonshard/

format-check:
	@echo "🔍 Checking code formatting..."
	@uv run ruff format dragonshard/ --check

security:
	@echo "🔒 Running security checks..."
	@echo "📦 Running Bandit..."
	@uv run bandit -r dragonshard/ -f txt
	@echo "🛡️ Running Safety..."
	@uv run safety check

all-checks: lint format-check security
	@echo "✅ All checks completed!"

# Testing targets
test: test-env-start
	@echo "🧪 Running unit tests..."
	@uv run pytest dragonshard/tests/ -v

test-crawlers:
	@echo "🕷️  Running crawler tests..."
	@uv run python dragonshard/api_inference/test_crawlers.py

test-fuzzer:
	@echo "🧬 Running fuzzer tests..."
	@uv run pytest dragonshard/tests/test_fuzzing.py dragonshard/tests/test_genetic_mutator.py dragonshard/tests/test_response_analyzer.py -v

test-fuzzer-integration:
	@echo "🧬 Running fuzzer integration tests..."
	@uv run pytest dragonshard/tests/test_genetic_fuzzer_integration.py -v

test-fuzzer-manual:
	@echo "🧬 Running manual fuzzer test..."
	@uv run python dragonshard/tests/test_genetic_fuzzer.py

test-planner:
	@echo "🧠 Running chain planner integration test..."
	@uv run python scripts/test_planner_integration.py

test-executor:
	@echo "⚡ Running executor integration test..."
	@PYTHONPATH=. uv run python scripts/test_executor_integration.py

test-executor-stress:
	@echo "🧪 Running executor stress test..."
	@PYTHONPATH=. uv run python scripts/test_executor_stress_integration.py

test-reverse-shell:
	@echo "🐚 Running reverse shell handler tests..."
	@PYTHONPATH=. uv run pytest dragonshard/tests/test_reverse_shell.py -v

test-reverse-shell-demo:
	@echo "🐚 Running reverse shell demo script..."
	@PYTHONPATH=. uv run python dragonshard/scripts/test_reverse_shell_demo.py

test-live-attacks:
	@echo "🎯 Running live attack tests against vulnerable containers..."
	@PYTHONPATH=. uv run python dragonshard/scripts/test_live_attacks.py

test-full-workflow:
	@echo "🐉 Running full DragonShard workflow tests..."
	@PYTHONPATH=. uv run python dragonshard/scripts/test_full_workflow.py

test-visualization-api:
	@echo "🌐 Running visualization API test..."
	@PYTHONPATH=. uv run python scripts/test_visualization_api.py

start-api:
	@echo "🚀 Starting DragonShard API..."
	@PYTHONPATH=. uv run uvicorn dragonshard.api.app:app --host 0.0.0.0 --port 8000 --reload

start-visualization-api:
	@echo "🚀 Starting DragonShard Visualization API (legacy)..."
	@PYTHONPATH=. uv run uvicorn dragonshard.visualizer.api.app:app --host 0.0.0.0 --port 8000 --reload

start-frontend:
	@echo "🌐 Starting DragonShard Frontend..."
	@cd frontend && pnpm run start

build-frontend:
	@echo "🔨 Building DragonShard Frontend..."
	@cd frontend && pnpm run build

test-benchmark:
	@echo "📊 Running genetic algorithm benchmarks..."
	@uv run python scripts/run_benchmarks.py

test-docker:
	@echo "🐳 Running Docker integration tests..."
	@uv run python scripts/run_docker_tests.py

test-websocket:
	@echo "🔌 Testing WebSocket support..."
	@uv run python scripts/test_websocket_support.py

test-privileged-scanner:
	@echo "🔐 Testing privileged scanner functionality..."
	@uv run python scripts/test_privileged_scanner.py

test-command-injection:
	@echo "💥 Running command injection exploitation tests..."
	@PYTHONPATH=. uv run pytest dragonshard/tests/test_command_injection_exploitation.py -v

demo-command-injection:
	@echo "🎯 Running command injection exploitation demo..."
	@PYTHONPATH=. uv run python scripts/demo_command_injection_exploitation.py

demo-command-injection-verbose:
	@echo "🎯 Running command injection exploitation demo (verbose)..."
	@PYTHONPATH=. uv run python scripts/demo_command_injection_exploitation.py --verbose

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
	@uv sync --extra dev
	@echo "🎨 Checking tkinter availability..."
	@python3 -c "import tkinter; print('✅ tkinter is available')" || (echo "⚠️  tkinter not available - install python3-tkinter on your system" && exit 1)
	@echo "🌐 Setting up frontend dependencies..."
	@cd dragonshard/visualizer/frontend && pnpm install
	@echo "🎭 Checking Playwright compatibility..."
	@python3 -c "import playwright; print('✅ Playwright installed')" || echo "⚠️  Playwright has compatibility issues on NixOS - browser automation features will be limited"
	@echo "🔌 Checking WebSocket support..."
	@python3 -c "import websockets; print('✅ WebSocket support available')" || echo "⚠️  WebSocket support not available - real-time features may not work"
	@echo "✅ Setup completed!"

setup-nixos:
	@echo "🔧 Setting up development environment for NixOS..."
	@echo "📦 Installing Python dependencies..."
	@uv sync --extra dev
	@echo "🎨 Checking tkinter availability..."
	@python3 -c "import tkinter; print('✅ tkinter is available')" || (echo "⚠️  tkinter not available - add python3-tkinter to your NixOS configuration" && exit 1)
	@echo "🌐 Setting up frontend dependencies..."
	@cd dragonshard/visualizer/frontend && pnpm install
	@echo "⚠️  Note: Playwright browser automation is limited on NixOS due to dynamic linking restrictions"
	@echo "✅ NixOS setup completed!"

setup-nixos-help:
	@echo "🔧 NixOS Setup Helper"
	@./scripts/setup-nixos.sh

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
	@find . -type f -name "*_export.json" -delete 2>/dev/null || true
	@find . -type f -name "*_report.json" -delete 2>/dev/null || true
	@find . -type f -name "attack_chains_export.json" -delete 2>/dev/null || true
	@find . -type f -name "attack_strategies_export.json" -delete 2>/dev/null || true
	@find . -type f -name "vulnerability_report.json" -delete 2>/dev/null || true
	@find . -type f -name "executor_results.json" -delete 2>/dev/null || true
	@find . -type f -name "session_data.json" -delete 2>/dev/null || true
	@find . -type f -name "state_graph.json" -delete 2>/dev/null || true
	@find . -type f -name "execution_results.json" -delete 2>/dev/null || true
	@find . -type f -name "stress_test_*.json" -delete 2>/dev/null || true
	@echo "✅ Cleanup completed!"

# Documentation targets
diagrams:
	@echo "📊 Generating ER and module diagrams..."
	@PYTHONPATH=. uv run python scripts/generate_diagrams.py
	@echo "🗄️  Generating database ER diagram..."
	@PYTHONPATH=. uv run python scripts/generate_db_er_diagram.py
	@echo "✅ Diagrams generated in docs/diagrams/"

diagrams-readme:
	@echo "📊 Generating diagrams and updating README..."
	@PYTHONPATH=. uv run python scripts/generate_diagrams.py --update-readme
	@echo "🗄️  Generating database ER diagram and updating README..."
	@PYTHONPATH=. uv run python scripts/generate_db_er_diagram.py --update-readme
	@echo "✅ Diagrams generated and README updated"

demo-diagrams:
	@echo "🎯 Running diagram generation demo..."
	@PYTHONPATH=. uv run python scripts/demo_diagrams.py

db-diagram:
	@echo "🗄️  Generating database ER diagram..."
	@PYTHONPATH=. uv run python scripts/generate_db_er_diagram.py
	@echo "✅ Database ER diagram generated in docs/diagrams/"

db-diagram-readme:
	@echo "🗄️  Generating database ER diagram and updating README..."
	@PYTHONPATH=. uv run python scripts/generate_db_er_diagram.py --update-readme
	@echo "✅ Database ER diagram generated and README updated"

# Convenience targets
dev: lint-fix format test
	@echo "🚀 Development workflow completed!"

ci: all-checks test
	@echo "🔧 CI workflow completed!" 