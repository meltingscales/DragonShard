# 🐉 DragonShard

DragonShard is an autonomous offensive security tool designed to discover vulnerabilities, infer API structure, fuzz endpoints, and plan multi-stage exploit chains.


## Status Badges
Add these to your README when connected to CI/CD services:

[![Codecov](https://codecov.io/gh/meltingscales/dragonshard/branch/main/graph/badge.svg)](https://codecov.io/gh/meltingscales/dragonshard)
[![GitHub Actions](https://github.com/meltingscales/dragonshard/workflows/CI%2FCD%20Pipeline/badge.svg)](https://github.com/meltingscales/dragonshard/actions)

## 📋 Project Status

See [TODO.md](TODO.md) for current development status and roadmap.

## Modules

- `core`: Glue logic, orchestration, and config
- `recon`: Host and service discovery
- `api_inference`: API structure and schema inference
- `fuzzing`: Input fuzzing and payload generation
- `exploits`: PoC discovery and execution
- `planner`: AI-driven attack chain planner
- `executor`: Runs attack steps and tracks state
- `visualizer`: (Optional) UI for graphs and chains

---

## Setup

```bash
uv venv
source .venv/bin/activate
uv pip install -r requirements.lock.txt
```

## Testing

### Unit Tests
```bash
pytest                    # Run all unit tests
pytest -v                 # Verbose output
pytest -s                 # Show print statements
pytest --cov=dragonshard  # With coverage
```

### Docker Integration Tests
The project includes Docker-based integration tests that scan actual vulnerable containers:

```bash
# Start test environment
make test-env-start

# Run Docker integration tests
make test-docker

# Run fuzzer tests with containers
make test-fuzzer-manual

# Stop test environment
make test-env-stop

# Clean up test environment
make test-env-clean
```

**Test Containers:**
- **DVWA** (Damn Vulnerable Web Application) - Port 8080
- **OWASP Juice Shop** - Port 3000
- **WebGoat** - Port 8081
- **Vulnerable PHP App** - Port 8082
- **Vulnerable Node.js App** - Port 8083
- **Vulnerable Python App** - Port 8084

**Requirements:**
- Docker and Docker Compose installed
- Docker daemon running
- Network access to pull container images

**Note:** Docker tests are optional and will be skipped if Docker is not available.

## Development Automation

### Quick Commands
Use the Makefile for convenient development tasks:

```bash
# Show all available commands
make help

# Linting and formatting
make lint          # Run linting checks
make lint-fix      # Auto-fix linting issues
make lint-unsafe   # Auto-fix with unsafe fixes
make format        # Format code
make format-check  # Check formatting
make security      # Run security checks
make all-checks    # Run all checks

# Testing
make test          # Run unit tests
make test-crawlers # Run crawler tests
make test-fuzzer   # Run fuzzer unit tests
make test-fuzzer-integration # Run fuzzer integration tests
make test-fuzzer-manual # Run manual fuzzer test with containers
make test-docker   # Run Docker tests

# Test Environment
make test-env-start # Start vulnerable test containers
make test-env-stop  # Stop vulnerable test containers
make test-env-clean # Clean up test environment

# Development workflows
make dev           # Lint-fix + format + test
make ci            # All checks + tests
make clean         # Clean up cache files
```



### VS Code Integration
Tasks are available in VS Code (Ctrl+Shift+P → "Tasks: Run Task"):
- **Lint Check** - Run ruff linting
- **Lint Fix** - Auto-fix linting issues
- **Format Code** - Format with ruff
- **Security Check** - Run security checks
- **Run Tests** - Run unit tests
- **All Checks** - Run comprehensive checks

## CI/CD

The project includes comprehensive CI/CD setup with multiple providers:

### GitHub Actions
- **Primary CI/CD** pipeline
- **Multi-Python testing** with matrix strategy (3.10, 3.11, 3.12)
- **Docker support** for integration tests
- **Linting** with Ruff
- **Security scanning** with Bandit and Safety
- **Docker image building** and testing
- **Coverage reporting** to Codecov
- **Caching** for faster builds

### Codecov
- **Code coverage reporting** with 80% target
- **GitHub integration** with status checks
- **PR comments** with coverage details
- **Multiple report formats** (HTML, XML, JSON)

### Security Scanning
- **Bandit** for Python security analysis
- **Safety** for dependency vulnerability checking
- **Automated scanning** in CI/CD pipeline

### Setup
```bash
# Set up development environment
make setup

# Run local CI checks
make all-checks
make test
```
