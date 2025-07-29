# 🐉 DragonShard

DragonShard is an autonomous offensive security tool designed to discover vulnerabilities, infer API structure, fuzz endpoints, and plan multi-stage exploit chains.


## Status Badges
Add these to your README when connected to CI/CD services:

[![Travis CI](https://travis-ci.com/meltingscales/dragonshard.svg?branch=main)](https://travis-ci.com/meltingscales/dragonshard)
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
# Run Docker integration tests
python scripts/run_docker_tests.py

# Or manually with Docker Compose
docker-compose -f docker-compose.test.yml up -d
pytest dragonshard/tests/test_docker_scanner.py -v -s
docker-compose -f docker-compose.test.yml down
```

**Test Containers:**
- **DVWA** (Damn Vulnerable Web Application) - Port 8080
- **OWASP Juice Shop** - Port 8081  
- **Vulhub** (Simple vulnerable web app) - Port 8082
- **Metasploitable** - Multiple ports (8083-8093)

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
make test-docker   # Run Docker tests

# Development workflows
make dev           # Lint-fix + format + test
make ci            # All checks + tests
make clean         # Clean up cache files
```

### Python Script
Use the custom linting script for more control:

```bash
# Basic linting
python scripts/lint.py

# Auto-fix issues
python scripts/lint.py --fix

# Format code
python scripts/lint.py --format

# Run all checks
python scripts/lint.py --all

# Security checks only
python scripts/lint.py --security
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

### Travis CI
- **Multi-Python testing** (3.10, 3.11, 3.12)
- **Docker support** for integration tests
- **Caching** for faster builds
- **Coverage reporting** to Codecov
- **Matrix testing** (unit + Docker tests)

### GitHub Actions
- **Alternative CI/CD** pipeline
- **Multi-Python testing** with matrix strategy
- **Linting** with Ruff
- **Security scanning** with Bandit and Safety
- **Docker image building** and testing

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
# Run CI/CD setup script
python scripts/setup_ci.py

# Run local CI checks
ruff check dragonshard/
bandit -r dragonshard/
pytest --cov=dragonshard --cov-report=term-missing
```
