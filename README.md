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

## Visualization Features

DragonShard includes advanced visualization tools for understanding genetic algorithm evolution and mutation trees:

### Genetic Algorithm Visualization
```bash
make test-visualization
```
- **Real-time evolution tracking** with fitness charts
- **Mutation history visualization** showing different mutation types
- **Population dynamics** and convergence analysis
- **Interactive GUI** with Tkinter and matplotlib

### Web Fuzzing Visualization
```bash
make test-web-fuzzing-viz
```
- **Real-time web fuzzing** against vulnerable targets
- **Mutation tree visualization** showing payload evolution
- **Vulnerability discovery tracking** with confidence scores
- **HTTP response analysis** and anomaly detection
- **Multi-payload type support** (SQL Injection, XSS, Command Injection, etc.)
- **Export capabilities** for results and mutation tree data

**Features:**
- **Target URL configuration** for testing specific websites
- **HTTP method selection** (GET, POST, PUT, DELETE)
- **Payload type selection** with domain-specific mutations
- **Real-time vulnerability scoring** based on response analysis
- **Mutation tree tracking** showing parent-child relationships
- **Progress tracking** with generation-by-generation evolution
- **Results export** in JSON format for further analysis

**Requirements:**
- Tkinter GUI support (not available in CI environments)
- Vulnerable test containers running (optional)
- Network access for web requests

## Planning Features

DragonShard includes intelligent attack planning capabilities that integrate reconnaissance and fuzzing results:

### Chain Planner Integration Test
```bash
make test-planner
```
- **Intelligent attack chain generation** based on discovered vulnerabilities
- **Vulnerability prioritization** with risk scoring and business impact assessment
- **Predefined attack strategies** for different vulnerability types
- **LLM integration framework** for advanced attack planning
- **Comprehensive vulnerability analysis** and attack opportunity identification
- **Export capabilities** for attack chains, strategies, and vulnerability reports

**Features:**
- **Multi-vulnerability analysis** with risk-based prioritization
- **Attack chain generation** for SQL injection, XSS, RCE, and authentication bypass
- **Business impact assessment** with technical and financial risk analysis
- **Time-to-exploit estimation** for vulnerability remediation planning
- **Attack strategy templates** for common penetration testing scenarios
- **Integration with existing modules** (crawler, fuzzer, genetic mutator)
- **JSON export** for attack chains, strategies, and vulnerability reports

**Requirements:**
- Python 3.10+ with all dependencies installed
- Network access for LLM integration (optional)
- Vulnerable test containers for realistic testing (optional)

## Execution Features

DragonShard includes comprehensive attack execution capabilities that take planned attack chains and execute them against real targets:

### Executor Integration Test
```bash
make test-executor
```
- **Intelligent attack chain execution** with real-time progress tracking
- **Session management** with authentication and state persistence
- **Network state graph** with host/service/vulnerability tracking
- **Concurrent execution** of multiple attack chains
- **Comprehensive error handling** and retry mechanisms
- **Export capabilities** for execution results and session data

**Features:**
- **Multi-chain execution** with threading support
- **Session persistence** with cookie and header management
- **Network topology mapping** with vulnerability correlation
- **Real-time monitoring** of execution progress and status
- **Authentication support** for form, basic, and token-based auth
- **State graph visualization** of discovered hosts and services
- **Integration with existing modules** (planner, fuzzer, crawler)
- **JSON export** for execution results, session data, and state graphs

**Requirements:**
- Python 3.10+ with all dependencies installed
- Network access for HTTP requests
- Vulnerable test containers for realistic testing (optional)

### Executor Stress Test
```bash
make test-executor-stress
```
- **Complex multi-step vulnerabilities** with 2, 3, and 4-step attack chains
- **CVE-based scenarios** including Log4Shell, BlueKeep, PrintNightmare, Zerologon, ProxyLogon, and vCenter
- **Concurrent execution** of multiple complex attack chains
- **State graph integration** with vulnerability correlation
- **Session management** with authentication persistence
- **Comprehensive export** of execution results, state graphs, and session data

**Features:**
- **2-step vulnerabilities**: Log4Shell (CVE-2021-44228), BlueKeep (CVE-2019-0708)
- **3-step vulnerabilities**: PrintNightmare (CVE-2021-34527), Zerologon (CVE-2020-1472)
- **4-step vulnerabilities**: ProxyLogon (CVE-2021-26855), vCenter (CVE-2021-21972)
- **Real-time monitoring** of complex attack chain execution
- **Vulnerability correlation** across multiple attack steps
- **Authentication state management** for multi-step scenarios
- **Network topology mapping** with service and vulnerability tracking
- **JSON export** for comprehensive analysis and reporting

**Requirements:**
- Python 3.10+ with all dependencies installed
- Docker and Docker Compose for stress test container
- Network access for HTTP requests and container communication

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
make test-visualization # Run genetic algorithm visualization
make test-web-fuzzing-viz # Run web fuzzing visualization with mutation tree
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
