# 🐉 DragonShard

DragonShard is an autonomous offensive security tool designed to discover vulnerabilities, infer API structure, fuzz endpoints, and plan multi-stage exploit chains.

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