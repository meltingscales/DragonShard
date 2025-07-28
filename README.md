# 🐉 DragonShard

DragonShard is an autonomous offensive security tool designed to discover vulnerabilities, infer API structure, fuzz endpoints, and plan multi-stage exploit chains.

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

```
pytest
```