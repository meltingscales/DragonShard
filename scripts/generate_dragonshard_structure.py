import os

BASE_DIR = "dragonshard"

STRUCTURE = {
    "core": ["main.py", "config.py", "utils.py"],
    "recon": ["scanner.py", "banner_grabber.py", "__init__.py"],
    "api_inference": ["crawler.py", "schema_infer.py", "auth_detector.py", "__init__.py"],
    "fuzzing": ["fuzzer.py", "payloads.json", "mutators.py", "__init__.py"],
    "exploits": ["searcher.py", "metasploit_bridge.py", "poc_runner.py", "__init__.py"],
    "planner": ["chain_planner.py", "prompts/base_prompt.txt", "prompts/examples.json", "__init__.py"],
    "executor": ["executor.py", "state_graph.py", "session_manager.py", "__init__.py"],
    "visualizer": ["graph_renderer.py", "ui.py", "__init__.py"],
    "data": ["recon_output.json", "api_schemas.json", "fuzz_log.json", "exploit_plan.json", "session_state.json"],
    "tests": ["test_recon.py", "test_fuzzer.py", "test_planner.py", "test_executor.py"],
    "scripts": ["install_deps.sh", "run_metasploit.sh"]
}

README = """# 🐉 DragonShard

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
"""

TODO = """# ✅ TODO

MVP Milestones
Phase 1 - Recon
 Implement scanner.py with Nmap support

 Output structured JSON of open ports and services

Phase 2 - API Inference
 Crawl discovered HTTP services

 Extract endpoints and infer data schemas

 Identify common auth patterns

Phase 3 - Fuzzing
 Use basic payloads on inputs (XSS, SQLi)

 Log anomalies and crashes

Phase 4 - Planner
 Feed recon/fuzz data to LLM

 Output plan of attack steps

Phase 5 - Executor
 Build graph of hosts/services

 Simulate or execute attack plan

"""

def create_project():
    print(f"📁 Creating project under {BASE_DIR}...")
    os.makedirs(BASE_DIR, exist_ok=True)

    for folder, files in STRUCTURE.items():
        folder_path = os.path.join(BASE_DIR, folder)
        os.makedirs(folder_path, exist_ok=True)
        for file in files:
            file_path = os.path.join(folder_path, file)
            # Handle nested folders like prompts/
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "w") as f:
                if file.endswith(".py"):
                    f.write(f"# Stub for {file}\n\n")
                    f.write("def placeholder():\n    pass\n")
                elif file.endswith(".json"):
                    f.write("{}\n")
                elif file.endswith(".txt"):
                    f.write("// Prompt template\n")
                elif file.endswith(".sh"):
                    f.write("#!/bin/bash\n# Stub script\n")

    with open(os.path.join(BASE_DIR, "README.md"), "w") as f:
        f.write(README)

    with open(os.path.join(BASE_DIR, "TODO.md"), "w") as f:
        f.write(TODO)

    print("✅ Project scaffold complete.")

if __name__ == "__main__":
    create_project()
