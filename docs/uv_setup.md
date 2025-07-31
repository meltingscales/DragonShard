# UV Setup and Best Practices for DragonShard

This document explains how DragonShard uses `uv` for dependency management and the best practices we follow.

## Overview

DragonShard uses `uv` as its primary Python package manager, following modern Python packaging standards. This provides:

- **Fast dependency resolution**: `uv` is significantly faster than pip
- **Reproducible builds**: Locked dependencies ensure consistent environments
- **Modern standards**: Uses `pyproject.toml` and `uv.lock` instead of `requirements.txt`
- **Development tools**: Integrated linting, formatting, and testing

## Project Structure

```
DragonShard/
├── pyproject.toml    # Project configuration and dependencies
├── uv.lock          # Locked dependency versions (generated)
├── requirements.lock.txt  # Legacy file (deprecated)
└── .venv/           # Virtual environment (managed by uv)
```

## Dependencies

### Core Dependencies (pyproject.toml)

```toml
[project]
dependencies = [
    "fastapi>=0.116.1",
    "uvicorn[standard]>=0.35.0",  # Includes WebSocket support
    "sqlalchemy>=2.0.42",
    "pydantic>=2.11.7",
    "httpx>=0.28.1",
    "python-nmap>=0.7.1",
    "alembic>=1.16.4",
    "psycopg2-binary>=2.9.10",
    "redis>=6.2.0",
    "requests>=2.32.3",
    "rich>=14.1.0",
    "pyyaml>=6.0.2",
    "playwright>=1.45.0",
    "matplotlib>=3.8.4",
    "numpy>=2.3.2",
    "networkx>=3.2.1",
    "graphviz>=0.21",
]
```

### Development Dependencies

```toml
[project.optional-dependencies]
dev = [
    "ruff>=0.12.7",
    "pytest>=8.4.1",
    "pytest-cov>=5.0.0",
    "coverage>=7.10.1",
    "bandit>=1.7.8",
    "safety>=2.3.5",
]
```

## Setup Commands

### Initial Setup

```bash
# Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and setup DragonShard
git clone https://github.com/meltingscales/dragonshard.git
cd dragonshard

# Setup development environment
make setup
```

### Manual Setup

```bash
# Sync dependencies (installs all packages)
uv sync

# Install with development dependencies
uv sync --extra dev

# Install with all optional dependencies
uv sync --all-extras
```

## UV Commands

### Dependency Management

```bash
# Sync dependencies (install/update based on pyproject.toml)
uv sync

# Check if environment is in sync
uv sync --check

# Add a new dependency
uv add package-name

# Add development dependency
uv add --extra dev package-name

# Remove dependency
uv remove package-name

# Update dependencies
uv sync --upgrade
```

### Running Commands

```bash
# Run Python script with uv environment
uv run python script.py

# Run with specific Python version
uv run --python 3.11 python script.py

# Run tests
uv run pytest

# Run linting
uv run ruff check dragonshard/
```

### Environment Management

```bash
# Show current environment
uv venv

# Create new environment
uv venv --python 3.11

# Activate environment
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate     # Windows
```

## Makefile Integration

DragonShard's Makefile uses `uv run` for all Python commands:

```makefile
# Example from Makefile
test:
	@uv run pytest dragonshard/tests/ -v

start-api:
	@uv run uvicorn dragonshard.api.app:app --host 0.0.0.0 --port 8000 --reload

lint:
	@uv run ruff check dragonshard/
```

## Migration from requirements.txt

### Before (Legacy)
```bash
# Old way - using requirements.lock.txt
uv pip install -r requirements.lock.txt
uv pip install "uvicorn[standard]"
```

### After (Modern UV)
```bash
# New way - using pyproject.toml and uv.lock
uv sync
```

## Best Practices

### 1. Always Use `uv sync`

Instead of `uv pip install`, use `uv sync`:

```bash
# ❌ Don't do this
uv pip install package-name

# ✅ Do this
uv add package-name
uv sync
```

### 2. Declare Dependencies in pyproject.toml

All dependencies should be declared in `pyproject.toml`:

```toml
[project]
dependencies = [
    "fastapi>=0.116.1",
    "uvicorn[standard]>=0.35.0",
]

[project.optional-dependencies]
dev = [
    "ruff>=0.12.7",
    "pytest>=8.4.1",
]
```

### 3. Use `uv run` for Scripts

Always use `uv run` to ensure the correct environment:

```bash
# ❌ Don't do this
python script.py

# ✅ Do this
uv run python script.py
```

### 4. Commit uv.lock

Always commit `uv.lock` to ensure reproducible builds:

```bash
git add uv.lock
git commit -m "Update dependencies"
```

### 5. Use Dependency Groups

Organize dependencies by purpose:

```toml
[project.optional-dependencies]
dev = ["ruff", "pytest", "coverage"]
test = ["pytest", "pytest-cov"]
docs = ["sphinx", "mkdocs"]
```

## Troubleshooting

### Environment Out of Sync

```bash
# Check sync status
uv sync --check

# Force sync
uv sync --reinstall
```

### Missing Dependencies

```bash
# Add missing dependency
uv add package-name

# Sync environment
uv sync
```

### Lock File Conflicts

```bash
# Regenerate lock file
rm uv.lock
uv sync
```

### Python Version Issues

```bash
# Check Python version
uv run python --version

# Use specific Python version
uv run --python 3.11 python script.py
```

## Development Workflow

### 1. Adding New Dependencies

```bash
# Add runtime dependency
uv add fastapi

# Add development dependency
uv add --group dev pytest

# Add optional dependency
uv add --extra test pytest-cov
```

### 2. Updating Dependencies

```bash
# Update all dependencies
uv sync --upgrade

# Update specific package
uv sync --upgrade-package fastapi
```

### 3. Testing Changes

```bash
# Run tests
make test

# Run linting
make lint

# Run security checks
make security
```

## CI/CD Integration

### GitHub Actions Example

```yaml
- name: Setup Python
  uses: actions/setup-python@v4
  with:
    python-version: '3.11'

- name: Install uv
  uses: astral-sh/setup-uv@v1

- name: Install dependencies
  run: uv sync

- name: Run tests
  run: uv run pytest
```

## Benefits of UV

### Performance
- **10-100x faster** than pip for dependency resolution
- **Parallel downloads** and installations
- **Smart caching** of packages

### Reliability
- **Deterministic builds** with lock files
- **Conflict resolution** with modern algorithms
- **Reproducible environments** across platforms

### Developer Experience
- **Integrated tools** (linting, formatting, testing)
- **Modern standards** (pyproject.toml, PEP 621)
- **Simple commands** (`uv sync`, `uv run`)

## Migration Guide

If you're coming from a `requirements.txt` workflow:

1. **Replace `pip install -r requirements.txt`** with `uv sync`
2. **Replace `python script.py`** with `uv run python script.py`
3. **Replace `pip install package`** with `uv add package && uv sync`
4. **Commit `uv.lock`** instead of `requirements.lock.txt`

## References

- [UV Documentation](https://docs.astral.sh/uv/)
- [PEP 621 - pyproject.toml](https://peps.python.org/pep-0621/)
- [Modern Python Packaging](https://packaging.python.org/en/latest/tutorials/packaging-projects/) 