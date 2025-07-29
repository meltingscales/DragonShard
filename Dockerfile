# DragonShard Docker Image
# Multi-stage build for production and development

# Base stage
FROM python:3.12-slim AS base

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    wget \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Set work directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.lock.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.lock.txt

# Install Playwright browsers
RUN playwright install chromium --with-deps

# Copy application code
COPY dragonshard/ ./dragonshard/
COPY pyproject.toml .

# Development stage
FROM base AS development

# Install development dependencies
RUN pip install --no-cache-dir \
    pytest \
    pytest-cov \
    ruff \
    bandit \
    safety

# Copy test files
COPY dragonshard/tests/ ./dragonshard/tests/
COPY docker-compose.test.yml .
COPY scripts/ ./scripts/

# Create non-root user
RUN useradd --create-home --shell /bin/bash dragonshard
USER dragonshard

# Default command
CMD ["python", "-m", "pytest", "-v"]

# Production stage
FROM base AS production

# Create non-root user
RUN useradd --create-home --shell /bin/bash dragonshard
USER dragonshard

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import dragonshard; print('Health check passed')" || exit 1

# Default command
CMD ["python", "-m", "dragonshard"] 