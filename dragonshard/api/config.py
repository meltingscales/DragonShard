"""
API Configuration for DragonShard

This module contains configuration settings for the DragonShard API,
including server settings, CORS configuration, and environment-specific settings.
"""

import os
from typing import List

# Server Configuration
API_HOST = os.getenv("DRAGONSHARD_API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("DRAGONSHARD_API_PORT", "8000"))
API_RELOAD = os.getenv("DRAGONSHARD_API_RELOAD", "true").lower() == "true"

# CORS Configuration
CORS_ORIGINS: List[str] = [
    "http://localhost:3000",  # React development server
    "http://localhost:3001",  # Alternative React port
    "http://127.0.0.1:3000",
    "http://127.0.0.1:3001",
    "http://localhost:5173",  # Vite default port
    "http://127.0.0.1:5173",
]

# Add production origins if specified
if os.getenv("DRAGONSHARD_CORS_ORIGINS"):
    CORS_ORIGINS.extend(os.getenv("DRAGONSHARD_CORS_ORIGINS", "").split(","))

# API Documentation
API_TITLE = "DragonShard API"
API_DESCRIPTION = """
## DragonShard API

Comprehensive API for DragonShard offensive security tool.

### Features
- **Attack Monitoring**: Real-time attack chain tracking and visualization
- **Vulnerability Analysis**: Vulnerability discovery and correlation
- **Network Topology**: Interactive network graph visualization
- **Genetic Fuzzing**: Monitor genetic algorithm progress and mutations
- **Session Management**: Track authentication and session states
- **Reverse Shell**: Manage reverse shell connections and consoles
- **Data Export**: Export results and reports in various formats

### Authentication
Currently no authentication required for development.

### WebSocket Support
Real-time updates available via WebSocket at `/ws`
"""

API_VERSION = "1.0.0"
API_CONTACT = {
    "name": "DragonShard Team",
    "url": "https://github.com/dragonshard/dragonshard",
}
API_LICENSE = {
    "name": "MIT",
    "url": "https://opensource.org/licenses/MIT",
}

# API Tags Metadata
API_TAGS_METADATA = [
    {
        "name": "attacks",
        "description": "Attack chain monitoring and management operations",
    },
    {
        "name": "vulnerabilities",
        "description": "Vulnerability discovery and analysis operations",
    },
    {
        "name": "network",
        "description": "Network topology and host discovery operations",
    },
    {
        "name": "fuzzing",
        "description": "Genetic algorithm and fuzzing operations",
    },
    {
        "name": "sessions",
        "description": "Session management and authentication operations",
    },
    {
        "name": "export",
        "description": "Data export and reporting operations",
    },
    {
        "name": "genetic_algorithm",
        "description": "Genetic algorithm progress and mutation tracking",
    },
    {
        "name": "reverse_shells",
        "description": "Reverse shell connection management",
    },
]

# Server URLs
SERVERS = [
    {"url": "http://localhost:8000", "description": "Development server"},
    {"url": "https://api.dragonshard.com", "description": "Production server"},
]

# Logging Configuration
LOG_LEVEL = os.getenv("DRAGONSHARD_LOG_LEVEL", "INFO")
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# WebSocket Configuration
WS_HEARTBEAT_INTERVAL = 30  # seconds
WS_MAX_CONNECTIONS = 100

# Rate Limiting (if implemented)
RATE_LIMIT_REQUESTS = 100  # requests per minute
RATE_LIMIT_WINDOW = 60  # seconds
