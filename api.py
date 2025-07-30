#!/usr/bin/env python3
"""
DragonShard Main API Entry Point

This is the main entry point for the DragonShard API server.
It imports the API from the dragonshard package and provides
a unified interface for all DragonShard functionality.
"""

import uvicorn
from dragonshard.api.app import app

if __name__ == "__main__":
    uvicorn.run(
        "dragonshard.api.app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    ) 