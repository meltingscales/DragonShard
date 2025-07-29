"""
FastAPI Backend for DragonShard Visualization System

Provides REST API endpoints and WebSocket connections for real-time
visualization data and interaction with DragonShard modules.
"""

from .app import create_app
from .models import *
from .endpoints import *

__all__ = [
    "create_app",
] 