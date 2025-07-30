"""
FastAPI Application for DragonShard Visualization System
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
import json
import logging
from typing import List, Dict, Any
import asyncio
from datetime import datetime
import os

from .models import *
from .websocket_manager import websocket_manager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_app() -> FastAPI:
    """Create and configure FastAPI application"""
    
    app = FastAPI(
        title="DragonShard Visualization API",
        description="Real-time visualization API for DragonShard attack monitoring",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc"
    )
    
    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # In production, specify actual origins
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Import routers after app creation to avoid circular imports
    from .endpoints import attacks, vulnerabilities, network, fuzzing, sessions, export, genetic_algorithm, reverse_shells
    
    # Include routers
    app.include_router(attacks.router, prefix="/api/v1/attacks", tags=["attacks"])
    app.include_router(vulnerabilities.router, prefix="/api/v1/vulnerabilities", tags=["vulnerabilities"])
    app.include_router(network.router, prefix="/api/v1/network", tags=["network"])
    app.include_router(fuzzing.router, prefix="/api/v1/fuzzing", tags=["fuzzing"])
    app.include_router(sessions.router, prefix="/api/v1/sessions", tags=["sessions"])
    app.include_router(export.router, prefix="/api/v1/export", tags=["export"])
    app.include_router(genetic_algorithm.router, prefix="/api/v1/genetic", tags=["genetic_algorithm"])
    app.include_router(reverse_shells.router, prefix="/api/v1", tags=["reverse_shells"])
    
    # Serve static files
    static_path = os.path.join(os.path.dirname(__file__), "..", "frontend", "public")
    if os.path.exists(static_path):
        app.mount("/static", StaticFiles(directory=static_path), name="static")
    
    @app.get("/", response_class=HTMLResponse)
    async def root():
        """Serve the main visualization interface"""
        html_path = os.path.join(os.path.dirname(__file__), "..", "frontend", "public", "index.html")
        if os.path.exists(html_path):
            return FileResponse(html_path)
        else:
            return """
            <!DOCTYPE html>
            <html>
            <head>
                <title>DragonShard Visualization</title>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
            </head>
            <body>
                <div style="text-align: center; padding: 50px; font-family: Arial, sans-serif;">
                    <h1>🐉 DragonShard Visualization</h1>
                    <p>API is running successfully!</p>
                    <p><a href="/api/docs">View API Documentation</a></p>
                </div>
            </body>
            </html>
            """
    
    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        """WebSocket endpoint for real-time updates"""
        await websocket_manager.connect(websocket)
        try:
            while True:
                # Keep connection alive and handle incoming messages
                data = await websocket.receive_text()
                message = json.loads(data)
                
                # Handle different message types
                if message.get("type") == "ping":
                    await websocket_manager.send_personal_message(
                        {"type": "pong", "timestamp": datetime.now().isoformat()},
                        websocket
                    )
                elif message.get("type") == "subscribe":
                    # Handle subscription to specific data streams
                    await websocket_manager.send_personal_message(
                        {"type": "subscribed", "stream": message.get("stream")},
                        websocket
                    )
                    
        except WebSocketDisconnect:
            websocket_manager.disconnect(websocket)
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
            websocket_manager.disconnect(websocket)
    
    @app.on_event("startup")
    async def startup_event():
        """Initialize application on startup"""
        logger.info("🚀 DragonShard Visualization API starting up...")
    
    @app.on_event("shutdown")
    async def shutdown_event():
        """Cleanup on shutdown"""
        logger.info("🛑 DragonShard Visualization API shutting down...")
    
    return app

# Global app instance
app = create_app()

# Export for uvicorn
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 