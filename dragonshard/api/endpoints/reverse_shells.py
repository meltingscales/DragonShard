#!/usr/bin/env python3
"""
Reverse Shell Management API Endpoints

Provides REST API endpoints for managing reverse shell connections,
including listener creation, command execution, and console history.
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from typing import Optional as OptionalType

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from dragonshard.executor.reverse_shell import ReverseShellHandler, ShellStatus

from ..models import BaseResponse, WebSocketMessage

logger = logging.getLogger(__name__)

# Global reverse shell handler instance
reverse_shell_handler = ReverseShellHandler()

router = APIRouter(prefix="/reverse-shells", tags=["reverse-shells"])


# Pydantic models for reverse shell API
class ReverseShellConnection(BaseModel):
    connection_id: str
    port: int
    status: str
    remote_address: OptionalType[str] = None
    remote_port: OptionalType[int] = None
    created_at: datetime
    last_activity: datetime
    console_history_size: int
    auto_close: bool
    timeout: int


class CreateListenerRequest(BaseModel):
    port: OptionalType[int] = None
    auto_close: bool = True
    timeout: int = 300


class SendCommandRequest(BaseModel):
    command: str


class ConsoleHistoryRequest(BaseModel):
    limit: OptionalType[int] = None


class ReverseShellSummary(BaseModel):
    total_connections: int
    listening_connections: int
    connected_connections: int
    disconnected_connections: int
    error_connections: int
    closed_connections: int


@router.post("/listeners", response_model=Dict[str, Any])
async def create_listener(request: CreateListenerRequest):
    """
    Create a new reverse shell listener.

    Args:
        request: Listener creation parameters

    Returns:
        Connection information
    """
    try:
        connection_id = reverse_shell_handler.create_listener(port=request.port)
        connection_info = reverse_shell_handler.get_connection_info(connection_id)

        if connection_info:
            # Convert datetime objects to ISO format for JSON serialization
            connection_info["created_at"] = connection_info["created_at"].isoformat()
            connection_info["last_activity"] = connection_info["last_activity"].isoformat()

        logger.info(f"Created reverse shell listener with ID {connection_id}")
        return {
            "success": True,
            "connection_id": connection_id,
            "connection_info": connection_info,
            "message": f"Reverse shell listener created on port {connection_info['port'] if connection_info else 'unknown'}",
        }

    except Exception as e:
        logger.error(f"Error creating reverse shell listener: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create listener: {str(e)}")


@router.get("/connections", response_model=List[ReverseShellConnection])
async def get_all_connections():
    """
    Get all reverse shell connections.

    Returns:
        List of all connection information
    """
    try:
        connections = reverse_shell_handler.get_all_connections()

        # Convert datetime objects to ISO format
        for conn in connections:
            if "created_at" in conn and conn["created_at"]:
                conn["created_at"] = conn["created_at"].isoformat()
            if "last_activity" in conn and conn["last_activity"]:
                conn["last_activity"] = conn["last_activity"].isoformat()

        return connections

    except Exception as e:
        logger.error(f"Error getting connections: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get connections: {str(e)}")


@router.get("/connections/{connection_id}", response_model=ReverseShellConnection)
async def get_connection_info(connection_id: str):
    """
    Get information about a specific reverse shell connection.

    Args:
        connection_id: The connection ID

    Returns:
        Connection information
    """
    try:
        connection_info = reverse_shell_handler.get_connection_info(connection_id)

        if not connection_info:
            raise HTTPException(status_code=404, detail="Connection not found")

        # Convert datetime objects to ISO format
        if "created_at" in connection_info and connection_info["created_at"]:
            connection_info["created_at"] = connection_info["created_at"].isoformat()
        if "last_activity" in connection_info and connection_info["last_activity"]:
            connection_info["last_activity"] = connection_info["last_activity"].isoformat()

        return connection_info

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting connection info for {connection_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get connection info: {str(e)}")


@router.post("/connections/{connection_id}/send", response_model=Dict[str, Any])
async def send_command(connection_id: str, request: SendCommandRequest):
    """
    Send a command to a reverse shell connection.

    Args:
        connection_id: The connection ID
        request: Command to send

    Returns:
        Success status
    """
    try:
        success = reverse_shell_handler.send_command(connection_id, request.command)

        if not success:
            raise HTTPException(
                status_code=400, detail="Failed to send command - connection may not be active"
            )

        logger.info(f"Sent command to connection {connection_id}: {request.command}")
        return {
            "success": True,
            "message": f"Command sent successfully to connection {connection_id}",
            "command": request.command,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error sending command to {connection_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to send command: {str(e)}")


@router.get("/connections/{connection_id}/history", response_model=Dict[str, Any])
async def get_console_history(connection_id: str, limit: OptionalType[int] = None):
    """
    Get console history for a reverse shell connection.

    Args:
        connection_id: The connection ID
        limit: Maximum number of lines to return

    Returns:
        Console history
    """
    try:
        history = reverse_shell_handler.get_console_history(connection_id, limit)

        return {
            "success": True,
            "connection_id": connection_id,
            "history": history,
            "history_size": len(history),
            "limit": limit,
        }

    except Exception as e:
        logger.error(f"Error getting console history for {connection_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get console history: {str(e)}")


@router.delete("/connections/{connection_id}", response_model=Dict[str, Any])
async def close_connection(connection_id: str):
    """
    Close a reverse shell connection.

    Args:
        connection_id: The connection ID

    Returns:
        Success status
    """
    try:
        success = reverse_shell_handler.close_connection(connection_id)

        if not success:
            raise HTTPException(status_code=404, detail="Connection not found")

        logger.info(f"Closed reverse shell connection {connection_id}")
        return {"success": True, "message": f"Connection {connection_id} closed successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error closing connection {connection_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to close connection: {str(e)}")


@router.get("/summary", response_model=ReverseShellSummary)
async def get_connections_summary():
    """
    Get a summary of all reverse shell connections.

    Returns:
        Connection summary statistics
    """
    try:
        connections = reverse_shell_handler.get_all_connections()

        summary = {
            "total_connections": len(connections),
            "listening_connections": 0,
            "connected_connections": 0,
            "disconnected_connections": 0,
            "error_connections": 0,
            "closed_connections": 0,
        }

        for conn in connections:
            status = conn.get("status", "unknown")
            if status == ShellStatus.LISTENING.value:
                summary["listening_connections"] += 1
            elif status == ShellStatus.CONNECTED.value:
                summary["connected_connections"] += 1
            elif status == ShellStatus.DISCONNECTED.value:
                summary["disconnected_connections"] += 1
            elif status == ShellStatus.ERROR.value:
                summary["error_connections"] += 1
            elif status == ShellStatus.CLOSED.value:
                summary["closed_connections"] += 1

        return summary

    except Exception as e:
        logger.error(f"Error getting connections summary: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get summary: {str(e)}")


@router.post("/cleanup", response_model=Dict[str, Any])
async def cleanup_inactive_connections(timeout_seconds: int = 300):
    """
    Clean up inactive reverse shell connections.

    Args:
        timeout_seconds: Timeout in seconds for inactive connections

    Returns:
        Cleanup results
    """
    try:
        cleaned_count = reverse_shell_handler.cleanup_inactive_connections(timeout_seconds)

        logger.info(f"Cleaned up {cleaned_count} inactive connections")
        return {
            "success": True,
            "cleaned_connections": cleaned_count,
            "timeout_seconds": timeout_seconds,
            "message": f"Cleaned up {cleaned_count} inactive connections",
        }

    except Exception as e:
        logger.error(f"Error cleaning up connections: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to cleanup connections: {str(e)}")


# WebSocket endpoint for real-time reverse shell interaction
@router.websocket("/ws/{connection_id}")
async def reverse_shell_websocket(websocket: WebSocket, connection_id: str):
    """
    WebSocket endpoint for real-time reverse shell interaction.

    Args:
        websocket: WebSocket connection
        connection_id: The reverse shell connection ID
    """
    await websocket.accept()
    logger.info(f"WebSocket connection established for reverse shell {connection_id}")

    try:
        # Register callback for real-time updates
        def on_data_received(conn_id: str, data: str):
            if conn_id == connection_id:
                asyncio.create_task(
                    websocket.send_text(
                        json.dumps(
                            {
                                "type": "data",
                                "connection_id": conn_id,
                                "data": data,
                                "timestamp": datetime.now().isoformat(),
                            }
                        )
                    )
                )

        def on_connection_status(conn_id: str, data: Any):
            if conn_id == connection_id:
                asyncio.create_task(
                    websocket.send_text(
                        json.dumps(
                            {
                                "type": "status",
                                "connection_id": conn_id,
                                "data": data,
                                "timestamp": datetime.now().isoformat(),
                            }
                        )
                    )
                )

        reverse_shell_handler.register_callback("data", on_data_received)
        reverse_shell_handler.register_callback("connection", on_connection_status)
        reverse_shell_handler.register_callback("disconnect", on_connection_status)
        reverse_shell_handler.register_callback("error", on_connection_status)

        # Send initial connection info
        connection_info = reverse_shell_handler.get_connection_info(connection_id)
        if connection_info:
            await websocket.send_text(
                json.dumps(
                    {
                        "type": "connection_info",
                        "connection_id": connection_id,
                        "data": connection_info,
                        "timestamp": datetime.now().isoformat(),
                    }
                )
            )

        # Handle incoming messages
        while True:
            try:
                message = await websocket.receive_text()
                data = json.loads(message)

                if data.get("type") == "command":
                    command = data.get("command", "")
                    success = reverse_shell_handler.send_command(connection_id, command)

                    await websocket.send_text(
                        json.dumps(
                            {
                                "type": "command_result",
                                "connection_id": connection_id,
                                "success": success,
                                "command": command,
                                "timestamp": datetime.now().isoformat(),
                            }
                        )
                    )

            except WebSocketDisconnect:
                logger.info(f"WebSocket disconnected for reverse shell {connection_id}")
                break
            except Exception as e:
                logger.error(f"Error in WebSocket for {connection_id}: {e}")
                await websocket.send_text(
                    json.dumps(
                        {
                            "type": "error",
                            "connection_id": connection_id,
                            "error": str(e),
                            "timestamp": datetime.now().isoformat(),
                        }
                    )
                )

    except Exception as e:
        logger.error(f"Error in reverse shell WebSocket: {e}")
    finally:
        try:
            await websocket.close()
        except Exception:
            pass
