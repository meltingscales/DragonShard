"""
Data export API endpoints
"""

import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict

from fastapi import APIRouter, HTTPException

from ..models import BaseResponse, ExportRequest, ExportResponse
from ..websocket_manager import websocket_manager

logger = logging.getLogger(__name__)
router = APIRouter()

# Mock export storage
exports: Dict[str, Dict[str, Any]] = {}


@router.post("/", response_model=ExportResponse)
async def create_export(export_request: ExportRequest):
    """Create a new data export"""
    try:
        export_id = str(uuid.uuid4())

        # Mock export data (in production, this would query the actual data)
        mock_data = {
            "attacks": [
                {
                    "id": "attack_001",
                    "name": "Log4Shell Attack",
                    "status": "running",
                    "steps": [
                        {"name": "Authentication", "status": "completed"},
                        {"name": "Log Injection", "status": "running"},
                    ],
                }
            ],
            "vulnerabilities": [
                {
                    "id": "vuln_001",
                    "name": "Log4Shell",
                    "level": "critical",
                    "cve_id": "CVE-2021-44228",
                }
            ],
            "network": {
                "hosts": [
                    {"ip": "192.168.1.100", "services": ["http", "rdp"], "vulnerabilities": 2}
                ]
            },
            "fuzzing": {
                "sessions": [
                    {
                        "id": "fuzz_001",
                        "name": "SQL Injection Fuzzing",
                        "generation": 15,
                        "best_fitness": 0.85,
                    }
                ]
            },
            "sessions": [
                {
                    "id": "session_001",
                    "target": "http://localhost:8085",
                    "authenticated": True,
                    "requests_count": 15,
                }
            ],
        }

        # Generate export data based on request
        if export_request.data_type == "attacks":
            export_data = mock_data["attacks"]
        elif export_request.data_type == "vulnerabilities":
            export_data = mock_data["vulnerabilities"]
        elif export_request.data_type == "network":
            export_data = mock_data["network"]
        elif export_request.data_type == "fuzzing":
            export_data = mock_data["fuzzing"]
        elif export_request.data_type == "sessions":
            export_data = mock_data["sessions"]
        else:
            export_data = mock_data

        # Apply filters if provided
        if export_request.filters:
            # Simple filter implementation
            if "status" in export_request.filters:
                if isinstance(export_data, list):
                    export_data = [
                        item
                        for item in export_data
                        if item.get("status") == export_request.filters["status"]
                    ]

        # Generate file content based on format
        if export_request.format == "json":
            file_content = json.dumps(export_data, indent=2, default=str)
        elif export_request.format == "csv":
            # Simple CSV conversion
            if isinstance(export_data, list) and export_data:
                headers = list(export_data[0].keys())
                csv_content = ",".join(headers) + "\n"
                for item in export_data:
                    row = ",".join(str(item.get(h, "")) for h in headers)
                    csv_content += row + "\n"
                file_content = csv_content
            else:
                file_content = ""
        else:
            file_content = str(export_data)

        # Store export
        exports[export_id] = {
            "data_type": export_request.data_type,
            "format": export_request.format,
            "filters": export_request.filters,
            "include_details": export_request.include_details,
            "content": file_content,
            "created_at": datetime.now(),
            "expires_at": datetime.now() + timedelta(hours=24),
        }

        # Create response
        export_response = ExportResponse(
            export_id=export_id,
            data_type=export_request.data_type,
            format=export_request.format,
            file_size=len(file_content.encode("utf-8")),
            download_url=f"/api/v1/export/{export_id}/download",
            expires_at=datetime.now() + timedelta(hours=24),
        )

        # Broadcast to WebSocket clients
        await websocket_manager.broadcast(
            {"type": "export_created", "data": export_response.dict()}
        )

        logger.info(f"Created export: {export_id}")
        return export_response
    except Exception as e:
        logger.error(f"Error creating export: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/{export_id}/download")
async def download_export(export_id: str):
    """Download an export file"""
    try:
        if export_id not in exports:
            raise HTTPException(status_code=404, detail="Export not found")

        export_data = exports[export_id]

        # Check if expired
        if datetime.now() > export_data["expires_at"]:
            raise HTTPException(status_code=410, detail="Export has expired")

        content = export_data["content"]
        format_type = export_data["format"]

        # Set appropriate content type
        if format_type == "json":
            media_type = "application/json"
        elif format_type == "csv":
            media_type = "text/csv"
        else:
            media_type = "text/plain"

        from fastapi.responses import Response

        return Response(
            content=content,
            media_type=media_type,
            headers={
                "Content-Disposition": f"attachment; filename=dragonshard_export_{export_id}.{format_type}"
            },
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error downloading export: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/{export_id}", response_model=ExportResponse)
async def get_export(export_id: str):
    """Get export information"""
    try:
        if export_id not in exports:
            raise HTTPException(status_code=404, detail="Export not found")

        export_data = exports[export_id]

        return ExportResponse(
            export_id=export_id,
            data_type=export_data["data_type"],
            format=export_data["format"],
            file_size=len(export_data["content"].encode("utf-8")),
            download_url=f"/api/v1/export/{export_id}/download",
            expires_at=export_data["expires_at"],
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting export: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/{export_id}", response_model=BaseResponse)
async def delete_export(export_id: str):
    """Delete an export"""
    try:
        if export_id not in exports:
            raise HTTPException(status_code=404, detail="Export not found")

        del exports[export_id]

        # Broadcast to WebSocket clients
        await websocket_manager.broadcast(
            {"type": "export_deleted", "data": {"export_id": export_id}}
        )

        logger.info(f"Deleted export: {export_id}")
        return BaseResponse(message=f"Export {export_id} deleted successfully")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting export: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
