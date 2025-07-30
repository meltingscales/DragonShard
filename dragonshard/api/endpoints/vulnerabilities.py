"""
Vulnerability analysis API endpoints
"""

import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query

from ..models import BaseResponse, Vulnerability, VulnerabilityLevel, VulnerabilitySummary
from ..websocket_manager import websocket_manager

logger = logging.getLogger(__name__)
router = APIRouter()

# Mock data storage
vulnerabilities: List[Vulnerability] = []


@router.get("/", response_model=List[Vulnerability])
async def get_vulnerabilities(
    level: Optional[VulnerabilityLevel] = Query(None, description="Filter by vulnerability level"),
    target: Optional[str] = Query(None, description="Filter by target"),
    limit: int = Query(50, description="Maximum number of vulnerabilities to return"),
):
    """Get all vulnerabilities"""
    try:
        filtered_vulns = vulnerabilities

        if level:
            filtered_vulns = [v for v in filtered_vulns if v.level == level]

        if target:
            filtered_vulns = [v for v in filtered_vulns if target in v.target]

        return filtered_vulns[:limit]
    except Exception as e:
        logger.error(f"Error getting vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/summary", response_model=VulnerabilitySummary)
async def get_vulnerability_summary():
    """Get vulnerability statistics summary"""
    try:
        total = len(vulnerabilities)
        critical_count = len([v for v in vulnerabilities if v.level == VulnerabilityLevel.CRITICAL])
        high_count = len([v for v in vulnerabilities if v.level == VulnerabilityLevel.HIGH])
        medium_count = len([v for v in vulnerabilities if v.level == VulnerabilityLevel.MEDIUM])
        low_count = len([v for v in vulnerabilities if v.level == VulnerabilityLevel.LOW])

        # Group by service
        by_service = {}
        for vuln in vulnerabilities:
            service = vuln.service or "unknown"
            by_service[service] = by_service.get(service, 0) + 1

        # Group by level
        by_level = {
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
        }

        return VulnerabilitySummary(
            total_vulnerabilities=total,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            by_service=by_service,
            by_level=by_level,
        )
    except Exception as e:
        logger.error(f"Error getting vulnerability summary: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/", response_model=Vulnerability)
async def create_vulnerability(vulnerability: Vulnerability):
    """Create a new vulnerability"""
    try:
        vulnerabilities.append(vulnerability)

        # Broadcast to WebSocket clients
        await websocket_manager.broadcast(
            {"type": "vulnerability_discovered", "data": vulnerability.dict()}
        )

        logger.info(f"Created vulnerability: {vulnerability.id}")
        return vulnerability
    except Exception as e:
        logger.error(f"Error creating vulnerability: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# Mock data for testing
def create_mock_vulnerabilities():
    """Create mock vulnerability data for testing"""
    global vulnerabilities

    mock_vulns = [
        Vulnerability(
            id="vuln_001",
            name="Log4Shell",
            description="Remote code execution via JNDI injection",
            level=VulnerabilityLevel.CRITICAL,
            cve_id="CVE-2021-44228",
            target="http://localhost:8085",
            service="http",
            port=8085,
            discovered_at=datetime.now(),
        ),
        Vulnerability(
            id="vuln_002",
            name="BlueKeep",
            description="Remote code execution in RDP service",
            level=VulnerabilityLevel.CRITICAL,
            cve_id="CVE-2019-0708",
            target="192.168.1.100",
            service="rdp",
            port=3389,
            discovered_at=datetime.now(),
        ),
        Vulnerability(
            id="vuln_003",
            name="SQL Injection",
            description="SQL injection in login form",
            level=VulnerabilityLevel.HIGH,
            target="http://localhost:8085/api/sql/complex",
            service="http",
            port=8085,
            discovered_at=datetime.now(),
        ),
    ]

    vulnerabilities = mock_vulns


# Initialize mock data
create_mock_vulnerabilities()
