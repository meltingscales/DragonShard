"""
Network topology API endpoints
"""

import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query

from ..models import Host, NetworkTopology, Service, ServiceType, Vulnerability
from ..websocket_manager import websocket_manager

logger = logging.getLogger(__name__)
router = APIRouter()

# Mock data storage
hosts: List[Host] = []


@router.get("/topology", response_model=NetworkTopology)
async def get_network_topology():
    """Get network topology"""
    try:
        total_services = sum(len(host.services) for host in hosts)
        total_vulnerabilities = sum(len(host.vulnerabilities) for host in hosts)

        return NetworkTopology(
            hosts=hosts,
            total_hosts=len(hosts),
            total_services=total_services,
            total_vulnerabilities=total_vulnerabilities,
        )
    except Exception as e:
        logger.error(f"Error getting network topology: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/hosts", response_model=List[Host])
async def get_hosts():
    """Get all hosts"""
    try:
        return hosts
    except Exception as e:
        logger.error(f"Error getting hosts: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/hosts/{host_id}", response_model=Host)
async def get_host(host_id: str):
    """Get specific host by ID"""
    try:
        for host in hosts:
            if host.id == host_id:
                return host

        raise HTTPException(status_code=404, detail="Host not found")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting host {host_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/hosts", response_model=Host)
async def create_host(host: Host):
    """Create a new host"""
    try:
        hosts.append(host)

        # Broadcast to WebSocket clients
        await websocket_manager.broadcast({"type": "host_discovered", "data": host.dict()})

        logger.info(f"Created host: {host.id}")
        return host
    except Exception as e:
        logger.error(f"Error creating host: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# Mock data for testing
def create_mock_network():
    """Create mock network data for testing"""
    global hosts

    # Create mock vulnerabilities
    log4shell_vuln = Vulnerability(
        id="vuln_001",
        name="Log4Shell",
        description="Remote code execution via JNDI injection",
        level="critical",
        cve_id="CVE-2021-44228",
        target="http://localhost:8085",
        service="http",
        port=8085,
        discovered_at=datetime.now(),
    )

    bluekeep_vuln = Vulnerability(
        id="vuln_002",
        name="BlueKeep",
        description="Remote code execution in RDP service",
        level="critical",
        cve_id="CVE-2019-0708",
        target="192.168.1.100",
        service="rdp",
        port=3389,
        discovered_at=datetime.now(),
    )

    # Create mock services
    http_service = Service(
        id="service_001",
        name="HTTP Server",
        type=ServiceType.HTTPS,
        port=8085,
        version="1.0.0",
        banner="nginx/1.18.0",
        discovered_at=datetime.now(),
        vulnerabilities=[log4shell_vuln],
    )

    rdp_service = Service(
        id="service_002",
        name="RDP Service",
        type=ServiceType.RDP,
        port=3389,
        version="10.0.19041.1",
        banner="Microsoft Terminal Services",
        discovered_at=datetime.now(),
        vulnerabilities=[bluekeep_vuln],
    )

    # Create mock host
    mock_host = Host(
        id="host_001",
        ip_address="192.168.1.100",
        hostname="test-server.local",
        os_info="Windows Server 2019",
        discovered_at=datetime.now(),
        last_seen=datetime.now(),
        services=[http_service, rdp_service],
        vulnerabilities=[log4shell_vuln, bluekeep_vuln],
    )

    hosts = [mock_host]


# Initialize mock data
create_mock_network()
