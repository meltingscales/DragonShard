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


@router.delete("/hosts/{host_id}")
async def delete_host(host_id: str):
    """Delete a host"""
    try:
        for i, host in enumerate(hosts):
            if host.id == host_id:
                deleted_host = hosts.pop(i)
                logger.info(f"Deleted host: {host_id}")
                return {"message": "Host deleted successfully"}
        
        raise HTTPException(status_code=404, detail="Host not found")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting host {host_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/hosts/{host_id}/scan")
async def scan_host(host_id: str):
    """Start a scan on a host"""
    try:
        # Find the host
        host = None
        for h in hosts:
            if h.id == host_id:
                host = h
                break
        
        if not host:
            raise HTTPException(status_code=404, detail="Host not found")
        
        # Mock scan operation - in real implementation, this would trigger actual scanning
        logger.info(f"Starting scan on host: {host_id}")
        
        # Broadcast scan start to WebSocket clients
        await websocket_manager.broadcast({
            "type": "scan_started", 
            "data": {"host_id": host_id, "status": "running"}
        })
        
        return {"message": "Scan started successfully", "host_id": host_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting scan on host {host_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/hosts/{host_id}/scan/status")
async def get_scan_status(host_id: str):
    """Get scan status for a host"""
    try:
        # Find the host
        host = None
        for h in hosts:
            if h.id == host_id:
                host = h
                break
        
        if not host:
            raise HTTPException(status_code=404, detail="Host not found")
        
        # Mock scan status - in real implementation, this would check actual scan status
        return {
            "host_id": host_id,
            "status": "completed",  # Mock status
            "progress": 100,
            "last_scan": datetime.now().isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting scan status for host {host_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/hosts/{host_id}/scan/results")
async def get_scan_results(host_id: str):
    """Get scan results for a host"""
    try:
        # Find the host
        host = None
        for h in hosts:
            if h.id == host_id:
                host = h
                break
        
        if not host:
            raise HTTPException(status_code=404, detail="Host not found")
        
        # Return the host's vulnerabilities as scan results
        return {
            "host_id": host_id,
            "scan_completed": True,
            "vulnerabilities_found": len(host.vulnerabilities),
            "services_discovered": len(host.services),
            "vulnerabilities": host.vulnerabilities,
            "services": host.services
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting scan results for host {host_id}: {e}")
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
