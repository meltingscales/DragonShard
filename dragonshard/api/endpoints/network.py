"""
Network topology API endpoints
"""

import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query

from ..models import Host, NetworkTopology, Service, ServiceType, Vulnerability, VulnerabilityLevel
from ..websocket_manager import websocket_manager
from ...core.scanner_service import ScannerService
from ...data.database import DatabaseManager

logger = logging.getLogger(__name__)
router = APIRouter()

# Initialize database and scanner service
db_manager = DatabaseManager()
scanner_service = ScannerService(db_manager)


def map_database_service_type_to_api(db_service_type_value: str) -> ServiceType:
    """Map database service type to API service type."""
    mapping = {
        "http": ServiceType.HTTP,
        "https": ServiceType.HTTPS,
        "ssh": ServiceType.SSH,
        "ftp": ServiceType.FTP,
        "smtp": ServiceType.SMTP,
        "dns": ServiceType.DNS,
        "database": ServiceType.MYSQL,  # Map database to mysql as closest match
        "api": ServiceType.HTTP,  # Map api to http as closest match
        "websocket": ServiceType.HTTP,  # Map websocket to http as closest match
        "unknown": ServiceType.HTTP,  # Map unknown to http as default
    }
    return mapping.get(db_service_type_value.lower(), ServiceType.HTTP)


@router.get("/topology", response_model=NetworkTopology)
async def get_network_topology():
    """Get network topology"""
    try:
        with db_manager.get_session() as session:
            from ...data.models import Host as DBHost, Service as DBService, Vulnerability as DBVulnerability
            
            # Get all hosts from database
            db_hosts = session.query(DBHost).all()
            
            # Convert to API models
            hosts = []
            total_services = 0
            total_vulnerabilities = 0
            
            for db_host in db_hosts:
                # Get services for this host
                db_services = session.query(DBService).filter(DBService.host_id == db_host.host_id).all()
                services = []
                for db_service in db_services:
                    # Map database service_type to API ServiceType enum
                    service_type = map_database_service_type_to_api(db_service.service_type.value if db_service.service_type else "unknown")
                    
                    service = Service(
                        id=db_service.service_id,
                        name=db_service.service_type.value if db_service.service_type else "unknown",
                        type=service_type,
                        port=db_service.port,
                        version=db_service.version,
                        banner=db_service.banner,
                        discovered_at=datetime.fromtimestamp(db_service.discovered_at),
                        vulnerabilities=[]  # Will be populated separately
                    )
                    services.append(service)
                
                # Get vulnerabilities for this host
                db_vulnerabilities = session.query(DBVulnerability).join(DBService).filter(DBService.host_id == db_host.host_id).all()
                vulnerabilities = []
                for db_vuln in db_vulnerabilities:
                    # Map database severity to API VulnerabilityLevel enum
                    level = VulnerabilityLevel.LOW
                    if db_vuln.severity:
                        try:
                            level = VulnerabilityLevel(db_vuln.severity.value)
                        except ValueError:
                            level = VulnerabilityLevel.LOW
                    
                    vulnerability = Vulnerability(
                        id=db_vuln.vuln_id,
                        name=db_vuln.vuln_type,
                        description=db_vuln.description,
                        level=level,
                        cve_id=db_vuln.cve_id,
                        target=db_vuln.service.host.ip_address if db_vuln.service and db_vuln.service.host else "",
                        service=db_vuln.service.service_type.value if db_vuln.service and db_vuln.service.service_type else None,
                        port=db_vuln.service.port if db_vuln.service else None,
                        discovered_at=datetime.fromtimestamp(db_vuln.discovered_at),
                        details={}  # Could be populated from evidence field
                    )
                    vulnerabilities.append(vulnerability)
                
                total_services += len(services)
                total_vulnerabilities += len(vulnerabilities)
                
                # Convert to API model
                host = Host(
                    id=db_host.host_id,
                    ip_address=db_host.ip_address,
                    hostname=db_host.hostname,
                    os_info=db_host.os_info,
                    discovered_at=datetime.fromtimestamp(db_host.discovered_at),
                    last_seen=datetime.fromtimestamp(db_host.last_seen),
                    services=services,
                    vulnerabilities=vulnerabilities
                )
                hosts.append(host)

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
        with db_manager.get_session() as session:
            from ...data.models import Host as DBHost, Service as DBService, Vulnerability as DBVulnerability
            
            # Get all hosts from database
            db_hosts = session.query(DBHost).all()
            
            # Convert to API models
            hosts = []
            
            for db_host in db_hosts:
                # Get services for this host
                db_services = session.query(DBService).filter(DBService.host_id == db_host.host_id).all()
                services = []
                for db_service in db_services:
                    # Map database service_type to API ServiceType enum
                    service_type = map_database_service_type_to_api(db_service.service_type.value if db_service.service_type else "unknown")
                    
                    service = Service(
                        id=db_service.service_id,
                        name=db_service.service_type.value if db_service.service_type else "unknown",
                        type=service_type,
                        port=db_service.port,
                        version=db_service.version,
                        banner=db_service.banner,
                        discovered_at=datetime.fromtimestamp(db_service.discovered_at),
                        vulnerabilities=[]  # Will be populated separately
                    )
                    services.append(service)
                
                # Get vulnerabilities for this host
                db_vulnerabilities = session.query(DBVulnerability).join(DBService).filter(DBService.host_id == db_host.host_id).all()
                vulnerabilities = []
                for db_vuln in db_vulnerabilities:
                    # Map database severity to API VulnerabilityLevel enum
                    level = VulnerabilityLevel.LOW
                    if db_vuln.severity:
                        try:
                            level = VulnerabilityLevel(db_vuln.severity.value)
                        except ValueError:
                            level = VulnerabilityLevel.LOW
                    
                    vulnerability = Vulnerability(
                        id=db_vuln.vuln_id,
                        name=db_vuln.vuln_type,
                        description=db_vuln.description,
                        level=level,
                        cve_id=db_vuln.cve_id,
                        target=db_vuln.service.host.ip_address if db_vuln.service and db_vuln.service.host else "",
                        service=db_vuln.service.service_type.value if db_vuln.service and db_vuln.service.service_type else None,
                        port=db_vuln.service.port if db_vuln.service else None,
                        discovered_at=datetime.fromtimestamp(db_vuln.discovered_at),
                        details={}  # Could be populated from evidence field
                    )
                    vulnerabilities.append(vulnerability)
                
                # Convert to API model
                host = Host(
                    id=db_host.host_id,
                    ip_address=db_host.ip_address,
                    hostname=db_host.hostname,
                    os_info=db_host.os_info,
                    discovered_at=datetime.fromtimestamp(db_host.discovered_at),
                    last_seen=datetime.fromtimestamp(db_host.last_seen),
                    services=services,
                    vulnerabilities=vulnerabilities
                )
                hosts.append(host)

        return hosts
    except Exception as e:
        logger.error(f"Error getting hosts: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/hosts/{host_id}", response_model=Host)
async def get_host(host_id: str):
    """Get specific host by ID"""
    try:
        with db_manager.get_session() as session:
            from ...data.models import Host as DBHost, Service as DBService, Vulnerability as DBVulnerability
            
            # Get host from database
            db_host = session.query(DBHost).filter(DBHost.host_id == host_id).first()
            if not db_host:
                raise HTTPException(status_code=404, detail="Host not found")
            
            # Get services for this host
            db_services = session.query(DBService).filter(DBService.host_id == host_id).all()
            services = []
            for db_service in db_services:
                # Map database service_type to API ServiceType enum
                service_type = map_database_service_type_to_api(db_service.service_type.value if db_service.service_type else "unknown")
                
                service = Service(
                    id=db_service.service_id,
                    name=db_service.service_type.value if db_service.service_type else "unknown",
                    type=service_type,
                    port=db_service.port,
                    version=db_service.version,
                    banner=db_service.banner,
                    discovered_at=datetime.fromtimestamp(db_service.discovered_at),
                    vulnerabilities=[]  # Will be populated separately
                )
                services.append(service)
            
            # Get vulnerabilities for this host
            db_vulnerabilities = session.query(DBVulnerability).join(DBService).filter(DBService.host_id == host_id).all()
            vulnerabilities = []
            for db_vuln in db_vulnerabilities:
                # Map database severity to API VulnerabilityLevel enum
                level = VulnerabilityLevel.LOW
                if db_vuln.severity:
                    try:
                        level = VulnerabilityLevel(db_vuln.severity.value)
                    except ValueError:
                        level = VulnerabilityLevel.LOW
                
                vulnerability = Vulnerability(
                    id=db_vuln.vuln_id,
                    name=db_vuln.vuln_type,
                    description=db_vuln.description,
                    level=level,
                    cve_id=db_vuln.cve_id,
                    target=db_vuln.service.host.ip_address if db_vuln.service and db_vuln.service.host else "",
                    service=db_vuln.service.service_type.value if db_vuln.service and db_vuln.service.service_type else None,
                    port=db_vuln.service.port if db_vuln.service else None,
                    discovered_at=datetime.fromtimestamp(db_vuln.discovered_at),
                    details={}  # Could be populated from evidence field
                )
                vulnerabilities.append(vulnerability)
            
            # Convert to API model
            host = Host(
                id=db_host.host_id,
                ip_address=db_host.ip_address,
                hostname=db_host.hostname,
                os_info=db_host.os_info,
                discovered_at=datetime.fromtimestamp(db_host.discovered_at),
                last_seen=datetime.fromtimestamp(db_host.last_seen),
                services=services,
                vulnerabilities=vulnerabilities
            )
            
            return host
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting host {host_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


from pydantic import BaseModel
from datetime import datetime
import uuid

# Add this model for the simple target creation request
class CreateTargetRequest(BaseModel):
    ip_address: str
    hostname: Optional[str] = None
    description: Optional[str] = None

@router.post("/hosts", response_model=Host)
async def create_host(host: Host):
    """Create a new host with full Host object"""
    try:
        hosts.append(host)

        # Broadcast to WebSocket clients
        await websocket_manager.broadcast({"type": "host_discovered", "data": host.dict()})

        logger.info(f"Created host: {host.id}")
        return host
    except Exception as e:
        logger.error(f"Error creating host: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/hosts/simple", response_model=Host)
async def create_simple_host(request: CreateTargetRequest):
    """Create a new host from simple form data"""
    try:
        import uuid
        import time
        
        # Generate a unique ID
        host_id = f"host_{uuid.uuid4().hex[:8]}"
        
        # Create host in database
        with db_manager.get_session() as session:
            from ...data.models import Host as DBHost, HostStatus
            
            db_host = DBHost(
                host_id=host_id,
                hostname=request.hostname or request.ip_address,
                ip_address=request.ip_address,
                status=HostStatus.DISCOVERED,
                discovered_at=time.time(),
                last_seen=time.time(),
                os_info=None,  # Will be discovered during scan
                mac_address=None,
                hostnames="[]",
                notes=request.description or ""
            )
            
            session.add(db_host)
            session.commit()
            
            # Convert to API model for response
            new_host = Host(
                id=host_id,
                ip_address=request.ip_address,
                hostname=request.hostname,
                os_info=None,
                discovered_at=datetime.fromtimestamp(db_host.discovered_at),
                last_seen=datetime.fromtimestamp(db_host.last_seen),
                services=[],
                vulnerabilities=[]
            )

        # Broadcast to WebSocket clients
        await websocket_manager.broadcast({"type": "host_discovered", "data": new_host.dict()})

        logger.info(f"Created simple host: {host_id}")
        return new_host
    except Exception as e:
        logger.error(f"Error creating simple host: {e}")
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
        # Use the scanner service to perform real scanning
        scan_result = scanner_service.scan_host(host_id, "comprehensive")
        
        # Broadcast scan completion to WebSocket clients
        await websocket_manager.broadcast({
            "type": "scan_completed", 
            "data": {
                "host_id": host_id, 
                "status": "completed",
                "services_found": scan_result["services_found"]
            }
        })
        
        return {
            "message": "Scan completed successfully", 
            "host_id": host_id,
            "services_found": scan_result["services_found"]
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error scanning host {host_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/hosts/{host_id}/scan/status")
async def get_scan_status(host_id: str):
    """Get scan status for a host"""
    try:
        status = scanner_service.get_scan_status(host_id)
        
        if "error" in status:
            raise HTTPException(status_code=404, detail=status["error"])
        
        return {
            "host_id": host_id,
            "status": status["status"],
            "services_count": status["services_count"],
            "vulnerabilities_count": status["vulnerabilities_count"],
            "last_scan": datetime.fromtimestamp(status["last_scan"]).isoformat(),
            "discovered_at": datetime.fromtimestamp(status["discovered_at"]).isoformat()
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
        results = scanner_service.get_scan_results(host_id)
        
        if "error" in results:
            raise HTTPException(status_code=404, detail=results["error"])
        
        return {
            "host_id": host_id,
            "scan_completed": results["scan_completed"],
            "services_found": results["services_found"],
            "vulnerabilities_found": results["vulnerabilities_found"],
            "services": results["services"],
            "vulnerabilities": results["vulnerabilities"],
            "host_info": results["host_info"]
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting scan results for host {host_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# Initialize database tables if needed
def init_database():
    """Initialize database tables if they don't exist"""
    try:
        db_manager.create_tables()
        logger.info("Database tables initialized")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")

# Initialize database
init_database()
