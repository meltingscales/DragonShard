#!/usr/bin/env python3
"""
DragonShard Scanner Service

Integrates the recon scanner with database storage for persistent scan results.
"""

import logging
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session as DBSession

from ..data.database import DatabaseManager
from ..data.models import Host, Service, Vulnerability, ServiceType, HostStatus, VulnerabilityLevel
from ..recon.scanner import run_scan, get_open_ports, scan_common_services

logger = logging.getLogger(__name__)


class ScannerService:
    """Service for performing network scans and storing results in the database."""

    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager

    def scan_host(self, host_id: str, scan_type: str = "comprehensive") -> Dict[str, Any]:
        """
        Scan a host and store results in the database.
        
        Args:
            host_id: ID of the host to scan
            scan_type: Type of scan ("quick", "comprehensive", "udp")
            
        Returns:
            Dictionary with scan results and status
        """
        try:
            # Get the host from database
            with self.db_manager.get_session() as session:
                host = session.query(Host).filter(Host.host_id == host_id).first()
                if not host:
                    raise ValueError(f"Host {host_id} not found")
                
                logger.info(f"Starting {scan_type} scan on host {host.ip_address}")
                
                # Perform the scan using existing scanner
                scan_results = run_scan(host.ip_address, scan_type)
                
                # Extract open ports
                open_ports = get_open_ports(scan_results)
                
                # Process scan results and store in database
                services_added = self._process_scan_results(host_id, open_ports, session)
                
                # Update host status
                host.status = HostStatus.SCANNED
                host.last_seen = time.time()
                session.commit()
                
                logger.info(f"Scan completed for host {host_id}. Found {services_added} services.")
                
                return {
                    "host_id": host_id,
                    "scan_type": scan_type,
                    "status": "completed",
                    "services_found": services_added,
                    "scan_results": scan_results
                }
                
        except Exception as e:
            logger.error(f"Error scanning host {host_id}: {e}")
            raise

    def _process_scan_results(self, host_id: str, open_ports: Dict[str, Any], session: DBSession) -> int:
        """
        Process scan results and store services in the database.
        
        Args:
            host_id: ID of the host
            open_ports: Dictionary with open ports from scan
            session: Database session
            
        Returns:
            Number of services added
        """
        services_added = 0
        
        for host_ip, port_data in open_ports.items():
            # Process TCP ports
            for port_info in port_data.get("tcp", []):
                service = self._create_service_from_scan(host_id, port_info, "tcp", session)
                if service:
                    services_added += 1
            
            # Process UDP ports
            for port_info in port_data.get("udp", []):
                service = self._create_service_from_scan(host_id, port_info, "udp", session)
                if service:
                    services_added += 1
        
        session.commit()
        return services_added

    def _create_service_from_scan(self, host_id: str, port_info: Dict[str, Any], protocol: str, session: DBSession) -> Optional[Service]:
        """
        Create a service record from scan results.
        
        Args:
            host_id: ID of the host
            port_info: Port information from scan
            protocol: Protocol (tcp/udp)
            session: Database session
            
        Returns:
            Created service object or None
        """
        try:
            port = port_info["port"]
            service_name = port_info.get("service", "unknown")
            version = port_info.get("version", "")
            product = port_info.get("product", "")
            
            # Generate service ID
            service_id = f"service_{host_id}_{protocol}_{port}_{uuid.uuid4().hex[:8]}"
            
            # Map service name to ServiceType
            service_type = self._map_service_type(service_name)
            
            # Create banner from product and version
            banner = ""
            if product:
                banner = product
                if version:
                    banner += f" {version}"
            elif version:
                banner = version
            
            # Check if service already exists
            existing_service = session.query(Service).filter(
                Service.host_id == host_id,
                Service.port == port,
                Service.protocol == protocol
            ).first()
            
            if existing_service:
                # Update existing service
                existing_service.service_type = service_type
                existing_service.banner = banner
                existing_service.version = version
                existing_service.last_seen = time.time()
                logger.debug(f"Updated existing service {existing_service.service_id}")
                return existing_service
            else:
                # Create new service
                service = Service(
                    service_id=service_id,
                    host_id=host_id,
                    port=port,
                    service_type=service_type,
                    protocol=protocol,
                    banner=banner,
                    version=version,
                    status="open",
                    discovered_at=time.time(),
                    last_seen=time.time()
                )
                
                session.add(service)
                logger.debug(f"Created new service {service_id} on port {port}")
                return service
                
        except Exception as e:
            logger.error(f"Error creating service from scan: {e}")
            return None

    def _map_service_type(self, service_name: str) -> ServiceType:
        """
        Map service name to ServiceType enum.
        
        Args:
            service_name: Name of the service from scan
            
        Returns:
            ServiceType enum value
        """
        service_name_lower = service_name.lower()
        
        if service_name_lower in ["http", "www"]:
            return ServiceType.HTTP
        elif service_name_lower in ["https", "ssl", "ssl/http"]:
            return ServiceType.HTTPS
        elif service_name_lower in ["ftp"]:
            return ServiceType.FTP
        elif service_name_lower in ["ssh"]:
            return ServiceType.SSH
        elif service_name_lower in ["smtp", "mail"]:
            return ServiceType.SMTP
        elif service_name_lower in ["dns", "domain"]:
            return ServiceType.DNS
        elif service_name_lower in ["mysql", "postgresql", "postgres", "mongodb", "redis", "database"]:
            return ServiceType.DATABASE
        elif service_name_lower in ["api", "rest", "soap"]:
            return ServiceType.API
        elif service_name_lower in ["websocket", "ws"]:
            return ServiceType.WEBSOCKET
        else:
            return ServiceType.UNKNOWN

    def get_scan_status(self, host_id: str) -> Dict[str, Any]:
        """
        Get scan status for a host.
        
        Args:
            host_id: ID of the host
            
        Returns:
            Dictionary with scan status information
        """
        try:
            with self.db_manager.get_session() as session:
                host = session.query(Host).filter(Host.host_id == host_id).first()
                if not host:
                    return {"error": "Host not found"}
                
                services = session.query(Service).filter(Service.host_id == host_id).all()
                vulnerabilities = session.query(Vulnerability).join(Service).filter(Service.host_id == host_id).all()
                
                return {
                    "host_id": host_id,
                    "status": host.status.value,
                    "services_count": len(services),
                    "vulnerabilities_count": len(vulnerabilities),
                    "last_scan": host.last_seen,
                    "discovered_at": host.discovered_at
                }
                
        except Exception as e:
            logger.error(f"Error getting scan status for host {host_id}: {e}")
            return {"error": str(e)}

    def get_scan_results(self, host_id: str) -> Dict[str, Any]:
        """
        Get detailed scan results for a host.
        
        Args:
            host_id: ID of the host
            
        Returns:
            Dictionary with detailed scan results
        """
        try:
            with self.db_manager.get_session() as session:
                host = session.query(Host).filter(Host.host_id == host_id).first()
                if not host:
                    return {"error": "Host not found"}
                
                services = session.query(Service).filter(Service.host_id == host_id).all()
                vulnerabilities = session.query(Vulnerability).join(Service).filter(Service.host_id == host_id).all()
                
                return {
                    "host_id": host_id,
                    "scan_completed": host.status == HostStatus.SCANNED,
                    "services_found": len(services),
                    "vulnerabilities_found": len(vulnerabilities),
                    "services": [service.to_dict() for service in services],
                    "vulnerabilities": [vuln.to_dict() for vuln in vulnerabilities],
                    "host_info": host.to_dict()
                }
                
        except Exception as e:
            logger.error(f"Error getting scan results for host {host_id}: {e}")
            return {"error": str(e)} 