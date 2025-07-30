#!/usr/bin/env python3
"""
DragonShard State Graph Module

Builds and maintains a graph representation of hosts, services,
and their relationships discovered during attack execution.
"""

import json
import logging
import time
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import networkx as nx

logger = logging.getLogger(__name__)


class ServiceType(Enum):
    """Types of services."""

    HTTP = "http"
    HTTPS = "https"
    FTP = "ftp"
    SSH = "ssh"
    SMTP = "smtp"
    DNS = "dns"
    DATABASE = "database"
    API = "api"
    WEBSOCKET = "websocket"
    UNKNOWN = "unknown"


class HostStatus(Enum):
    """Host status."""

    DISCOVERED = "discovered"
    SCANNED = "scanned"
    VULNERABLE = "vulnerable"
    COMPROMISED = "compromised"
    BLOCKED = "blocked"
    OFFLINE = "offline"


class VulnerabilityLevel(Enum):
    """Vulnerability severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ServiceInfo:
    """Information about a service."""

    service_id: str
    host: str
    port: int
    service_type: ServiceType
    protocol: str
    banner: Optional[str] = None
    version: Optional[str] = None
    status: str = "open"
    discovered_at: float = None
    last_seen: float = None
    vulnerabilities: List[str] = None
    credentials: Dict[str, str] = None

    def __post_init__(self):
        if self.discovered_at is None:
            self.discovered_at = time.time()
        if self.last_seen is None:
            self.last_seen = time.time()
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.credentials is None:
            self.credentials = {}


@dataclass
class HostInfo:
    """Information about a host."""

    host_id: str
    hostname: str
    ip_address: str
    status: HostStatus
    discovered_at: float
    last_seen: float
    services: List[str] = None  # List of service IDs
    vulnerabilities: List[str] = None
    os_info: Optional[str] = None
    mac_address: Optional[str] = None
    hostnames: List[str] = None
    notes: str = ""

    def __post_init__(self):
        if self.services is None:
            self.services = []
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.hostnames is None:
            self.hostnames = []


@dataclass
class VulnerabilityInfo:
    """Information about a vulnerability."""

    vuln_id: str
    service_id: str
    vuln_type: str
    severity: VulnerabilityLevel
    description: str
    discovered_at: float
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    exploit_available: bool = False
    exploited: bool = False
    evidence: str = ""
    remediation: str = ""

    def __post_init__(self):
        if self.discovered_at is None:
            self.discovered_at = time.time()


@dataclass
class ConnectionInfo:
    """Information about a connection between hosts."""

    connection_id: str
    source_host: str
    target_host: str
    connection_type: str  # e.g., "http_request", "dns_query", "ssh_connection"
    protocol: str
    port: int
    established_at: float
    last_seen: float
    data_transferred: int = 0
    status: str = "active"

    def __post_init__(self):
        if self.established_at is None:
            self.established_at = time.time()
        if self.last_seen is None:
            self.last_seen = time.time()


class StateGraph:
    """
    Maintains a graph representation of the attack environment,
    including hosts, services, vulnerabilities, and relationships.
    """

    def __init__(self):
        """Initialize the state graph."""
        self.graph = nx.DiGraph()

        # Data storage
        self.hosts: Dict[str, HostInfo] = {}
        self.services: Dict[str, ServiceInfo] = {}
        self.vulnerabilities: Dict[str, VulnerabilityInfo] = {}
        self.connections: Dict[str, ConnectionInfo] = {}

        # Graph metadata
        self.graph_metadata = {
            "created_at": time.time(),
            "last_updated": time.time(),
            "total_hosts": 0,
            "total_services": 0,
            "total_vulnerabilities": 0,
            "total_connections": 0,
        }

        logger.info("StateGraph initialized successfully")

    def add_host(
        self, hostname: str, ip_address: str, status: HostStatus = HostStatus.DISCOVERED
    ) -> str:
        """
        Add a host to the state graph.

        Args:
            hostname: Hostname or domain
            ip_address: IP address
            status: Host status

        Returns:
            Host ID
        """
        host_id = f"host_{hash(ip_address)}"

        if host_id in self.hosts:
            # Update existing host
            host = self.hosts[host_id]
            host.last_seen = time.time()
            host.status = status
            if hostname not in host.hostnames:
                host.hostnames.append(hostname)
        else:
            # Create new host
            host = HostInfo(
                host_id=host_id,
                hostname=hostname,
                ip_address=ip_address,
                status=status,
                discovered_at=time.time(),
                last_seen=time.time(),
                hostnames=[hostname],
            )
            self.hosts[host_id] = host

            # Add node to graph
            self.graph.add_node(host_id, type="host", data=host)

        self._update_metadata()
        logger.info(f"Added/updated host: {hostname} ({ip_address})")

        return host_id

    def add_service(
        self,
        host_id: str,
        port: int,
        service_type: ServiceType,
        protocol: str = "tcp",
        banner: Optional[str] = None,
    ) -> str:
        """
        Add a service to the state graph.

        Args:
            host_id: Host ID
            port: Port number
            service_type: Type of service
            protocol: Protocol (tcp/udp)
            banner: Service banner

        Returns:
            Service ID
        """
        service_id = f"service_{host_id}_{port}_{protocol}"

        if service_id in self.services:
            # Update existing service
            service = self.services[service_id]
            service.last_seen = time.time()
            if banner:
                service.banner = banner
        else:
            # Create new service
            service = ServiceInfo(
                service_id=service_id,
                host=host_id,
                port=port,
                service_type=service_type,
                protocol=protocol,
                banner=banner,
            )
            self.services[service_id] = service

            # Add node to graph
            self.graph.add_node(service_id, type="service", data=service)

            # Add edge from host to service
            self.graph.add_edge(host_id, service_id, relationship="hosts")

        # Update host's service list
        if host_id in self.hosts:
            if service_id not in self.hosts[host_id].services:
                self.hosts[host_id].services.append(service_id)

        self._update_metadata()
        logger.info(f"Added/updated service: {service_type.value} on {host_id}:{port}")

        return service_id

    def add_vulnerability(
        self,
        service_id: str,
        vuln_type: str,
        severity: VulnerabilityLevel,
        description: str,
        evidence: str = "",
    ) -> str:
        """
        Add a vulnerability to the state graph.

        Args:
            service_id: Service ID
            vuln_type: Type of vulnerability
            severity: Vulnerability severity
            description: Vulnerability description
            evidence: Evidence of the vulnerability

        Returns:
            Vulnerability ID
        """
        vuln_id = f"vuln_{service_id}_{vuln_type}_{int(time.time())}"

        vuln = VulnerabilityInfo(
            vuln_id=vuln_id,
            service_id=service_id,
            vuln_type=vuln_type,
            severity=severity,
            description=description,
            discovered_at=time.time(),
            evidence=evidence,
        )

        self.vulnerabilities[vuln_id] = vuln

        # Add node to graph
        self.graph.add_node(vuln_id, type="vulnerability", data=vuln)

        # Add edge from service to vulnerability
        self.graph.add_edge(service_id, vuln_id, relationship="vulnerable_to")

        # Update service's vulnerability list
        if service_id in self.services:
            self.services[service_id].vulnerabilities.append(vuln_id)

        # Update host's vulnerability list
        service = self.services.get(service_id)
        if service and service.host in self.hosts:
            if vuln_id not in self.hosts[service.host].vulnerabilities:
                self.hosts[service.host].vulnerabilities.append(vuln_id)

        self._update_metadata()
        logger.info(f"Added vulnerability: {vuln_type} ({severity.value}) on {service_id}")

        return vuln_id

    def add_connection(
        self, source_host: str, target_host: str, connection_type: str, protocol: str, port: int
    ) -> str:
        """
        Add a connection between hosts.

        Args:
            source_host: Source host ID
            target_host: Target host ID
            connection_type: Type of connection
            protocol: Protocol used
            port: Port number

        Returns:
            Connection ID
        """
        connection_id = f"conn_{source_host}_{target_host}_{protocol}_{port}"

        if connection_id in self.connections:
            # Update existing connection
            conn = self.connections[connection_id]
            conn.last_seen = time.time()
        else:
            # Create new connection
            conn = ConnectionInfo(
                connection_id=connection_id,
                source_host=source_host,
                target_host=target_host,
                connection_type=connection_type,
                protocol=protocol,
                port=port,
                established_at=time.time(),
                last_seen=time.time(),
            )
            self.connections[connection_id] = conn

            # Add edge to graph
            self.graph.add_edge(source_host, target_host, relationship="connects_to", data=conn)

        self._update_metadata()
        logger.info(f"Added/updated connection: {source_host} -> {target_host}")

        return connection_id

    def get_host_info(self, host_id: str) -> Optional[HostInfo]:
        """
        Get information about a host.

        Args:
            host_id: Host ID

        Returns:
            HostInfo or None
        """
        return self.hosts.get(host_id)

    def get_service_info(self, service_id: str) -> Optional[ServiceInfo]:
        """
        Get information about a service.

        Args:
            service_id: Service ID

        Returns:
            ServiceInfo or None
        """
        return self.services.get(service_id)

    def get_vulnerability_info(self, vuln_id: str) -> Optional[VulnerabilityInfo]:
        """
        Get information about a vulnerability.

        Args:
            vuln_id: Vulnerability ID

        Returns:
            VulnerabilityInfo or None
        """
        return self.vulnerabilities.get(vuln_id)

    def get_host_services(self, host_id: str) -> List[ServiceInfo]:
        """
        Get all services for a host.

        Args:
            host_id: Host ID

        Returns:
            List of ServiceInfo objects
        """
        if host_id not in self.hosts:
            return []

        return [self.services[sid] for sid in self.hosts[host_id].services if sid in self.services]

    def get_host_vulnerabilities(self, host_id: str) -> List[VulnerabilityInfo]:
        """
        Get all vulnerabilities for a host.

        Args:
            host_id: Host ID

        Returns:
            List of VulnerabilityInfo objects
        """
        if host_id not in self.hosts:
            return []

        return [
            self.vulnerabilities[vid]
            for vid in self.hosts[host_id].vulnerabilities
            if vid in self.vulnerabilities
        ]

    def get_service_vulnerabilities(self, service_id: str) -> List[VulnerabilityInfo]:
        """
        Get all vulnerabilities for a service.

        Args:
            service_id: Service ID

        Returns:
            List of VulnerabilityInfo objects
        """
        if service_id not in self.services:
            return []

        return [
            self.vulnerabilities[vid]
            for vid in self.services[service_id].vulnerabilities
            if vid in self.vulnerabilities
        ]

    def get_connected_hosts(self, host_id: str) -> List[str]:
        """
        Get all hosts connected to a given host.

        Args:
            host_id: Host ID

        Returns:
            List of connected host IDs
        """
        if host_id not in self.graph:
            return []

        connected = []
        for neighbor in self.graph.neighbors(host_id):
            if self.graph.nodes[neighbor].get("type") == "host":
                connected.append(neighbor)

        return connected

    def get_path_between_hosts(self, source_host: str, target_host: str) -> List[str]:
        """
        Get the shortest path between two hosts.

        Args:
            source_host: Source host ID
            target_host: Target host ID

        Returns:
            List of nodes in the path
        """
        try:
            path = nx.shortest_path(self.graph, source_host, target_host)
            return path
        except nx.NetworkXNoPath:
            return []

    def get_critical_paths(self) -> List[List[str]]:
        """
        Get critical attack paths in the graph.

        Returns:
            List of critical paths
        """
        critical_paths = []

        # Find paths from vulnerable services to critical hosts
        vulnerable_services = [
            sid for sid, service in self.services.items() if service.vulnerabilities
        ]

        for service_id in vulnerable_services:
            service = self.services[service_id]
            host_id = service.host

            # Find paths from this service to other hosts
            for target_host in self.hosts:
                if target_host != host_id:
                    path = self.get_path_between_hosts(host_id, target_host)
                    if path and len(path) > 1:
                        critical_paths.append(path)

        return critical_paths

    def get_vulnerability_summary(self) -> Dict[str, Any]:
        """
        Get a summary of vulnerabilities in the graph.

        Returns:
            Vulnerability summary
        """
        summary = {
            "total_vulnerabilities": len(self.vulnerabilities),
            "by_severity": {},
            "by_type": {},
            "by_host": {},
            "critical_vulnerabilities": [],
        }

        for vuln in self.vulnerabilities.values():
            # Count by severity
            severity = vuln.severity.value
            summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1

            # Count by type
            vuln_type = vuln.vuln_type
            summary["by_type"][vuln_type] = summary["by_type"].get(vuln_type, 0) + 1

            # Count by host
            service = self.services.get(vuln.service_id)
            if service:
                host_id = service.host
                summary["by_host"][host_id] = summary["by_host"].get(host_id, 0) + 1

            # Track critical vulnerabilities
            if vuln.severity == VulnerabilityLevel.CRITICAL:
                summary["critical_vulnerabilities"].append(
                    {
                        "vuln_id": vuln.vuln_id,
                        "service_id": vuln.service_id,
                        "type": vuln.vuln_type,
                        "description": vuln.description,
                    }
                )

        return summary

    def get_network_topology(self) -> Dict[str, Any]:
        """
        Get the network topology summary.

        Returns:
            Network topology information
        """
        topology = {
            "total_hosts": len(self.hosts),
            "total_services": len(self.services),
            "total_connections": len(self.connections),
            "hosts_by_status": {},
            "services_by_type": {},
            "network_segments": [],
        }

        # Count hosts by status
        for host in self.hosts.values():
            status = host.status.value
            topology["hosts_by_status"][status] = topology["hosts_by_status"].get(status, 0) + 1

        # Count services by type
        for service in self.services.values():
            service_type = service.service_type.value
            topology["services_by_type"][service_type] = (
                topology["services_by_type"].get(service_type, 0) + 1
            )

        # Find network segments (connected components)
        host_nodes = [n for n, data in self.graph.nodes(data=True) if data.get("type") == "host"]
        host_subgraph = self.graph.subgraph(host_nodes)

        for component in nx.connected_components(host_subgraph.to_undirected()):
            topology["network_segments"].append(list(component))

        return topology

    def export_graph(self, filename: str) -> None:
        """
        Export the state graph to a JSON file.

        Args:
            filename: Output filename
        """

        def convert_enum(obj):
            """Convert Enum values to strings for JSON serialization."""
            if isinstance(obj, dict):
                return {k: convert_enum(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_enum(item) for item in obj]
            elif hasattr(obj, "value"):  # Enum objects
                return obj.value
            else:
                return obj

        data = {
            "exported_at": time.time(),
            "metadata": self.graph_metadata,
            "hosts": {hid: convert_enum(asdict(host)) for hid, host in self.hosts.items()},
            "services": {
                sid: convert_enum(asdict(service)) for sid, service in self.services.items()
            },
            "vulnerabilities": {
                vid: convert_enum(asdict(vuln)) for vid, vuln in self.vulnerabilities.items()
            },
            "connections": {
                cid: convert_enum(asdict(conn)) for cid, conn in self.connections.items()
            },
            "graph_edges": [
                {
                    "source": edge[0],
                    "target": edge[1],
                    "relationship": edge[2].get("relationship", "unknown"),
                    "data": convert_enum(asdict(edge[2].get("data")))
                    if edge[2].get("data")
                    else None,
                }
                for edge in self.graph.edges(data=True)
            ],
        }

        with open(filename, "w") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Exported state graph to {filename}")

    def import_graph(self, filename: str) -> bool:
        """
        Import a state graph from a JSON file.

        Args:
            filename: Input filename

        Returns:
            True if import successful, False otherwise
        """
        try:
            with open(filename, "r") as f:
                data = json.load(f)

            # Clear existing data
            self.hosts.clear()
            self.services.clear()
            self.vulnerabilities.clear()
            self.connections.clear()
            self.graph.clear()

            # Import hosts
            for hid, host_data in data.get("hosts", {}).items():
                host = HostInfo(**host_data)
                self.hosts[hid] = host
                self.graph.add_node(hid, type="host", data=host)

            # Import services
            for sid, service_data in data.get("services", {}).items():
                service = ServiceInfo(**service_data)
                self.services[sid] = service
                self.graph.add_node(sid, type="service", data=service)
                if service.host in self.hosts:
                    self.graph.add_edge(service.host, sid, relationship="hosts")

            # Import vulnerabilities
            for vid, vuln_data in data.get("vulnerabilities", {}).items():
                vuln = VulnerabilityInfo(**vuln_data)
                self.vulnerabilities[vid] = vuln
                self.graph.add_node(vid, type="vulnerability", data=vuln)
                if vuln.service_id in self.services:
                    self.graph.add_edge(vuln.service_id, vid, relationship="vulnerable_to")

            # Import connections
            for cid, conn_data in data.get("connections", {}).items():
                conn = ConnectionInfo(**conn_data)
                self.connections[cid] = conn
                self.graph.add_edge(
                    conn.source_host, conn.target_host, relationship="connects_to", data=conn
                )

            logger.info(f"Imported state graph from {filename}")
            return True

        except Exception as e:
            logger.error(f"Failed to import state graph from {filename}: {e}")
            return False

    def _update_metadata(self):
        """Update graph metadata."""
        self.graph_metadata.update(
            {
                "last_updated": time.time(),
                "total_hosts": len(self.hosts),
                "total_services": len(self.services),
                "total_vulnerabilities": len(self.vulnerabilities),
                "total_connections": len(self.connections),
            }
        )

    def clear(self):
        """Clear all data from the state graph."""
        self.hosts.clear()
        self.services.clear()
        self.vulnerabilities.clear()
        self.connections.clear()
        self.graph.clear()
        self._update_metadata()
        logger.info("State graph cleared")


if __name__ == "__main__":
    # Example usage
    import logging

    logging.basicConfig(level=logging.INFO)

    # Initialize state graph
    state_graph = StateGraph()

    # Add some hosts
    host1 = state_graph.add_host("web.example.com", "192.168.1.10")
    host2 = state_graph.add_host("db.example.com", "192.168.1.20")

    # Add services
    service1 = state_graph.add_service(host1, 80, ServiceType.HTTP)
    service2 = state_graph.add_service(host1, 443, ServiceType.HTTPS)
    service3 = state_graph.add_service(host2, 3306, ServiceType.DATABASE)

    # Add vulnerabilities
    vuln1 = state_graph.add_vulnerability(
        service1, "sql_injection", VulnerabilityLevel.HIGH, "SQL injection vulnerability found"
    )
    vuln2 = state_graph.add_vulnerability(
        service2, "xss", VulnerabilityLevel.MEDIUM, "Cross-site scripting vulnerability"
    )

    # Add connections
    state_graph.add_connection(host1, host2, "database_query", "tcp", 3306)

    # Get summaries
    vuln_summary = state_graph.get_vulnerability_summary()
    topology = state_graph.get_network_topology()

    print(f"Vulnerability summary: {vuln_summary}")
    print(f"Network topology: {topology}")

    # Export graph
    state_graph.export_graph("state_graph.json")
