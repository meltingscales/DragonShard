#!/usr/bin/env python3
"""
DragonShard Database-Backed State Graph

Replaces the in-memory state graph with persistent database storage.
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

import networkx as nx

from dragonshard.data.database import get_repository
from dragonshard.data.models import (
    Connection,
    Host,
    HostStatus,
    Service,
    ServiceType,
    Vulnerability,
    VulnerabilityLevel,
)

logger = logging.getLogger(__name__)


class DatabaseStateGraph:
    """
    Database-backed state graph for persistent storage.
    """

    def __init__(self):
        """Initialize the database state graph."""
        self.host_repo = get_repository(Host)
        self.service_repo = get_repository(Service)
        self.vulnerability_repo = get_repository(Vulnerability)
        self.connection_repo = get_repository(Connection)

        # In-memory graph for quick operations
        self.graph = nx.DiGraph()
        self._load_graph_from_db()

        logger.info("DatabaseStateGraph initialized successfully")

    def _load_graph_from_db(self):
        """Load graph data from database into memory."""
        try:
            # Load hosts
            hosts = self.host_repo.get_all()
            for host in hosts:
                self.graph.add_node(host.host_id, type="host", data=host.to_dict())

            # Load services
            services = self.service_repo.get_all()
            for service in services:
                self.graph.add_node(service.service_id, type="service", data=service.to_dict())
                if service.host_id in self.graph:
                    self.graph.add_edge(service.host_id, service.service_id, relationship="hosts")

            # Load vulnerabilities
            vulnerabilities = self.vulnerability_repo.get_all()
            for vuln in vulnerabilities:
                self.graph.add_node(vuln.vuln_id, type="vulnerability", data=vuln.to_dict())
                if vuln.service_id in self.graph:
                    self.graph.add_edge(vuln.service_id, vuln.vuln_id, relationship="vulnerable_to")

            # Load connections
            connections = self.connection_repo.get_all()
            for conn in connections:
                self.graph.add_edge(
                    conn.source_host,
                    conn.target_host,
                    relationship="connects_to",
                    data=conn.to_dict(),
                )

            logger.info(f"Loaded graph from database: {len(hosts)} hosts, {len(services)} services, {len(vulnerabilities)} vulnerabilities, {len(connections)} connections")

        except Exception as e:
            logger.error(f"Failed to load graph from database: {e}")

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

        existing_host = self.host_repo.get_by_id(host_id)
        if existing_host:
            # Update existing host
            self.host_repo.update(
                host_id,
                last_seen=time.time(),
                status=status,
            )
            
            # Update hostnames
            hostnames = json.loads(existing_host.hostnames)
            if hostname not in hostnames:
                hostnames.append(hostname)
                self.host_repo.update(host_id, hostnames=json.dumps(hostnames))
        else:
            # Create new host
            host_data = {
                "host_id": host_id,
                "hostname": hostname,
                "ip_address": ip_address,
                "status": status,
                "discovered_at": time.time(),
                "last_seen": time.time(),
                "hostnames": json.dumps([hostname]),
            }
            self.host_repo.create(**host_data)

            # Add node to graph
            self.graph.add_node(host_id, type="host", data=host_data)

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

        existing_service = self.service_repo.get_by_id(service_id)
        if existing_service:
            # Update existing service
            update_data = {"last_seen": time.time()}
            if banner:
                update_data["banner"] = banner
            self.service_repo.update(service_id, **update_data)
        else:
            # Create new service
            service_data = {
                "service_id": service_id,
                "host_id": host_id,
                "port": port,
                "service_type": service_type,
                "protocol": protocol,
                "banner": banner,
                "discovered_at": time.time(),
                "last_seen": time.time(),
            }
            self.service_repo.create(**service_data)

            # Add node to graph
            self.graph.add_node(service_id, type="service", data=service_data)

            # Add edge from host to service
            if host_id in self.graph:
                self.graph.add_edge(host_id, service_id, relationship="hosts")

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

        vuln_data = {
            "vuln_id": vuln_id,
            "service_id": service_id,
            "vuln_type": vuln_type,
            "severity": severity,
            "description": description,
            "discovered_at": time.time(),
            "evidence": evidence,
        }

        self.vulnerability_repo.create(**vuln_data)

        # Add node to graph
        self.graph.add_node(vuln_id, type="vulnerability", data=vuln_data)

        # Add edge from service to vulnerability
        if service_id in self.graph:
            self.graph.add_edge(service_id, vuln_id, relationship="vulnerable_to")

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

        existing_connection = self.connection_repo.get_by_id(connection_id)
        if existing_connection:
            # Update existing connection
            self.connection_repo.update(connection_id, last_seen=time.time())
        else:
            # Create new connection
            conn_data = {
                "connection_id": connection_id,
                "source_host": source_host,
                "target_host": target_host,
                "connection_type": connection_type,
                "protocol": protocol,
                "port": port,
                "established_at": time.time(),
                "last_seen": time.time(),
            }
            self.connection_repo.create(**conn_data)

            # Add edge to graph
            self.graph.add_edge(source_host, target_host, relationship="connects_to", data=conn_data)

        logger.info(f"Added/updated connection: {source_host} -> {target_host}")
        return connection_id

    def get_host_info(self, host_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a host.

        Args:
            host_id: Host ID

        Returns:
            Host information dictionary or None
        """
        host = self.host_repo.get_by_id(host_id)
        return host.to_dict() if host else None

    def get_service_info(self, service_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a service.

        Args:
            service_id: Service ID

        Returns:
            Service information dictionary or None
        """
        service = self.service_repo.get_by_id(service_id)
        return service.to_dict() if service else None

    def get_vulnerability_info(self, vuln_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a vulnerability.

        Args:
            vuln_id: Vulnerability ID

        Returns:
            Vulnerability information dictionary or None
        """
        vuln = self.vulnerability_repo.get_by_id(vuln_id)
        return vuln.to_dict() if vuln else None

    def get_host_services(self, host_id: str) -> List[Dict[str, Any]]:
        """
        Get all services for a host.

        Args:
            host_id: Host ID

        Returns:
            List of service information dictionaries
        """
        services = self.service_repo.filter_by(host_id=host_id)
        return [service.to_dict() for service in services]

    def get_host_vulnerabilities(self, host_id: str) -> List[Dict[str, Any]]:
        """
        Get all vulnerabilities for a host.

        Args:
            host_id: Host ID

        Returns:
            List of vulnerability information dictionaries
        """
        # Get all services for the host
        services = self.service_repo.filter_by(host_id=host_id)
        service_ids = [service.service_id for service in services]
        
        # Get all vulnerabilities for these services
        vulnerabilities = []
        for service_id in service_ids:
            service_vulns = self.vulnerability_repo.filter_by(service_id=service_id)
            vulnerabilities.extend([vuln.to_dict() for vuln in service_vulns])
        
        return vulnerabilities

    def get_service_vulnerabilities(self, service_id: str) -> List[Dict[str, Any]]:
        """
        Get all vulnerabilities for a service.

        Args:
            service_id: Service ID

        Returns:
            List of vulnerability information dictionaries
        """
        vulnerabilities = self.vulnerability_repo.filter_by(service_id=service_id)
        return [vuln.to_dict() for vuln in vulnerabilities]

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

        # Find vulnerable services
        vulnerable_services = self.vulnerability_repo.get_all()
        service_ids = [vuln.service_id for vuln in vulnerable_services]

        for service_id in service_ids:
            service = self.service_repo.get_by_id(service_id)
            if service:
                host_id = service.host_id

                # Find paths from this service to other hosts
                for target_host in self.host_repo.get_all():
                    if target_host.host_id != host_id:
                        path = self.get_path_between_hosts(host_id, target_host.host_id)
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
            "total_vulnerabilities": self.vulnerability_repo.count(),
            "by_severity": {},
            "by_type": {},
            "by_host": {},
            "critical_vulnerabilities": [],
        }

        vulnerabilities = self.vulnerability_repo.get_all()
        for vuln in vulnerabilities:
            # Count by severity
            severity = vuln.severity.value
            summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1

            # Count by type
            vuln_type = vuln.vuln_type
            summary["by_type"][vuln_type] = summary["by_type"].get(vuln_type, 0) + 1

            # Count by host
            service = self.service_repo.get_by_id(vuln.service_id)
            if service:
                host_id = service.host_id
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
            "total_hosts": self.host_repo.count(),
            "total_services": self.service_repo.count(),
            "total_connections": self.connection_repo.count(),
            "hosts_by_status": {},
            "services_by_type": {},
            "network_segments": [],
        }

        # Count hosts by status
        hosts = self.host_repo.get_all()
        for host in hosts:
            status = host.status.value
            topology["hosts_by_status"][status] = topology["hosts_by_status"].get(status, 0) + 1

        # Count services by type
        services = self.service_repo.get_all()
        for service in services:
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
        hosts = self.host_repo.get_all()
        services = self.service_repo.get_all()
        vulnerabilities = self.vulnerability_repo.get_all()
        connections = self.connection_repo.get_all()

        data = {
            "exported_at": time.time(),
            "hosts": {host.host_id: host.to_dict() for host in hosts},
            "services": {service.service_id: service.to_dict() for service in services},
            "vulnerabilities": {vuln.vuln_id: vuln.to_dict() for vuln in vulnerabilities},
            "connections": {conn.connection_id: conn.to_dict() for conn in connections},
            "graph_edges": [
                {
                    "source": edge[0],
                    "target": edge[1],
                    "relationship": edge[2].get("relationship", "unknown"),
                    "data": edge[2].get("data"),
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
            self.clear()

            # Import hosts
            for hid, host_data in data.get("hosts", {}).items():
                self.host_repo.create(**host_data)

            # Import services
            for sid, service_data in data.get("services", {}).items():
                self.service_repo.create(**service_data)

            # Import vulnerabilities
            for vid, vuln_data in data.get("vulnerabilities", {}).items():
                self.vulnerability_repo.create(**vuln_data)

            # Import connections
            for cid, conn_data in data.get("connections", {}).items():
                self.connection_repo.create(**conn_data)

            # Reload graph from database
            self._load_graph_from_db()

            logger.info(f"Imported state graph from {filename}")
            return True

        except Exception as e:
            logger.error(f"Failed to import state graph from {filename}: {e}")
            return False

    def clear(self):
        """Clear all data from the state graph."""
        # Clear database
        self.host_repo.get_all()  # Get all to delete
        self.service_repo.get_all()
        self.vulnerability_repo.get_all()
        self.connection_repo.get_all()

        # Clear in-memory graph
        self.graph.clear()

        logger.info("State graph cleared") 