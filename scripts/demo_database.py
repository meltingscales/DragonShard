#!/usr/bin/env python3
"""
DragonShard Database Demo

Demonstrates the database-backed session manager and state graph functionality.
"""

import logging
import sys
import time
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from dragonshard.data.session_manager_db import DatabaseSessionManager
from dragonshard.data.state_graph_db import DatabaseStateGraph
from dragonshard.data.models import (
    AuthMethod, HostStatus, ServiceType, VulnerabilityLevel
)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def demo_session_manager():
    """Demonstrate session manager functionality."""
    logger.info("🔐 Session Manager Demo")
    logger.info("=" * 50)
    
    session_manager = DatabaseSessionManager()
    
    # Create multiple sessions
    session1 = session_manager.create_session("http://web.example.com", AuthMethod.FORM)
    session2 = session_manager.create_session("http://api.example.com", AuthMethod.TOKEN)
    session3 = session_manager.create_session("http://admin.example.com", AuthMethod.BASIC)
    
    logger.info(f"Created sessions: {session1}, {session2}, {session3}")
    
    # Get session info
    for session_id in [session1, session2, session3]:
        info = session_manager.get_session_info(session_id)
        logger.info(f"Session {session_id}: {info['target_host']} ({info['state']})")
    
    # Test authentication (will fail in demo, but shows the flow)
    credentials = {"username": "admin", "password": "password123"}
    result = session_manager.authenticate_session(session1, credentials)
    logger.info(f"Authentication result: {result}")
    
    # Get session headers
    headers = session_manager.get_session_headers(session1)
    logger.info(f"Session headers: {len(headers)} headers")
    
    # Clean up
    for session_id in [session1, session2, session3]:
        session_manager.destroy_session(session_id)
    
    logger.info("Session manager demo completed\n")


def demo_state_graph():
    """Demonstrate state graph functionality."""
    logger.info("🌐 State Graph Demo")
    logger.info("=" * 50)
    
    state_graph = DatabaseStateGraph()
    
    # Add hosts
    web_host = state_graph.add_host("web.example.com", "192.168.1.10", HostStatus.DISCOVERED)
    db_host = state_graph.add_host("db.example.com", "192.168.1.20", HostStatus.DISCOVERED)
    api_host = state_graph.add_host("api.example.com", "192.168.1.30", HostStatus.DISCOVERED)
    
    logger.info(f"Added hosts: {web_host}, {db_host}, {api_host}")
    
    # Add services
    web_http = state_graph.add_service(web_host, 80, ServiceType.HTTP)
    web_https = state_graph.add_service(web_host, 443, ServiceType.HTTPS)
    db_mysql = state_graph.add_service(db_host, 3306, ServiceType.DATABASE)
    api_rest = state_graph.add_service(api_host, 8080, ServiceType.API)
    
    logger.info(f"Added services: {web_http}, {web_https}, {db_mysql}, {api_rest}")
    
    # Add vulnerabilities
    vuln1 = state_graph.add_vulnerability(
        web_http, "sql_injection", VulnerabilityLevel.HIGH, 
        "SQL injection vulnerability in login form"
    )
    vuln2 = state_graph.add_vulnerability(
        web_https, "xss", VulnerabilityLevel.MEDIUM, 
        "Cross-site scripting in search functionality"
    )
    vuln3 = state_graph.add_vulnerability(
        db_mysql, "weak_password", VulnerabilityLevel.CRITICAL, 
        "Default MySQL password still in use"
    )
    
    logger.info(f"Added vulnerabilities: {vuln1}, {vuln2}, {vuln3}")
    
    # Add connections
    conn1 = state_graph.add_connection(web_host, db_host, "database_query", "tcp", 3306)
    conn2 = state_graph.add_connection(web_host, api_host, "api_request", "tcp", 8080)
    
    logger.info(f"Added connections: {conn1}, {conn2}")
    
    # Query data
    web_info = state_graph.get_host_info(web_host)
    logger.info(f"Web host info: {web_info['hostname']} ({web_info['ip_address']})")
    
    web_services = state_graph.get_host_services(web_host)
    logger.info(f"Web host services: {len(web_services)} services")
    
    web_vulns = state_graph.get_host_vulnerabilities(web_host)
    logger.info(f"Web host vulnerabilities: {len(web_vulns)} vulnerabilities")
    
    # Get summaries
    vuln_summary = state_graph.get_vulnerability_summary()
    logger.info(f"Vulnerability summary: {vuln_summary['total_vulnerabilities']} total")
    logger.info(f"By severity: {vuln_summary['by_severity']}")
    
    topology = state_graph.get_network_topology()
    logger.info(f"Network topology: {topology['total_hosts']} hosts, {topology['total_services']} services")
    logger.info(f"Services by type: {topology['services_by_type']}")
    
    logger.info("State graph demo completed\n")


def demo_persistence():
    """Demonstrate data persistence across sessions."""
    logger.info("💾 Data Persistence Demo")
    logger.info("=" * 50)
    
    # Create first instance and add data
    state_graph1 = DatabaseStateGraph()
    host_id = state_graph1.add_host("persistent.example.com", "192.168.1.100", HostStatus.DISCOVERED)
    service_id = state_graph1.add_service(host_id, 80, ServiceType.HTTP)
    vuln_id = state_graph1.add_vulnerability(
        service_id, "demo_vuln", VulnerabilityLevel.LOW, "Demo vulnerability"
    )
    
    logger.info(f"Added data in first instance: {host_id}, {service_id}, {vuln_id}")
    
    # Create second instance and verify data persists
    state_graph2 = DatabaseStateGraph()
    host_info = state_graph2.get_host_info(host_id)
    service_info = state_graph2.get_service_info(service_id)
    vuln_info = state_graph2.get_vulnerability_info(vuln_id)
    
    if host_info:
        logger.info(f"✓ Host data persisted: {host_info['hostname']}")
    if service_info:
        logger.info(f"✓ Service data persisted: {service_info['service_type']}")
    if vuln_info:
        logger.info(f"✓ Vulnerability data persisted: {vuln_info['vuln_type']}")
    
    # Check totals
    topology = state_graph2.get_network_topology()
    logger.info(f"✓ Total hosts: {topology['total_hosts']}")
    logger.info(f"✓ Total services: {topology['total_services']}")
    
    vuln_summary = state_graph2.get_vulnerability_summary()
    logger.info(f"✓ Total vulnerabilities: {vuln_summary['total_vulnerabilities']}")
    
    logger.info("Data persistence demo completed\n")


def main():
    """Run all demos."""
    logger.info("🐉 DragonShard Database Demo")
    logger.info("=" * 60)
    
    try:
        demo_session_manager()
        demo_state_graph()
        demo_persistence()
        
        logger.info("🎉 All demos completed successfully!")
        logger.info("The database backend is working correctly.")
        
    except Exception as e:
        logger.error(f"Demo failed: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main()) 