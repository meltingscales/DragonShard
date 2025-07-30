#!/usr/bin/env python3
"""
Test script for DragonShard database implementation.
"""

import logging
import sys
import time
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from dragonshard.data.database import initialize_database, get_database_manager
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


def test_database_connection():
    """Test database connection."""
    logger.info("Testing database connection...")
    
    try:
        # Initialize database
        db_manager = initialize_database()
        
        # Check connection
        if db_manager.check_connection():
            logger.info("✓ Database connection successful")
            return True
        else:
            logger.error("✗ Database connection failed")
            return False
            
    except Exception as e:
        logger.error(f"✗ Database connection test failed: {e}")
        return False


def test_session_manager():
    """Test session manager functionality."""
    logger.info("Testing session manager...")
    
    try:
        session_manager = DatabaseSessionManager()
        
        # Create a session
        session_id = session_manager.create_session("http://example.com", AuthMethod.FORM)
        logger.info(f"✓ Created session: {session_id}")
        
        # Get session info
        session_info = session_manager.get_session_info(session_id)
        if session_info:
            logger.info(f"✓ Session info retrieved: {session_info['target_host']}")
        else:
            logger.error("✗ Failed to get session info")
            return False
        
        # Test authentication
        credentials = {
            "username": "testuser",
            "password": "testpass"
        }
        
        # Note: This will fail in test environment, but that's expected
        auth_result = session_manager.authenticate_session(session_id, credentials)
        logger.info(f"✓ Authentication test completed (result: {auth_result})")
        
        # Clean up
        session_manager.destroy_session(session_id)
        logger.info("✓ Session destroyed")
        
        return True
        
    except Exception as e:
        logger.error(f"✗ Session manager test failed: {e}")
        return False


def test_state_graph():
    """Test state graph functionality."""
    logger.info("Testing state graph...")
    
    try:
        state_graph = DatabaseStateGraph()
        
        # Add hosts
        host1_id = state_graph.add_host("web.example.com", "192.168.1.10", HostStatus.DISCOVERED)
        host2_id = state_graph.add_host("db.example.com", "192.168.1.20", HostStatus.DISCOVERED)
        logger.info(f"✓ Added hosts: {host1_id}, {host2_id}")
        
        # Add services
        service1_id = state_graph.add_service(host1_id, 80, ServiceType.HTTP)
        service2_id = state_graph.add_service(host1_id, 443, ServiceType.HTTPS)
        service3_id = state_graph.add_service(host2_id, 3306, ServiceType.DATABASE)
        logger.info(f"✓ Added services: {service1_id}, {service2_id}, {service3_id}")
        
        # Add vulnerabilities
        vuln1_id = state_graph.add_vulnerability(
            service1_id, "sql_injection", VulnerabilityLevel.HIGH, "SQL injection vulnerability found"
        )
        vuln2_id = state_graph.add_vulnerability(
            service2_id, "xss", VulnerabilityLevel.MEDIUM, "Cross-site scripting vulnerability"
        )
        logger.info(f"✓ Added vulnerabilities: {vuln1_id}, {vuln2_id}")
        
        # Add connections
        conn_id = state_graph.add_connection(host1_id, host2_id, "database_query", "tcp", 3306)
        logger.info(f"✓ Added connection: {conn_id}")
        
        # Test queries
        host_info = state_graph.get_host_info(host1_id)
        if host_info:
            logger.info(f"✓ Retrieved host info: {host_info['hostname']}")
        
        services = state_graph.get_host_services(host1_id)
        logger.info(f"✓ Retrieved {len(services)} services for host")
        
        vulnerabilities = state_graph.get_service_vulnerabilities(service1_id)
        logger.info(f"✓ Retrieved {len(vulnerabilities)} vulnerabilities for service")
        
        # Test summaries
        vuln_summary = state_graph.get_vulnerability_summary()
        logger.info(f"✓ Vulnerability summary: {vuln_summary['total_vulnerabilities']} total")
        
        topology = state_graph.get_network_topology()
        logger.info(f"✓ Network topology: {topology['total_hosts']} hosts, {topology['total_services']} services")
        
        return True
        
    except Exception as e:
        logger.error(f"✗ State graph test failed: {e}")
        return False


def test_repository_operations():
    """Test repository operations."""
    logger.info("Testing repository operations...")
    
    try:
        db_manager = get_database_manager()
        
        # Test host repository
        from dragonshard.data.models import Host, HostStatus
        host_repo = db_manager.get_repository(Host)
        
        # Create a test host
        host_data = {
            "host_id": "test_host_123",
            "hostname": "test.example.com",
            "ip_address": "192.168.1.100",
            "status": HostStatus.DISCOVERED,
            "discovered_at": time.time(),
            "last_seen": time.time(),
            "hostnames": "[]",
        }
        
        host = host_repo.create(**host_data)
        logger.info(f"✓ Created host: {host.host_id}")
        
        # Retrieve host
        retrieved_host = host_repo.get_by_id("test_host_123")
        if retrieved_host:
            logger.info(f"✓ Retrieved host: {retrieved_host.hostname}")
        else:
            logger.error("✗ Failed to retrieve host")
            return False
        
        # Update host
        updated_host = host_repo.update("test_host_123", status=HostStatus.SCANNED)
        if updated_host:
            logger.info(f"✓ Updated host status: {updated_host.status}")
        else:
            logger.error("✗ Failed to update host")
            return False
        
        # Count hosts
        count = host_repo.count()
        logger.info(f"✓ Host count: {count}")
        
        # Delete host
        deleted = host_repo.delete("test_host_123")
        if deleted:
            logger.info("✓ Deleted test host")
        else:
            logger.error("✗ Failed to delete host")
            return False
        
        return True
        
    except Exception as e:
        logger.error(f"✗ Repository operations test failed: {e}")
        return False


def main():
    """Run all database tests."""
    logger.info("🧪 Running DragonShard database tests...")
    
    tests = [
        ("Database Connection", test_database_connection),
        ("Session Manager", test_session_manager),
        ("State Graph", test_state_graph),
        ("Repository Operations", test_repository_operations),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        logger.info(f"\n{'='*50}")
        logger.info(f"Running test: {test_name}")
        logger.info(f"{'='*50}")
        
        try:
            if test_func():
                logger.info(f"✓ {test_name}: PASSED")
                passed += 1
            else:
                logger.error(f"✗ {test_name}: FAILED")
        except Exception as e:
            logger.error(f"✗ {test_name}: ERROR - {e}")
    
    logger.info(f"\n{'='*50}")
    logger.info(f"Test Results: {passed}/{total} tests passed")
    logger.info(f"{'='*50}")
    
    if passed == total:
        logger.info("🎉 All tests passed!")
        return 0
    else:
        logger.error("❌ Some tests failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main()) 