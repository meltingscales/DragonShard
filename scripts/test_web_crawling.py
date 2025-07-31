#!/usr/bin/env python3
"""
Test script for DragonShard Web Crawling functionality

This script demonstrates the web crawling feature by:
1. Adding sample HTTP services to the database
2. Running web crawling on those services
3. Displaying the results
"""

import logging
import sys
import time
import uuid

# Add the project root to the path
sys.path.insert(0, '.')

from dragonshard.data.database import DatabaseManager
from dragonshard.data.models import Host, Service, ServiceType
from dragonshard.api_inference.web_crawler import WebCrawlerManager

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def create_sample_data():
    """Create sample hosts and services for testing."""
    logger.info("Creating sample data for web crawling test...")
    
    db_manager = DatabaseManager()
    with db_manager.get_session() as session:
        # Create a sample host
        host = Host(
            host_id=f"host_{uuid.uuid4().hex[:8]}",
            hostname="test.example.com",
            ip_address="192.168.1.100",
            status="discovered",
            discovered_at=time.time(),
            last_seen=time.time()
        )
        session.add(host)
        session.commit()
        
        # Create HTTP service
        http_service = Service(
            service_id=f"service_{uuid.uuid4().hex[:8]}",
            host_id=host.host_id,
            port=80,
            service_type=ServiceType.HTTP,
            protocol="tcp",
            status="open",
            discovered_at=time.time(),
            last_seen=time.time()
        )
        session.add(http_service)
        
        # Create HTTPS service
        https_service = Service(
            service_id=f"service_{uuid.uuid4().hex[:8]}",
            host_id=host.host_id,
            port=443,
            service_type=ServiceType.HTTPS,
            protocol="tcp",
            status="open",
            discovered_at=time.time(),
            last_seen=time.time()
        )
        session.add(https_service)
        
        session.commit()
        
        logger.info(f"Created host: {host.host_id}")
        logger.info(f"Created HTTP service: {http_service.service_id}")
        logger.info(f"Created HTTPS service: {https_service.service_id}")
        
        return host.host_id, http_service.service_id, https_service.service_id


def test_web_crawling():
    """Test the web crawling functionality."""
    logger.info("Starting web crawling test...")
    
    # Create sample data
    host_id, http_service_id, https_service_id = create_sample_data()
    
    # Test listing services
    logger.info("\n=== Listing HTTP/HTTPS Services ===")
    db_manager = DatabaseManager()
    with db_manager.get_session() as session:
        services = session.query(Service).filter(
            Service.service_type.in_([ServiceType.HTTP, ServiceType.HTTPS])
        ).all()
        
        logger.info(f"Found {len(services)} HTTP/HTTPS services:")
        for service in services:
            logger.info(f"  - {service.service_id}: {service.host.hostname}:{service.port} ({service.service_type.value})")
    
    # Test crawling a specific service (this will fail since the service doesn't actually exist)
    logger.info("\n=== Testing Web Crawling ===")
    with db_manager.get_session() as session:
        manager = WebCrawlerManager(session)
        
        # Get statistics before crawling
        stats_before = manager.get_website_statistics()
        logger.info(f"Statistics before crawling: {stats_before}")
        
        # Try to crawl the HTTP service (this will fail gracefully since it's not a real service)
        logger.info(f"Attempting to crawl service {http_service_id}...")
        website = manager.crawl_specific_service(http_service_id)
        
        if website:
            logger.info(f"Successfully crawled website {website.website_id}")
            logger.info(f"  - Pages: {website.total_pages}")
            logger.info(f"  - Forms: {website.total_forms}")
            logger.info(f"  - Endpoints: {website.total_endpoints}")
        else:
            logger.info("Crawling failed (expected for non-existent service)")
        
        # Get statistics after crawling
        stats_after = manager.get_website_statistics()
        logger.info(f"Statistics after crawling: {stats_after}")


def main():
    """Main function."""
    try:
        test_web_crawling()
        logger.info("Web crawling test completed successfully!")
        
    except Exception as e:
        logger.error(f"Error during web crawling test: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 