#!/usr/bin/env python3
"""
DragonShard Web Crawl Discovery Script

This script integrates with the existing scanner to automatically discover
and crawl websites from HTTP/HTTPS services found during network scanning.
"""

import argparse
import logging
import sys
from typing import List, Optional

# Add the project root to the path
sys.path.insert(0, '.')

from dragonshard.api_inference.web_crawler import WebCrawlerManager
from dragonshard.data.database import DatabaseManager
from dragonshard.data.models import Service, ServiceType

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def crawl_all_services() -> None:
    """Crawl all HTTP/HTTPS services in the database."""
    logger.info("Starting web crawl discovery for all HTTP/HTTPS services...")
    
    db_manager = DatabaseManager()
    with db_manager.get_session() as session:
        manager = WebCrawlerManager(session)
        
        # Get statistics before crawling
        stats_before = manager.get_website_statistics()
        logger.info(f"Current statistics: {stats_before}")
        
        # Crawl all services
        websites = manager.crawl_all_http_services()
        
        # Get statistics after crawling
        stats_after = manager.get_website_statistics()
        logger.info(f"Final statistics: {stats_after}")
        
        logger.info(f"Completed crawling {len(websites)} websites")


def crawl_specific_service(service_id: str) -> None:
    """Crawl a specific service by ID."""
    logger.info(f"Starting web crawl discovery for service {service_id}...")
    
    db_manager = DatabaseManager()
    with db_manager.get_session() as session:
        manager = WebCrawlerManager(session)
        website = manager.crawl_specific_service(service_id)
        
        if website:
            logger.info(f"Successfully crawled website {website.website_id}")
            logger.info(f"  - Pages: {website.total_pages}")
            logger.info(f"  - Forms: {website.total_forms}")
            logger.info(f"  - Endpoints: {website.total_endpoints}")
        else:
            logger.error(f"Failed to crawl service {service_id}")


def list_http_services() -> None:
    """List all HTTP/HTTPS services in the database."""
    logger.info("Listing all HTTP/HTTPS services...")
    
    db_manager = DatabaseManager()
    with db_manager.get_session() as session:
        services = session.query(Service).filter(
            Service.service_type.in_([ServiceType.HTTP, ServiceType.HTTPS])
        ).all()
        
        if not services:
            logger.info("No HTTP/HTTPS services found")
            return
        
        logger.info(f"Found {len(services)} HTTP/HTTPS services:")
        for service in services:
            logger.info(f"  - {service.service_id}: {service.host.hostname}:{service.port} ({service.service_type.value})")


def show_statistics() -> None:
    """Show web crawling statistics."""
    logger.info("Web crawling statistics:")
    
    db_manager = DatabaseManager()
    with db_manager.get_session() as session:
        manager = WebCrawlerManager(session)
        stats = manager.get_website_statistics()
        
        logger.info(f"  - Total websites: {stats['total_websites']}")
        logger.info(f"  - Total pages: {stats['total_pages']}")
        logger.info(f"  - Total forms: {stats['total_forms']}")
        logger.info(f"  - Total endpoints: {stats['total_endpoints']}")
        logger.info("  - Websites by status:")
        for status, count in stats['websites_by_status'].items():
            logger.info(f"    - {status}: {count}")


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="DragonShard Web Crawl Discovery")
    parser.add_argument("--action", choices=["crawl-all", "crawl-service", "list-services", "stats"], 
                       default="crawl-all", help="Action to perform")
    parser.add_argument("--service-id", help="Service ID to crawl (for crawl-service action)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        if args.action == "crawl-all":
            crawl_all_services()
        elif args.action == "crawl-service":
            if not args.service_id:
                logger.error("--service-id is required for crawl-service action")
                sys.exit(1)
            crawl_specific_service(args.service_id)
        elif args.action == "list-services":
            list_http_services()
        elif args.action == "stats":
            show_statistics()
        
        logger.info("Web crawl discovery completed successfully")
        
    except Exception as e:
        logger.error(f"Error during web crawl discovery: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 