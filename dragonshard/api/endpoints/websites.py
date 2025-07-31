#!/usr/bin/env python3
"""
DragonShard Website API Endpoints

API endpoints for managing website crawling, form enumeration, and endpoint discovery.
"""

import logging
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query

from dragonshard.api_inference.web_crawler import WebCrawlerManager
from dragonshard.data.database import DatabaseManager
from dragonshard.data.models import Website, WebsitePage, WebsitePageForm, WebsitePageEndpoint

logger = logging.getLogger(__name__)

router = APIRouter()

# Initialize database manager
db_manager = DatabaseManager()


@router.get("/")
async def get_websites(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
) -> Dict[str, Any]:
    """Get all websites with pagination."""
    try:
        with db_manager.get_session() as session:
            websites = session.query(Website).offset(skip).limit(limit).all()
            
            return {
                "websites": [website.to_dict() for website in websites],
                "total": session.query(Website).count(),
                "skip": skip,
                "limit": limit
            }
    except Exception as e:
        logger.error(f"Error getting websites: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/statistics")
async def get_website_statistics() -> Dict[str, Any]:
    """Get website crawling statistics."""
    try:
        with db_manager.get_session() as session:
            manager = WebCrawlerManager(session)
            stats = manager.get_website_statistics()
            
            return {
                "statistics": stats,
                "timestamp": time.time()
            }
    except Exception as e:
        logger.error(f"Error getting website statistics: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/forms/all")
async def get_all_forms(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
) -> Dict[str, Any]:
    """Get all forms across all websites (for fuzzing targets)."""
    try:
        with db_manager.get_session() as session:
            forms = session.query(WebsitePageForm).offset(skip).limit(limit).all()
            
            return {
                "forms": [form.to_dict() for form in forms],
                "total": session.query(WebsitePageForm).count(),
                "skip": skip,
                "limit": limit
            }
    except Exception as e:
        logger.error(f"Error getting all forms: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/endpoints/all")
async def get_all_endpoints(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
) -> Dict[str, Any]:
    """Get all endpoints across all websites (for fuzzing targets)."""
    try:
        with db_manager.get_session() as session:
            endpoints = session.query(WebsitePageEndpoint).offset(skip).limit(limit).all()
            
            return {
                "endpoints": [endpoint.to_dict() for endpoint in endpoints],
                "total": session.query(WebsitePageEndpoint).count(),
                "skip": skip,
                "limit": limit
            }
    except Exception as e:
        logger.error(f"Error getting all endpoints: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/crawl-all")
async def crawl_all_websites() -> Dict[str, Any]:
    """Crawl all HTTP/HTTPS services to discover websites."""
    try:
        with db_manager.get_session() as session:
            manager = WebCrawlerManager(session)
            websites = manager.crawl_all_http_services()
            
            return {
                "message": f"Successfully crawled {len(websites)} websites",
                "websites_crawled": len(websites),
                "website_ids": [website.website_id for website in websites]
            }
    except Exception as e:
        logger.error(f"Error crawling all websites: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/{website_id}")
async def get_website(
    website_id: str,
) -> Dict[str, Any]:
    """Get a specific website by ID."""
    try:
        with db_manager.get_session() as session:
            website = session.query(Website).filter(Website.website_id == website_id).first()
            if not website:
                raise HTTPException(status_code=404, detail="Website not found")
            
            return website.to_dict()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting website {website_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/{website_id}/pages")
async def get_website_pages(
    website_id: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
) -> Dict[str, Any]:
    """Get all pages for a specific website."""
    try:
        with db_manager.get_session() as session:
            website = session.query(Website).filter(Website.website_id == website_id).first()
            if not website:
                raise HTTPException(status_code=404, detail="Website not found")
            
            pages = session.query(WebsitePage).filter(
                WebsitePage.website_id == website_id
            ).offset(skip).limit(limit).all()
            
            return {
                "pages": [page.to_dict() for page in pages],
                "total": session.query(WebsitePage).filter(WebsitePage.website_id == website_id).count(),
                "skip": skip,
                "limit": limit
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting pages for website {website_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/{website_id}/forms")
async def get_website_forms(
    website_id: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
) -> Dict[str, Any]:
    """Get all forms for a specific website."""
    try:
        with db_manager.get_session() as session:
            website = session.query(Website).filter(Website.website_id == website_id).first()
            if not website:
                raise HTTPException(status_code=404, detail="Website not found")
            
            # Get forms through pages
            forms = session.query(WebsitePageForm).join(WebsitePage).filter(
                WebsitePage.website_id == website_id
            ).offset(skip).limit(limit).all()
            
            return {
                "forms": [form.to_dict() for form in forms],
                "total": session.query(WebsitePageForm).join(WebsitePage).filter(
                    WebsitePage.website_id == website_id
                ).count(),
                "skip": skip,
                "limit": limit
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting forms for website {website_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/{website_id}/endpoints")
async def get_website_endpoints(
    website_id: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
) -> Dict[str, Any]:
    """Get all endpoints for a specific website."""
    try:
        with db_manager.get_session() as session:
            website = session.query(Website).filter(Website.website_id == website_id).first()
            if not website:
                raise HTTPException(status_code=404, detail="Website not found")
            
            # Get endpoints through pages
            endpoints = session.query(WebsitePageEndpoint).join(WebsitePage).filter(
                WebsitePage.website_id == website_id
            ).offset(skip).limit(limit).all()
            
            return {
                "endpoints": [endpoint.to_dict() for endpoint in endpoints],
                "total": session.query(WebsitePageEndpoint).join(WebsitePage).filter(
                    WebsitePage.website_id == website_id
                ).count(),
                "skip": skip,
                "limit": limit
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting endpoints for website {website_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/crawl-service/{service_id}")
async def crawl_service(
    service_id: str,
) -> Dict[str, Any]:
    """Crawl a specific service to discover its website."""
    try:
        with db_manager.get_session() as session:
            manager = WebCrawlerManager(session)
            website = manager.crawl_specific_service(service_id)
            
            if not website:
                raise HTTPException(status_code=404, detail="Service not found or crawling failed")
            
            return {
                "message": f"Successfully crawled website {website.website_id}",
                "website": website.to_dict()
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error crawling service {service_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error") 