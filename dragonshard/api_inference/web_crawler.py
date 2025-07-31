#!/usr/bin/env python3
"""
DragonShard Web Crawler

Enhanced web crawler that integrates with the database schema to discover
websites, pages, forms, and API endpoints. Designed to work with the
existing crawler infrastructure and database models.
"""

import json
import logging
import re
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup
from sqlalchemy.orm import Session

from dragonshard.data.models import (
    Service,
    ServiceType,
    Website,
    WebsitePage,
    WebsitePageForm,
    WebsitePageEndpoint,
)

logger = logging.getLogger(__name__)


class WebCrawler:
    """Enhanced web crawler for discovering websites, pages, forms, and endpoints."""

    def __init__(self, db_session: Session, max_depth: int = 3, max_pages: int = 100):
        self.db_session = db_session
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited_urls: Set[str] = set()
        self.client = httpx.Client(
            timeout=30.0,
            follow_redirects=True,
            headers={
                "User-Agent": "DragonShard/1.0 Web Crawler",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            }
        )

    def crawl_service(self, service: Service) -> Optional[Website]:
        """Crawl a service to discover websites and their content."""
        if service.service_type not in [ServiceType.HTTP, ServiceType.HTTPS]:
            logger.info(f"Service {service.service_id} is not HTTP/HTTPS, skipping")
            return None

        # Determine base URL
        protocol = "https" if service.service_type == ServiceType.HTTPS else "http"
        base_url = f"{protocol}://{service.host.hostname}:{service.port}"
        
        # Check if website already exists
        existing_website = self.db_session.query(Website).filter(
            Website.service_id == service.service_id
        ).first()
        
        if existing_website:
            logger.info(f"Website already exists for service {service.service_id}, updating")
            website = existing_website
            website.last_crawled_at = time.time()
            website.crawl_status = "crawling"
        else:
            # Create new website
            website = Website(
                website_id=f"website_{uuid.uuid4().hex[:8]}",
                service_id=service.service_id,
                base_url=base_url,
                crawl_depth=self.max_depth,
                max_pages=self.max_pages,
                crawl_status="crawling"
            )
            self.db_session.add(website)
            self.db_session.commit()

        try:
            # Start crawling from the base URL
            self._crawl_website(website, base_url, depth=0)
            
            # Update website statistics
            website.crawl_status = "completed"
            website.total_pages = len(website.pages)
            website.total_forms = sum(len(page.forms) for page in website.pages)
            website.total_endpoints = sum(len(page.endpoints) for page in website.pages)
            website.last_crawled_at = time.time()
            
            self.db_session.commit()
            logger.info(f"Completed crawling website {website.website_id}: {website.total_pages} pages, {website.total_forms} forms, {website.total_endpoints} endpoints")
            
            return website
            
        except Exception as e:
            logger.error(f"Error crawling website {website.website_id}: {e}")
            website.crawl_status = "failed"
            self.db_session.commit()
            return None

    def _crawl_website(self, website: Website, url: str, depth: int, parent_page: Optional[WebsitePage] = None) -> None:
        """Recursively crawl a website starting from a URL."""
        if depth > self.max_depth or len(self.visited_urls) >= self.max_pages:
            return

        if url in self.visited_urls:
            return

        self.visited_urls.add(url)
        
        try:
            # Fetch the page
            start_time = time.time()
            response = self.client.get(url)
            response_time = time.time() - start_time
            
            # Create page record
            page = WebsitePage(
                page_id=f"page_{uuid.uuid4().hex[:8]}",
                website_id=website.website_id,
                url=url,
                status_code=response.status_code,
                content_type=response.headers.get("content-type", ""),
                response_size=len(response.content),
                response_time=response_time,
                depth=depth,
                parent_page_id=parent_page.page_id if parent_page else None,
                is_accessible=response.status_code < 400
            )
            
            self.db_session.add(page)
            self.db_session.commit()

            if response.status_code >= 400:
                logger.warning(f"Page {url} returned status {response.status_code}")
                return

            # Parse HTML content
            if "text/html" in response.headers.get("content-type", ""):
                soup = BeautifulSoup(response.content, "html.parser")
                
                # Extract page title
                title_tag = soup.find("title")
                if title_tag:
                    page.title = title_tag.get_text().strip()
                
                # Extract forms
                forms = soup.find_all("form")
                for form in forms:
                    self._extract_form(page, form)
                
                # Extract potential API endpoints from links and scripts
                self._extract_endpoints(page, soup)
                
                # Find links for further crawling
                if depth < self.max_depth:
                    links = soup.find_all("a", href=True)
                    for link in links[:10]:  # Limit links per page
                        href = link["href"]
                        absolute_url = urljoin(url, href)
                        
                        # Only crawl same-domain URLs
                        if self._is_same_domain(url, absolute_url):
                            self._crawl_website(website, absolute_url, depth + 1, page)

        except Exception as e:
            logger.error(f"Error crawling {url}: {e}")

    def _extract_form(self, page: WebsitePage, form_element) -> None:
        """Extract form information from a BeautifulSoup form element."""
        try:
            form_action = form_element.get("action", "")
            form_method = form_element.get("method", "GET").upper()
            form_name = form_element.get("name", "")
            form_id = form_element.get("id", "")
            form_class = form_element.get("class", "")
            
            # Determine form type
            is_login_form = self._is_login_form(form_element)
            is_search_form = self._is_search_form(form_element)
            
            # Extract form fields
            form_fields = []
            for input_element in form_element.find_all(["input", "textarea", "select"]):
                field = {
                    "name": input_element.get("name", ""),
                    "type": input_element.get("type", "text"),
                    "id": input_element.get("id", ""),
                    "required": input_element.get("required") is not None,
                    "placeholder": input_element.get("placeholder", ""),
                }
                form_fields.append(field)
            
            # Create form record
            form = WebsitePageForm(
                form_id=f"form_{uuid.uuid4().hex[:8]}",
                page_id=page.page_id,
                form_action=form_action,
                form_method=form_method,
                form_name=form_name,
                form_id_attribute=form_id,
                form_class=" ".join(form_class) if isinstance(form_class, list) else form_class,
                is_login_form=is_login_form,
                is_search_form=is_search_form,
                form_fields=json.dumps(form_fields)
            )
            
            self.db_session.add(form)
            
        except Exception as e:
            logger.error(f"Error extracting form from {page.url}: {e}")

    def _extract_endpoints(self, page: WebsitePage, soup: BeautifulSoup) -> None:
        """Extract potential API endpoints from page content."""
        try:
            # Look for common API endpoint patterns in links
            api_patterns = [
                r"/api/",
                r"/rest/",
                r"/v\d+/",
                r"/json/",
                r"/xml/",
                r"/graphql",
                r"/swagger",
                r"/openapi"
            ]
            
            links = soup.find_all("a", href=True)
            for link in links:
                href = link["href"]
                for pattern in api_patterns:
                    if re.search(pattern, href, re.IGNORECASE):
                        self._create_endpoint(page, href, "GET")
                        break
            
            # Look for AJAX calls in scripts
            scripts = soup.find_all("script")
            for script in scripts:
                if script.string:
                    # Look for fetch, XMLHttpRequest, or $.ajax calls
                    ajax_patterns = [
                        r'fetch\(["\']([^"\']+)["\']',
                        r'XMLHttpRequest\(["\']([^"\']+)["\']',
                        r'\$\.ajax\([^)]*url:\s*["\']([^"\']+)["\']',
                    ]
                    
                    for pattern in ajax_patterns:
                        matches = re.findall(pattern, script.string)
                        for match in matches:
                            self._create_endpoint(page, match, "GET")
                            
        except Exception as e:
            logger.error(f"Error extracting endpoints from {page.url}: {e}")

    def _create_endpoint(self, page: WebsitePage, path: str, method: str) -> None:
        """Create an endpoint record."""
        try:
            endpoint = WebsitePageEndpoint(
                endpoint_id=f"endpoint_{uuid.uuid4().hex[:8]}",
                page_id=page.page_id,
                endpoint_path=path,
                method=method,
                is_api_endpoint=True,
                parameters=json.dumps([])  # TODO: Extract parameters from path
            )
            
            self.db_session.add(endpoint)
            
        except Exception as e:
            logger.error(f"Error creating endpoint record: {e}")

    def _is_login_form(self, form_element) -> bool:
        """Determine if a form is a login form."""
        form_text = form_element.get_text().lower()
        login_indicators = ["login", "signin", "username", "password", "email"]
        return any(indicator in form_text for indicator in login_indicators)

    def _is_search_form(self, form_element) -> bool:
        """Determine if a form is a search form."""
        form_text = form_element.get_text().lower()
        search_indicators = ["search", "find", "query", "q="]
        return any(indicator in form_text for indicator in search_indicators)

    def _is_same_domain(self, url1: str, url2: str) -> bool:
        """Check if two URLs are from the same domain."""
        try:
            domain1 = urlparse(url1).netloc
            domain2 = urlparse(url2).netloc
            return domain1 == domain2
        except Exception:
            return False

    def close(self):
        """Close the HTTP client."""
        self.client.close()


class WebCrawlerManager:
    """Manager for coordinating web crawling operations."""

    def __init__(self, db_session: Session):
        self.db_session = db_session

    def crawl_all_http_services(self) -> List[Website]:
        """Crawl all HTTP/HTTPS services in the database."""
        services = self.db_session.query(Service).filter(
            Service.service_type.in_([ServiceType.HTTP, ServiceType.HTTPS])
        ).all()
        
        websites = []
        for service in services:
            logger.info(f"Crawling service {service.service_id} ({service.host.hostname}:{service.port})")
            crawler = WebCrawler(self.db_session)
            try:
                website = crawler.crawl_service(service)
                if website:
                    websites.append(website)
            finally:
                crawler.close()
        
        return websites

    def crawl_specific_service(self, service_id: str) -> Optional[Website]:
        """Crawl a specific service by ID."""
        service = self.db_session.query(Service).filter(Service.service_id == service_id).first()
        if not service:
            logger.error(f"Service {service_id} not found")
            return None
        
        crawler = WebCrawler(self.db_session)
        try:
            return crawler.crawl_service(service)
        finally:
            crawler.close()

    def get_website_statistics(self) -> Dict[str, Any]:
        """Get statistics about discovered websites."""
        total_websites = self.db_session.query(Website).count()
        total_pages = self.db_session.query(WebsitePage).count()
        total_forms = self.db_session.query(WebsitePageForm).count()
        total_endpoints = self.db_session.query(WebsitePageEndpoint).count()
        
        return {
            "total_websites": total_websites,
            "total_pages": total_pages,
            "total_forms": total_forms,
            "total_endpoints": total_endpoints,
            "websites_by_status": {
                "pending": self.db_session.query(Website).filter(Website.crawl_status == "pending").count(),
                "crawling": self.db_session.query(Website).filter(Website.crawl_status == "crawling").count(),
                "completed": self.db_session.query(Website).filter(Website.crawl_status == "completed").count(),
                "failed": self.db_session.query(Website).filter(Website.crawl_status == "failed").count(),
            }
        } 