import httpx
from typing import List, Set, Optional
from urllib.parse import urljoin, urlparse
import re
from abc import ABC, abstractmethod
import logging

logger = logging.getLogger(__name__)


class BaseCrawler(ABC):
    """Base class for web crawlers."""
    
    def __init__(self, max_depth: int = 2, max_pages: int = 50, timeout: int = 10):
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
    
    @abstractmethod
    def extract_links(self, content: str, base_url: str) -> Set[str]:
        """Extract links from page content."""
        pass
    
    @abstractmethod
    def fetch_page(self, url: str) -> Optional[str]:
        """Fetch page content."""
        pass
    
    def crawl(self, start_url: str) -> Set[str]:
        """
        Crawl from start_url, following links up to max_depth.
        Returns discovered URLs.
        """
        visited = set()
        to_visit = [(start_url, 0)]
        
        logger.info(f"Starting crawl from {start_url} (max_depth={self.max_depth}, max_pages={self.max_pages})")
        
        while to_visit and len(visited) < self.max_pages:
            url, depth = to_visit.pop(0)
            
            if url in visited or depth > self.max_depth:
                continue
                
            logger.debug(f"Crawling {url} at depth {depth}")
            
            try:
                content = self.fetch_page(url)
                if content is None:
                    continue
                    
                visited.add(url)
                links = self.extract_links(content, url)
                
                logger.debug(f"Found {len(links)} links on {url}")
                
                for link in links:
                    if link not in visited:
                        to_visit.append((link, depth + 1))
                        
            except Exception as e:
                logger.warning(f"Error crawling {url}: {e}")
                
        logger.info(f"Crawl completed. Discovered {len(visited)} URLs")
        return visited


class FastCrawler(BaseCrawler):
    """Fast crawler using httpx - no JavaScript support."""
    
    def __init__(self, max_depth: int = 2, max_pages: int = 50, timeout: int = 10):
        super().__init__(max_depth, max_pages, timeout)
        self.client = httpx.Client(timeout=self.timeout)
    
    def extract_links(self, html: str, base_url: str) -> Set[str]:
        """
        Extract all href links from HTML, resolving relative URLs.
        """
        links = set()
        for match in re.findall(r'href=["\"](.*?)["\"]', html, re.IGNORECASE):
            # Ignore javascript: and mailto: links
            if match.startswith("javascript:") or match.startswith("mailto:"):
                continue
            # Resolve relative URLs
            full_url = urljoin(base_url, match)
            # Only keep http(s) links
            if urlparse(full_url).scheme in ("http", "https"):
                links.add(full_url)
        return links
    
    def fetch_page(self, url: str) -> Optional[str]:
        """
        Fetch page content using httpx.
        """
        try:
            response = self.client.get(url)
            if response.status_code != 200 or 'text/html' not in response.headers.get('content-type', ''):
                return None
            return response.text
        except Exception as e:
            logger.warning(f"Failed to fetch {url}: {e}")
            return None
    
    def __del__(self):
        """Clean up httpx client."""
        if hasattr(self, 'client'):
            self.client.close()


# Legacy function for backward compatibility
def crawl(start_url: str, max_depth: int = 2, max_pages: int = 50) -> Set[str]:
    """
    Legacy function - uses FastCrawler.
    """
    crawler = FastCrawler(max_depth=max_depth, max_pages=max_pages)
    return crawler.crawl(start_url)


if __name__ == "__main__":
    # Example usage
    import logging
    logging.basicConfig(level=logging.INFO)
    
    start = "http://testphp.vulnweb.com/"
    crawler = FastCrawler(max_depth=1, max_pages=10)
    found = crawler.crawl(start)
    print("Discovered URLs:")
    for url in found:
        print(url)
