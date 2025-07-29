import logging
import time
from typing import Optional, Set
from urllib.parse import urljoin, urlparse

from playwright.sync_api import Page, sync_playwright

logger = logging.getLogger(__name__)


class JSCrawler:
    """
    JavaScript-enabled crawler using Playwright.
    Can handle dynamic content and JavaScript-rendered links.
    """

    def __init__(
        self, max_depth: int = 2, max_pages: int = 50, wait_time: int = 2, headless: bool = True
    ):
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.wait_time = wait_time  # Time to wait for JS to load
        self.headless = headless
        self.playwright = None
        self.browser = None

    def __enter__(self):
        """Context manager entry."""
        self.playwright = sync_playwright().start()
        self.browser = self.playwright.chromium.launch(headless=self.headless)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if self.browser:
            self.browser.close()
        if self.playwright:
            self.playwright.stop()

    def extract_links(self, page: Page, base_url: str) -> Set[str]:
        """
        Extract all href links from the rendered page, including JavaScript-generated ones.
        """
        links = set()

        try:
            # Wait for page to load and JavaScript to execute
            page.wait_for_load_state("networkidle", timeout=10000)

            # Get all links from the rendered DOM
            link_elements = page.query_selector_all("a[href]")

            for element in link_elements:
                href = element.get_attribute("href")
                if not href:
                    continue

                # Ignore javascript: and mailto: links
                if href.startswith("javascript:") or href.startswith("mailto:"):
                    continue

                # Resolve relative URLs
                full_url = urljoin(base_url, href)

                # Only keep http(s) links
                if urlparse(full_url).scheme in ("http", "https"):
                    links.add(full_url)

            logger.debug(f"Extracted {len(links)} links from {base_url}")

        except Exception as e:
            logger.warning(f"Error extracting links from {base_url}: {e}")

        return links

    def fetch_page(self, url: str) -> Optional[Page]:
        """
        Fetch and render page content using Playwright.
        Returns the page object for further processing.
        """
        try:
            page = self.browser.new_page()

            # Set user agent to avoid detection
            page.set_extra_http_headers(
                {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            )

            # Navigate to the page
            response = page.goto(url, wait_until="domcontentloaded", timeout=30000)

            if not response or response.status != 200:
                logger.warning(
                    f"Failed to load {url}: status {response.status if response else 'No response'}"
                )
                page.close()
                return None

            # Wait for JavaScript to load and execute
            time.sleep(self.wait_time)

            return page

        except Exception as e:
            logger.warning(f"Failed to fetch {url}: {e}")
            return None

    def crawl(self, start_url: str) -> Set[str]:
        """
        Crawl from start_url, following links up to max_depth.
        Returns discovered URLs.
        """
        visited = set()
        to_visit = [(start_url, 0)]

        logger.info(
            f"Starting JS-enabled crawl from {start_url} (max_depth={self.max_depth}, max_pages={self.max_pages})"
        )

        while to_visit and len(visited) < self.max_pages:
            url, depth = to_visit.pop(0)

            if url in visited or depth > self.max_depth:
                continue

            logger.debug(f"Crawling {url} at depth {depth}")

            try:
                page = self.fetch_page(url)
                if page is None:
                    continue

                visited.add(url)
                links = self.extract_links(page, url)

                logger.debug(f"Found {len(links)} links on {url}")

                # Close the page to free memory
                page.close()

                for link in links:
                    if link not in visited:
                        to_visit.append((link, depth + 1))

            except Exception as e:
                logger.warning(f"Error crawling {url}: {e}")

        logger.info(f"JS crawl completed. Discovered {len(visited)} URLs")
        return visited


def crawl_with_js(
    start_url: str,
    max_depth: int = 2,
    max_pages: int = 50,
    wait_time: int = 2,
    headless: bool = True,
) -> Set[str]:
    """
    Convenience function for JavaScript-enabled crawling.
    """
    with JSCrawler(
        max_depth=max_depth, max_pages=max_pages, wait_time=wait_time, headless=headless
    ) as crawler:
        return crawler.crawl(start_url)


if __name__ == "__main__":
    # Example usage
    import logging

    logging.basicConfig(level=logging.INFO)

    start = "http://testphp.vulnweb.com/"

    # Use context manager for automatic cleanup
    with JSCrawler(max_depth=1, max_pages=10, headless=True) as crawler:
        found = crawler.crawl(start)
        print("Discovered URLs:")
        for url in found:
            print(url)
