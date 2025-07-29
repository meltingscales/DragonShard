from typing import Set, Optional, Dict, Any
import logging
from .crawler import FastCrawler
from .js_crawler import JSCrawler

logger = logging.getLogger(__name__)


class UnifiedCrawler:
    """
    Unified crawler that can use either fast (httpx) or JavaScript-enabled (Playwright) crawling.
    """
    
    def __init__(self, use_js: bool = False, **kwargs):
        """
        Initialize crawler.
        
        Args:
            use_js: If True, use JavaScript-enabled crawler (slower but handles dynamic content)
            **kwargs: Passed to the underlying crawler
        """
        self.use_js = use_js
        self.kwargs = kwargs
        
        if use_js:
            self.crawler = JSCrawler(**kwargs)
        else:
            self.crawler = FastCrawler(**kwargs)
    
    def crawl(self, start_url: str) -> Set[str]:
        """
        Crawl the given URL using the appropriate crawler.
        """
        if self.use_js:
            logger.info(f"Using JavaScript-enabled crawler for {start_url}")
            with self.crawler as js_crawler:
                return js_crawler.crawl(start_url)
        else:
            logger.info(f"Using fast crawler for {start_url}")
            return self.crawler.crawl(start_url)


def smart_crawl(start_url: str, max_depth: int = 2, max_pages: int = 50,
                force_js: bool = False, **kwargs) -> Set[str]:
    """
    Smart crawling that automatically chooses the best crawler.
    
    Args:
        start_url: URL to start crawling from
        max_depth: Maximum crawl depth
        max_pages: Maximum number of pages to crawl
        force_js: Force JavaScript-enabled crawling
        **kwargs: Additional arguments for crawlers
    """
    if force_js:
        logger.info("Forcing JavaScript-enabled crawling")
        return crawl_with_js(start_url, max_depth, max_pages, **kwargs)
    
    # For now, use fast crawler by default
    # In the future, you could add logic to detect if JS is needed
    logger.info("Using fast crawler (use force_js=True for JavaScript support)")
    return crawl_fast(start_url, max_depth, max_pages, **kwargs)


def crawl_fast(start_url: str, max_depth: int = 2, max_pages: int = 50, **kwargs) -> Set[str]:
    """
    Fast crawling using httpx (no JavaScript support).
    """
    crawler = FastCrawler(max_depth=max_depth, max_pages=max_pages, **kwargs)
    return crawler.crawl(start_url)


def crawl_with_js(start_url: str, max_depth: int = 2, max_pages: int = 50,
                  wait_time: int = 2, headless: bool = True, **kwargs) -> Set[str]:
    """
    JavaScript-enabled crawling using Playwright.
    """
    with JSCrawler(max_depth=max_depth, max_pages=max_pages,
                   wait_time=wait_time, headless=headless, **kwargs) as crawler:
        return crawler.crawl(start_url)


def compare_crawlers(start_url: str, max_depth: int = 1, max_pages: int = 10) -> Dict[str, Any]:
    """
    Compare results from both crawlers on the same URL.
    Useful for testing if JavaScript is needed.
    """
    import time
    
    results = {}
    
    # Test fast crawler
    logger.info("Testing fast crawler...")
    start_time = time.time()
    fast_results = crawl_fast(start_url, max_depth, max_pages)
    fast_time = time.time() - start_time
    
    results['fast'] = {
        'urls': fast_results,
        'count': len(fast_results),
        'time': fast_time
    }
    
    # Test JS crawler
    logger.info("Testing JavaScript-enabled crawler...")
    start_time = time.time()
    js_results = crawl_with_js(start_url, max_depth, max_pages)
    js_time = time.time() - start_time
    
    results['js'] = {
        'urls': js_results,
        'count': len(js_results),
        'time': js_time
    }
    
    # Compare results
    fast_only = fast_results - js_results
    js_only = js_results - fast_results
    common = fast_results & js_results
    
    results['comparison'] = {
        'fast_only': fast_only,
        'js_only': js_only,
        'common': common,
        'fast_only_count': len(fast_only),
        'js_only_count': len(js_only),
        'common_count': len(common),
        'js_needed': len(js_only) > 0
    }
    
    return results


if __name__ == "__main__":
    # Example usage
    import logging
    logging.basicConfig(level=logging.INFO)
    
    start = "http://testphp.vulnweb.com/"
    
    # Test both crawlers
    print("=== Comparing Crawlers ===")
    results = compare_crawlers(start, max_depth=1, max_pages=10)
    
    print(f"\nFast crawler found {results['fast']['count']} URLs in {results['fast']['time']:.2f}s")
    print(f"JS crawler found {results['js']['count']} URLs in {results['js']['time']:.2f}s")
    
    if results['comparison']['js_needed']:
        print(f"\n⚠️  JavaScript is needed! JS crawler found {results['comparison']['js_only_count']} additional URLs")
        print("JS-only URLs:", results['comparison']['js_only'])
    else:
        print("\n✅ Fast crawler is sufficient for this site")
    
    print(f"\nCommon URLs: {results['comparison']['common_count']}")
    print(f"Fast-only URLs: {results['comparison']['fast_only_count']}") 