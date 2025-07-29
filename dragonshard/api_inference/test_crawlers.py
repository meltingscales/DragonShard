#!/usr/bin/env python3
"""
Test script to demonstrate both crawler implementations.
"""

import logging
import sys
import os

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from dragonshard.api_inference.crawler import FastCrawler
from dragonshard.api_inference.js_crawler import JSCrawler
from dragonshard.api_inference.unified_crawler import compare_crawlers, smart_crawl


def test_fast_crawler():
    """Test the fast httpx-based crawler."""
    print("=== Testing Fast Crawler ===")
    
    crawler = FastCrawler(max_depth=1, max_pages=5)
    urls = crawler.crawl("http://testphp.vulnweb.com/")
    
    print(f"Found {len(urls)} URLs:")
    for url in sorted(urls):
        print(f"  - {url}")


def test_js_crawler():
    """Test the JavaScript-enabled crawler."""
    print("\n=== Testing JavaScript-Enabled Crawler ===")
    
    with JSCrawler(max_depth=1, max_pages=5, headless=True) as crawler:
        urls = crawler.crawl("http://testphp.vulnweb.com/")
    
    print(f"Found {len(urls)} URLs:")
    for url in sorted(urls):
        print(f"  - {url}")


def test_comparison():
    """Compare both crawlers on the same site."""
    print("\n=== Comparing Both Crawlers ===")
    
    results = compare_crawlers("http://testphp.vulnweb.com/", max_depth=1, max_pages=5)
    
    print(f"Fast crawler: {results['fast']['count']} URLs in {results['fast']['time']:.2f}s")
    print(f"JS crawler: {results['js']['count']} URLs in {results['js']['time']:.2f}s")
    
    if results['comparison']['js_needed']:
        print(f"\n⚠️  JavaScript needed! JS crawler found {results['comparison']['js_only_count']} additional URLs")
    else:
        print("\n✅ Fast crawler is sufficient")


def test_smart_crawl():
    """Test the smart crawling function."""
    print("\n=== Testing Smart Crawl ===")
    
    # Test fast crawling
    print("Fast crawling:")
    urls = smart_crawl("http://testphp.vulnweb.com/", max_depth=1, max_pages=5)
    print(f"Found {len(urls)} URLs")
    
    # Test JS crawling
    print("\nJavaScript crawling:")
    urls = smart_crawl("http://testphp.vulnweb.com/", max_depth=1, max_pages=5, force_js=True)
    print(f"Found {len(urls)} URLs")


if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        test_fast_crawler()
        test_js_crawler()
        test_comparison()
        test_smart_crawl()
        
        print("\n✅ All tests completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Error during testing: {e}")
        import traceback
        traceback.print_exc() 