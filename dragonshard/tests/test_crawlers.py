#!/usr/bin/env python3
"""
Unit tests for the crawler modules.
"""

import unittest
import logging
from unittest.mock import patch, MagicMock, Mock
from typing import Set
import sys
import os

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from dragonshard.api_inference.crawler import FastCrawler, BaseCrawler
from dragonshard.api_inference.js_crawler import JSCrawler
from dragonshard.api_inference.unified_crawler import (
    UnifiedCrawler, smart_crawl, crawl_fast, crawl_with_js, compare_crawlers
)


class TestBaseCrawler(unittest.TestCase):
    """Test the base crawler class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.crawler = FastCrawler(max_depth=2, max_pages=10, timeout=5)
    
    def test_base_crawler_initialization(self):
        """Test that the base crawler initializes correctly."""
        self.assertEqual(self.crawler.max_depth, 2)
        self.assertEqual(self.crawler.max_pages, 10)
        self.assertEqual(self.crawler.timeout, 5)
    
    def test_base_crawler_abstract_methods(self):
        """Test that BaseCrawler is abstract and cannot be instantiated."""
        with self.assertRaises(TypeError):
            BaseCrawler()


class TestFastCrawler(unittest.TestCase):
    """Test the fast httpx-based crawler."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.crawler = FastCrawler(max_depth=1, max_pages=5)
    
    def tearDown(self):
        """Clean up after tests."""
        if hasattr(self.crawler, 'client'):
            self.crawler.client.close()
    
    def test_fast_crawler_initialization(self):
        """Test that FastCrawler initializes correctly."""
        self.assertIsNotNone(self.crawler.client)
        self.assertEqual(self.crawler.max_depth, 1)
        self.assertEqual(self.crawler.max_pages, 5)
    
    def test_extract_links_basic(self):
        """Test basic link extraction."""
        html = '''
        <html>
            <a href="http://example.com/page1">Page 1</a>
            <a href="http://example.com/page2">Page 2</a>
            <a href="javascript:void(0)">JS Link</a>
            <a href="mailto:test@example.com">Email</a>
        </html>
        '''
        base_url = "http://example.com/"
        links = self.crawler.extract_links(html, base_url)
        
        expected = {
            "http://example.com/page1",
            "http://example.com/page2"
        }
        self.assertEqual(links, expected)
    
    def test_extract_links_relative_urls(self):
        """Test extraction of relative URLs."""
        html = '''
        <html>
            <a href="/relative/path">Relative</a>
            <a href="relative.html">Relative</a>
            <a href="../parent.html">Parent</a>
        </html>
        '''
        base_url = "http://example.com/current/"
        links = self.crawler.extract_links(html, base_url)
        
        expected = {
            "http://example.com/relative/path",
            "http://example.com/current/relative.html",
            "http://example.com/parent.html"
        }
        self.assertEqual(links, expected)
    
    @patch('httpx.Client.get')
    def test_fetch_page_success(self, mock_get):
        """Test successful page fetching."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {'content-type': 'text/html'}
        mock_response.text = '<html><a href="http://example.com">Link</a></html>'
        mock_get.return_value = mock_response
        
        content = self.crawler.fetch_page("http://example.com/")
        self.assertIsNotNone(content)
        self.assertEqual(content, mock_response.text)
    
    @patch('httpx.Client.get')
    def test_fetch_page_non_html(self, mock_get):
        """Test fetching non-HTML content."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {'content-type': 'application/json'}
        mock_get.return_value = mock_response
        
        content = self.crawler.fetch_page("http://example.com/api")
        self.assertIsNone(content)
    
    @patch('httpx.Client.get')
    def test_fetch_page_error(self, mock_get):
        """Test handling of fetch errors."""
        mock_get.side_effect = Exception("Network error")
        
        content = self.crawler.fetch_page("http://example.com/")
        self.assertIsNone(content)
    
    @patch('httpx.Client.get')
    def test_crawl_basic(self, mock_get):
        """Test basic crawling functionality."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {'content-type': 'text/html'}
        mock_response.text = '''
        <html>
            <a href="http://example.com/page1">Page 1</a>
            <a href="http://example.com/page2">Page 2</a>
        </html>
        '''
        mock_get.return_value = mock_response
        
        urls = self.crawler.crawl("http://example.com/")
        
        # Should find the start URL and the linked pages
        expected = {
            "http://example.com/",
            "http://example.com/page1",
            "http://example.com/page2"
        }
        self.assertEqual(urls, expected)


class TestJSCrawler(unittest.TestCase):
    """Test the JavaScript-enabled crawler."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.crawler = JSCrawler(max_depth=1, max_pages=5, headless=True)
    
    def test_js_crawler_initialization(self):
        """Test that JSCrawler initializes correctly."""
        self.assertEqual(self.crawler.max_depth, 1)
        self.assertEqual(self.crawler.max_pages, 5)
        self.assertEqual(self.crawler.wait_time, 2)
        self.assertTrue(self.crawler.headless)
    
    @patch('playwright.sync_api.sync_playwright')
    def test_context_manager(self, mock_playwright):
        """Test context manager functionality."""
        mock_playwright_instance = MagicMock()
        mock_browser = MagicMock()
        mock_playwright_instance.chromium.launch.return_value = mock_browser
        mock_playwright.return_value.__enter__.return_value = mock_playwright_instance
        
        with JSCrawler() as crawler:
            self.assertIsNotNone(crawler.browser)
        
        # Check that cleanup was called
        mock_browser.close.assert_called_once()
        mock_playwright_instance.stop.assert_called_once()
    
    @patch('playwright.sync_api.sync_playwright')
    def test_extract_links(self, mock_playwright):
        """Test link extraction from rendered page."""
        # Mock the page and elements
        mock_element1 = MagicMock()
        mock_element1.get_attribute.return_value = "http://example.com/page1"
        
        mock_element2 = MagicMock()
        mock_element2.get_attribute.return_value = "javascript:void(0)"
        
        mock_element3 = MagicMock()
        mock_element3.get_attribute.return_value = "mailto:test@example.com"
        
        mock_page = MagicMock()
        mock_page.query_selector_all.return_value = [mock_element1, mock_element2, mock_element3]
        
        links = self.crawler.extract_links(mock_page, "http://example.com/")
        
        expected = {"http://example.com/page1"}
        self.assertEqual(links, expected)
    
    @patch('playwright.sync_api.sync_playwright')
    def test_fetch_page_success(self, mock_playwright):
        """Test successful page fetching with Playwright."""
        # Mock the browser and page
        mock_browser = MagicMock()
        mock_page = MagicMock()
        mock_response = MagicMock()
        mock_response.status = 200
        
        mock_browser.new_page.return_value = mock_page
        mock_page.goto.return_value = mock_response
        
        self.crawler.browser = mock_browser
        
        page = self.crawler.fetch_page("http://example.com/")
        
        self.assertIsNotNone(page)
        mock_page.set_extra_http_headers.assert_called_once()
        mock_page.goto.assert_called_once()
    
    @patch('playwright.sync_api.sync_playwright')
    def test_fetch_page_error(self, mock_playwright):
        """Test handling of fetch errors in JS crawler."""
        mock_browser = MagicMock()
        mock_page = MagicMock()
        mock_browser.new_page.return_value = mock_page
        mock_page.goto.side_effect = Exception("Navigation error")
        
        self.crawler.browser = mock_browser
        
        page = self.crawler.fetch_page("http://example.com/")
        self.assertIsNone(page)


class TestUnifiedCrawler(unittest.TestCase):
    """Test the unified crawler functionality."""
    
    def test_unified_crawler_fast(self):
        """Test unified crawler with fast mode."""
        with patch('dragonshard.api_inference.crawler.FastCrawler') as mock_fast_crawler:
            mock_crawler_instance = MagicMock()
            mock_crawler_instance.crawl.return_value = {"http://example.com/"}
            mock_fast_crawler.return_value = mock_crawler_instance
            
            crawler = UnifiedCrawler(use_js=False, max_depth=1, max_pages=5)
            urls = crawler.crawl("http://example.com/")
            
            self.assertEqual(urls, {"http://example.com/"})
            mock_fast_crawler.assert_called_once_with(max_depth=1, max_pages=5)
    
    def test_unified_crawler_js(self):
        """Test unified crawler with JavaScript mode."""
        with patch('dragonshard.api_inference.js_crawler.JSCrawler') as mock_js_crawler:
            mock_crawler_instance = MagicMock()
            mock_crawler_instance.crawl.return_value = {"http://example.com/"}
            mock_js_crawler.return_value.__enter__.return_value = mock_crawler_instance
            
            crawler = UnifiedCrawler(use_js=True, max_depth=1, max_pages=5)
            urls = crawler.crawl("http://example.com/")
            
            self.assertEqual(urls, {"http://example.com/"})
            mock_js_crawler.assert_called_once_with(max_depth=1, max_pages=5)


class TestCrawlerFunctions(unittest.TestCase):
    """Test the convenience functions."""
    
    @patch('dragonshard.api_inference.unified_crawler.crawl_fast')
    def test_smart_crawl_fast(self, mock_crawl_fast):
        """Test smart_crawl with fast mode."""
        mock_crawl_fast.return_value = {"http://example.com/"}
        
        urls = smart_crawl("http://example.com/", max_depth=1, max_pages=5)
        
        self.assertEqual(urls, {"http://example.com/"})
        mock_crawl_fast.assert_called_once_with("http://example.com/", 1, 5)
    
    @patch('dragonshard.api_inference.unified_crawler.crawl_with_js')
    def test_smart_crawl_js(self, mock_crawl_with_js):
        """Test smart_crawl with JavaScript mode."""
        mock_crawl_with_js.return_value = {"http://example.com/"}
        
        urls = smart_crawl("http://example.com/", max_depth=1, max_pages=5, force_js=True)
        
        self.assertEqual(urls, {"http://example.com/"})
        mock_crawl_with_js.assert_called_once()
    
    @patch('dragonshard.api_inference.unified_crawler.crawl_fast')
    @patch('dragonshard.api_inference.unified_crawler.crawl_with_js')
    def test_compare_crawlers(self, mock_crawl_with_js, mock_crawl_fast):
        """Test crawler comparison functionality."""
        mock_crawl_fast.return_value = {"http://example.com/", "http://example.com/page1"}
        mock_crawl_with_js.return_value = {"http://example.com/", "http://example.com/page1", "http://example.com/js-page"}
        
        results = compare_crawlers("http://example.com/", max_depth=1, max_pages=5)
        
        self.assertIn('fast', results)
        self.assertIn('js', results)
        self.assertIn('comparison', results)
        self.assertTrue(results['comparison']['js_needed'])
        self.assertEqual(results['comparison']['js_only_count'], 1)


class TestCrawlerIntegration(unittest.TestCase):
    """Integration tests for crawler functionality."""
    
    def test_crawler_imports(self):
        """Test that all crawler modules can be imported."""
        try:
            from dragonshard.api_inference.crawler import FastCrawler, BaseCrawler
            from dragonshard.api_inference.js_crawler import JSCrawler
            from dragonshard.api_inference.unified_crawler import (
                UnifiedCrawler, smart_crawl, crawl_fast, crawl_with_js, compare_crawlers
            )
        except ImportError as e:
            self.fail(f"Failed to import crawler modules: {e}")
    
    def test_crawler_instantiation(self):
        """Test that crawler classes can be instantiated."""
        try:
            fast_crawler = FastCrawler(max_depth=1, max_pages=5)
            self.assertIsInstance(fast_crawler, FastCrawler)
            
            js_crawler = JSCrawler(max_depth=1, max_pages=5)
            self.assertIsInstance(js_crawler, JSCrawler)
            
            unified_crawler = UnifiedCrawler(use_js=False, max_depth=1, max_pages=5)
            self.assertIsInstance(unified_crawler, UnifiedCrawler)
        except Exception as e:
            self.fail(f"Failed to instantiate crawler classes: {e}")


if __name__ == '__main__':
    # Set up logging for tests
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run the tests
    unittest.main(verbosity=2) 