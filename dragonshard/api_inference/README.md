# API Inference Crawler Module

This module provides web crawling capabilities for discovering API endpoints and web pages. It includes two different crawler implementations to handle different types of websites.

## Crawler Types

### 1. Fast Crawler (`FastCrawler`)
- **Library**: `httpx`
- **JavaScript Support**: ❌ No
- **Speed**: ⚡ Fast
- **Use Case**: Static websites, server-rendered content
- **Memory Usage**: Low
- **Dependencies**: `httpx`

### 2. JavaScript-Enabled Crawler (`JSCrawler`)
- **Library**: `playwright`
- **JavaScript Support**: ✅ Yes
- **Speed**: 🐌 Slower
- **Use Case**: Dynamic websites, SPAs, JavaScript-heavy sites
- **Memory Usage**: Higher (runs browser)
- **Dependencies**: `playwright`

## Usage Examples

### Basic Fast Crawling
```python
from dragonshard.api_inference.crawler import FastCrawler

# Create fast crawler
crawler = FastCrawler(max_depth=2, max_pages=50)
urls = crawler.crawl("http://example.com/")

print(f"Found {len(urls)} URLs")
for url in urls:
    print(f"  - {url}")
```

### JavaScript-Enabled Crawling
```python
from dragonshard.api_inference.js_crawler import JSCrawler

# Use context manager for automatic cleanup
with JSCrawler(max_depth=2, max_pages=50, headless=True) as crawler:
    urls = crawler.crawl("http://example.com/")

print(f"Found {len(urls)} URLs")
```

### Smart Crawling (Recommended)
```python
from dragonshard.api_inference.unified_crawler import smart_crawl

# Fast crawling (default)
urls = smart_crawl("http://example.com/", max_depth=2, max_pages=50)

# Force JavaScript crawling
urls = smart_crawl("http://example.com/", max_depth=2, max_pages=50, force_js=True)
```

### Compare Both Crawlers
```python
from dragonshard.api_inference.unified_crawler import compare_crawlers

# Compare results from both crawlers
results = compare_crawlers("http://example.com/", max_depth=1, max_pages=10)

print(f"Fast crawler: {results['fast']['count']} URLs in {results['fast']['time']:.2f}s")
print(f"JS crawler: {results['js']['count']} URLs in {results['js']['time']:.2f}s")

if results['comparison']['js_needed']:
    print("⚠️  JavaScript is needed for this site!")
else:
    print("✅ Fast crawler is sufficient")
```

## Configuration Options

### Fast Crawler Options
- `max_depth`: Maximum crawl depth (default: 2)
- `max_pages`: Maximum number of pages to crawl (default: 50)
- `timeout`: HTTP request timeout in seconds (default: 10)

### JavaScript Crawler Options
- `max_depth`: Maximum crawl depth (default: 2)
- `max_pages`: Maximum number of pages to crawl (default: 50)
- `wait_time`: Time to wait for JavaScript to load in seconds (default: 2)
- `headless`: Run browser in headless mode (default: True)

## When to Use Each Crawler

### Use Fast Crawler When:
- ✅ Site is mostly static HTML
- ✅ Links are present in the initial HTML
- ✅ No dynamic content loading
- ✅ Speed is important
- ✅ Memory usage is a concern

### Use JavaScript Crawler When:
- ✅ Site uses JavaScript frameworks (React, Vue, Angular)
- ✅ Links are loaded dynamically via AJAX
- ✅ Content is rendered client-side
- ✅ You need to capture JavaScript-generated links
- ✅ Site has complex interactions

## Testing

Run the test script to see both crawlers in action:

```bash
cd dragonshard/api_inference
python test_crawlers.py
```

## Installation

The fast crawler only requires `httpx` (already in requirements).

For the JavaScript crawler, install Playwright:

```bash
# Install playwright
pip install playwright

# Install browser binaries
playwright install chromium
```

## Performance Comparison

| Metric | Fast Crawler | JS Crawler |
|--------|--------------|------------|
| Speed | ⚡ Very Fast | 🐌 Slower |
| Memory | Low | Higher |
| JS Support | ❌ No | ✅ Yes |
| Setup | Simple | Requires browser |
| Use Case | Static sites | Dynamic sites |

## Troubleshooting

### Playwright Issues
- **Browser not found**: Run `playwright install chromium`
- **Permission errors**: Run with appropriate permissions
- **Memory issues**: Reduce `max_pages` or use fast crawler

### Network Issues
- **Timeout errors**: Increase `timeout` parameter
- **Connection refused**: Check target site availability
- **Rate limiting**: Add delays between requests

## Future Enhancements

- [ ] Automatic detection of JavaScript requirements
- [ ] Configurable user agents
- [ ] Cookie/session support
- [ ] Proxy support
- [ ] Rate limiting
- [ ] Respect robots.txt
- [ ] Sitemap.xml parsing 