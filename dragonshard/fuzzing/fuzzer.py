"""
DragonShard Fuzzer Module

Main fuzzing engine for vulnerability discovery.
"""

import json
import logging
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)


@dataclass
class FuzzResult:
    """Result of a fuzzing test."""

    url: str
    method: str
    payload: str
    payload_type: str
    status_code: int
    response_time: float
    response_size: int
    response_headers: Dict[str, str]
    response_body: str
    is_vulnerable: bool
    vulnerability_type: Optional[str]
    confidence: float
    evidence: Optional[str]


class Fuzzer:
    """
    Main fuzzing engine for vulnerability discovery.
    """

    def __init__(self, timeout: int = 10, max_retries: int = 3, delay: float = 0.1):
        """
        Initialize the fuzzer.

        Args:
            timeout: HTTP request timeout in seconds
            max_retries: Maximum number of retries for failed requests
            delay: Delay between requests in seconds
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.delay = delay
        self.client = httpx.Client(timeout=timeout)
        self.payloads = self._load_payloads()
        self.results: List[FuzzResult] = []

    def __del__(self):
        """Clean up the HTTP client."""
        if hasattr(self, "client"):
            self.client.close()

    def _load_payloads(self) -> Dict[str, Dict[str, Any]]:
        """Load payloads from the JSON file."""
        try:
            with open("dragonshard/fuzzing/payloads.json", "r") as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning("payloads.json not found, using empty payloads")
            return {}
        except json.JSONDecodeError as e:
            logger.error(f"Error loading payloads.json: {e}")
            return {}

    def fuzz_url(
        self,
        url: str,
        method: str = "GET",
        payload_types: Optional[List[str]] = None,
        custom_headers: Optional[Dict[str, str]] = None,
    ) -> List[FuzzResult]:
        """
        Fuzz a single URL with various payloads.

        Args:
            url: Target URL to fuzz
            method: HTTP method (GET, POST, etc.)
            payload_types: List of payload types to test (e.g., ['xss', 'sqli'])
            custom_headers: Custom HTTP headers to include

        Returns:
            List of FuzzResult objects
        """
        logger.info(f"Fuzzing {url} with method {method}")

        if payload_types is None:
            payload_types = list(self.payloads.keys())

        results = []

        for payload_type in payload_types:
            if payload_type not in self.payloads:
                logger.warning(f"Unknown payload type: {payload_type}")
                continue

            payloads = self.payloads[payload_type]["payloads"]
            logger.info(f"Testing {len(payloads)} {payload_type} payloads")

            for payload in payloads:
                result = self._test_payload(url, method, payload, payload_type, custom_headers)
                results.append(result)

                # Add delay between requests
                time.sleep(self.delay)

        self.results.extend(results)
        return results

    def _test_payload(
        self,
        url: str,
        method: str,
        payload: str,
        payload_type: str,
        custom_headers: Optional[Dict[str, str]] = None,
    ) -> FuzzResult:
        """
        Test a single payload against the target URL.

        Args:
            url: Target URL
            method: HTTP method
            payload: The payload to test
            payload_type: Type of payload (xss, sqli, etc.)
            custom_headers: Custom HTTP headers

        Returns:
            FuzzResult object
        """
        start_time = time.time()

        # Prepare headers
        headers = {
            "User-Agent": "DragonShard/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }

        if custom_headers:
            headers.update(custom_headers)

        # Prepare request data
        if method.upper() == "GET":
            # Add payload to URL parameters
            parsed_url = urlparse(url)
            if parsed_url.query:
                url_with_payload = f"{url}&test={payload}"
            else:
                url_with_payload = f"{url}?test={payload}"
            request_data = None
        else:
            # For POST/PUT/etc, add payload to body
            url_with_payload = url
            request_data = {"test": payload}

        # Make the request
        try:
            response = self.client.request(
                method=method,
                url=url_with_payload,
                headers=headers,
                data=request_data,
                follow_redirects=False,
            )

            response_time = time.time() - start_time

            # Analyze response for vulnerabilities
            is_vulnerable, vulnerability_type, confidence, evidence = self._analyze_response(
                response, payload, payload_type
            )

            return FuzzResult(
                url=url,
                method=method,
                payload=payload,
                payload_type=payload_type,
                status_code=response.status_code,
                response_time=response_time,
                response_size=len(response.content),
                response_headers=dict(response.headers),
                response_body=response.text,
                is_vulnerable=is_vulnerable,
                vulnerability_type=vulnerability_type,
                confidence=confidence,
                evidence=evidence,
            )

        except Exception as e:
            logger.warning(f"Error testing payload {payload}: {e}")
            response_time = time.time() - start_time

            return FuzzResult(
                url=url,
                method=method,
                payload=payload,
                payload_type=payload_type,
                status_code=0,
                response_time=response_time,
                response_size=0,
                response_headers={},
                response_body="",
                is_vulnerable=False,
                vulnerability_type=None,
                confidence=0.0,
                evidence=f"Request failed: {str(e)}",
            )

    def _analyze_response(
        self, response: httpx.Response, payload: str, payload_type: str
    ) -> Tuple[bool, Optional[str], float, Optional[str]]:
        """
        Analyze response for potential vulnerabilities.

        Args:
            response: HTTP response object
            payload: The payload that was sent
            payload_type: Type of payload

        Returns:
            Tuple of (is_vulnerable, vulnerability_type, confidence, evidence)
        """
        response_text = response.text.lower()
        response_headers = {k.lower(): v.lower() for k, v in response.headers.items()}

        # XSS detection
        if payload_type == "xss":
            return self._detect_xss(response_text, payload)

        # SQL Injection detection
        elif payload_type == "sqli":
            return self._detect_sqli(response_text, payload)

        # Command Injection detection
        elif payload_type == "command_injection":
            return self._detect_command_injection(response_text, payload)

        # Path Traversal detection
        elif payload_type == "path_traversal":
            return self._detect_path_traversal(response_text, payload)

        # Default: basic anomaly detection
        else:
            return self._detect_anomaly(response, payload, payload_type)

    def _detect_xss(
        self, response_text: str, payload: str
    ) -> Tuple[bool, Optional[str], float, Optional[str]]:
        """Detect XSS vulnerabilities."""
        # Check if payload is reflected in response
        if payload.lower() in response_text:
            return True, "XSS", 0.8, "Payload reflected in response"

        # Check for common XSS indicators
        xss_indicators = [
            "script",
            "javascript:",
            "onerror",
            "onload",
            "onclick",
            "alert(",
            "confirm(",
            "prompt(",
            "eval(",
        ]

        for indicator in xss_indicators:
            if indicator in response_text:
                return True, "XSS", 0.6, f"XSS indicator found: {indicator}"

        return False, None, 0.0, None

    def _detect_sqli(
        self, response_text: str, payload: str
    ) -> Tuple[bool, Optional[str], float, Optional[str]]:
        """Detect SQL injection vulnerabilities."""
        # Check for SQL error messages
        sql_errors = [
            "sql syntax",
            "mysql",
            "oracle",
            "postgresql",
            "sqlite",
            "syntax error",
            "unclosed quotation mark",
            "quoted string",
            "mysql_fetch_array",
            "mysql_fetch_object",
            "mysql_num_rows",
        ]

        for error in sql_errors:
            if error in response_text:
                return True, "SQL Injection", 0.9, f"SQL error detected: {error}"

        # Check for payload reflection
        if payload.lower() in response_text:
            return True, "SQL Injection", 0.7, "SQL payload reflected in response"

        return False, None, 0.0, None

    def _detect_command_injection(
        self, response_text: str, payload: str
    ) -> Tuple[bool, Optional[str], float, Optional[str]]:
        """Detect command injection vulnerabilities."""
        # Check for command output in response
        command_outputs = [
            "root:",
            "uid=",
            "gid=",
            "groups=",
            "total ",
            "drwx",
            "ls -la",
            "whoami",
            "id",
            "pwd",
            "uname",
            "cat ",
        ]

        for output in command_outputs:
            if output in response_text:
                return True, "Command Injection", 0.9, f"Command output detected: {output}"

        return False, None, 0.0, None

    def _detect_path_traversal(
        self, response_text: str, payload: str
    ) -> Tuple[bool, Optional[str], float, Optional[str]]:
        """Detect path traversal vulnerabilities."""
        # Check for file contents in response
        file_indicators = [
            "root:x:",
            "bin:x:",
            "daemon:x:",
            "sys:x:",
            "sync:x:",
            "games:x:",
            "man:x:",
            "lp:x:",
            "mail:x:",
            "news:x:",
            "uucp:x:",
            "proxy:x:",
            "www-data:x:",
            "backup:x:",
            "list:x:",
            "irc:x:",
            "gnats:x:",
            "nobody:x:",
            "systemd-network:x:",
        ]

        for indicator in file_indicators:
            if indicator in response_text:
                return True, "Path Traversal", 0.9, f"File contents detected: {indicator}"

        return False, None, 0.0, None

    def _detect_anomaly(
        self, response: httpx.Response, payload: str, payload_type: str
    ) -> Tuple[bool, Optional[str], float, Optional[str]]:
        """Detect general anomalies in response."""
        # Check for unusual status codes
        if response.status_code >= 500:
            return True, f"{payload_type.upper()}", 0.7, f"Server error: {response.status_code}"

        # Check for unusual response size
        if len(response.content) > 10000:  # Large response might indicate data leakage
            return (
                True,
                f"{payload_type.upper()}",
                0.5,
                f"Large response size: {len(response.content)} bytes",
            )

        # Check for payload reflection
        if payload.lower() in response.text.lower():
            return True, f"{payload_type.upper()}", 0.6, "Payload reflected in response"

        return False, None, 0.0, None

    def get_vulnerabilities(self) -> List[FuzzResult]:
        """Get all detected vulnerabilities."""
        return [result for result in self.results if result.is_vulnerable]

    def get_results_summary(self) -> Dict[str, Any]:
        """Get a summary of fuzzing results."""
        total_tests = len(self.results)
        vulnerabilities = self.get_vulnerabilities()

        summary = {
            "total_tests": total_tests,
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerability_types": {},
            "payload_types_tested": set(),
            "average_response_time": 0.0,
            "success_rate": 0.0,
        }

        if total_tests > 0:
            # Calculate statistics
            successful_tests = [r for r in self.results if r.status_code > 0]
            summary["success_rate"] = len(successful_tests) / total_tests
            summary["average_response_time"] = (
                sum(r.response_time for r in self.results) / total_tests
            )

            # Count vulnerability types
            for vuln in vulnerabilities:
                vuln_type = vuln.vulnerability_type or "Unknown"
                summary["vulnerability_types"][vuln_type] = (
                    summary["vulnerability_types"].get(vuln_type, 0) + 1
                )

            # Get payload types tested
            summary["payload_types_tested"] = set(r.payload_type for r in self.results)

        return summary

    def export_results(self, filename: str, format: str = "json") -> None:
        """
        Export fuzzing results to a file.

        Args:
            filename: Output filename
            format: Export format (json, csv)
        """
        if format == "json":
            with open(filename, "w") as f:
                json.dump([asdict(result) for result in self.results], f, indent=2)
        elif format == "csv":
            import csv

            with open(filename, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=asdict(self.results[0]).keys())
                writer.writeheader()
                for result in self.results:
                    writer.writerow(asdict(result))
        else:
            raise ValueError(f"Unsupported format: {format}")

        logger.info(f"Results exported to {filename}")


if __name__ == "__main__":
    # Example usage
    import logging

    logging.basicConfig(level=logging.INFO)

    fuzzer = Fuzzer()
    results = fuzzer.fuzz_url("http://testphp.vulnweb.com/search.php", "GET", ["xss", "sqli"])

    print(f"Found {len(fuzzer.get_vulnerabilities())} vulnerabilities")
    for vuln in fuzzer.get_vulnerabilities():
        print(f"- {vuln.vulnerability_type}: {vuln.evidence}")
