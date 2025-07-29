#!/usr/bin/env python3
"""
Unit tests for the fuzzing module.
"""

import json
import logging
import os
import sys
import tempfile
import unittest
from typing import Any, Dict, List
from unittest.mock import MagicMock, Mock, patch

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from dragonshard.fuzzing.anomaly_detector import AnomalyDetector, AnomalyResult
from dragonshard.fuzzing.fuzzer import Fuzzer, FuzzResult
from dragonshard.fuzzing.mutators import PayloadMutator


class TestFuzzer(unittest.TestCase):
    """Test the main fuzzer engine."""

    def setUp(self):
        """Set up test fixtures."""
        self.fuzzer = Fuzzer(timeout=5, delay=0.01)

    def tearDown(self):
        """Clean up after tests."""
        if hasattr(self.fuzzer, "client"):
            self.fuzzer.client.close()

    def test_fuzzer_initialization(self):
        """Test that Fuzzer initializes correctly."""
        self.assertEqual(self.fuzzer.timeout, 5)
        self.assertEqual(self.fuzzer.delay, 0.01)
        self.assertEqual(self.fuzzer.max_retries, 3)
        self.assertIsNotNone(self.fuzzer.client)
        self.assertIsInstance(self.fuzzer.payloads, dict)

    def test_load_payloads(self):
        """Test payload loading functionality."""
        # Test that payloads are loaded
        self.assertIn("xss", self.fuzzer.payloads)
        self.assertIn("sqli", self.fuzzer.payloads)
        self.assertIn("command_injection", self.fuzzer.payloads)

        # Test payload structure
        xss_payloads = self.fuzzer.payloads["xss"]["payloads"]
        self.assertIsInstance(xss_payloads, list)
        self.assertGreater(len(xss_payloads), 0)

    @patch("httpx.Client.request")
    def test_test_payload_success(self, mock_request):
        """Test successful payload testing."""
        # Mock successful response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "Normal response"
        mock_response.content = b"Normal response"
        mock_response.headers = {"content-type": "text/html"}
        mock_request.return_value = mock_response

        result = self.fuzzer._test_payload(
            "http://example.com/test", "GET", "<script>alert('XSS')</script>", "xss"
        )

        self.assertIsInstance(result, FuzzResult)
        self.assertEqual(result.url, "http://example.com/test")
        self.assertEqual(result.method, "GET")
        self.assertEqual(result.payload, "<script>alert('XSS')</script>")
        self.assertEqual(result.payload_type, "xss")
        self.assertEqual(result.status_code, 200)
        self.assertFalse(result.is_vulnerable)

    @patch("httpx.Client.request")
    def test_test_payload_xss_detection(self, mock_request):
        """Test XSS vulnerability detection."""
        # Mock response with XSS payload reflection
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "Found: <script>alert('XSS')</script>"
        mock_response.content = b"Found: <script>alert('XSS')</script>"
        mock_response.headers = {"content-type": "text/html"}
        mock_request.return_value = mock_response

        result = self.fuzzer._test_payload(
            "http://example.com/test", "GET", "<script>alert('XSS')</script>", "xss"
        )

        self.assertTrue(result.is_vulnerable)
        self.assertEqual(result.vulnerability_type, "XSS")
        self.assertGreater(result.confidence, 0.7)
        self.assertIsNotNone(result.evidence)

    @patch("httpx.Client.request")
    def test_test_payload_sqli_detection(self, mock_request):
        """Test SQL injection vulnerability detection."""
        # Mock response with SQL error
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "You have an error in your SQL syntax near '1 OR 1=1'"
        mock_response.content = b"You have an error in your SQL syntax near '1 OR 1=1'"
        mock_response.headers = {"content-type": "text/html"}
        mock_request.return_value = mock_response

        result = self.fuzzer._test_payload("http://example.com/test", "GET", "1 OR 1=1", "sqli")

        self.assertTrue(result.is_vulnerable)
        self.assertEqual(result.vulnerability_type, "SQL Injection")
        self.assertGreater(result.confidence, 0.8)
        self.assertIsNotNone(result.evidence)

    @patch("httpx.Client.request")
    def test_test_payload_command_injection_detection(self, mock_request):
        """Test command injection vulnerability detection."""
        # Mock response with command output
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "root:x:0:0:root:/root:/bin/bash"
        mock_response.content = b"root:x:0:0:root:/root:/bin/bash"
        mock_response.headers = {"content-type": "text/html"}
        mock_request.return_value = mock_response

        result = self.fuzzer._test_payload(
            "http://example.com/test", "GET", "cat /etc/passwd", "command_injection"
        )

        self.assertTrue(result.is_vulnerable)
        self.assertEqual(result.vulnerability_type, "Command Injection")
        self.assertGreater(result.confidence, 0.8)
        self.assertIsNotNone(result.evidence)

    @patch("httpx.Client.request")
    def test_test_payload_error_handling(self, mock_request):
        """Test error handling in payload testing."""
        # Mock request failure
        mock_request.side_effect = Exception("Connection error")

        result = self.fuzzer._test_payload("http://example.com/test", "GET", "test payload", "xss")

        self.assertIsInstance(result, FuzzResult)
        self.assertEqual(result.status_code, 0)
        self.assertFalse(result.is_vulnerable)
        self.assertIsNotNone(result.evidence)
        self.assertIn("Request failed", result.evidence)

    def test_detect_xss(self):
        """Test XSS detection logic."""
        # Test payload reflection
        is_vuln, vuln_type, confidence, evidence = self.fuzzer._detect_xss(
            "Found: <script>alert('XSS')</script>", "<script>alert('XSS')</script>"
        )
        self.assertTrue(is_vuln)
        self.assertEqual(vuln_type, "XSS")
        self.assertGreaterEqual(confidence, 0.6)  # Changed to >=

        # Test XSS indicators
        is_vuln, vuln_type, confidence, evidence = self.fuzzer._detect_xss(
            "javascript:alert('XSS')", "test"
        )
        self.assertTrue(is_vuln)
        self.assertEqual(vuln_type, "XSS")

        # Test no vulnerability
        is_vuln, vuln_type, confidence, evidence = self.fuzzer._detect_xss(
            "Normal response", "test"
        )
        self.assertFalse(is_vuln)

    def test_detect_sqli(self):
        """Test SQL injection detection logic."""
        # Test SQL error
        is_vuln, vuln_type, confidence, evidence = self.fuzzer._detect_sqli(
            "sql syntax error in your query", "test"
        )
        self.assertTrue(is_vuln)
        self.assertEqual(vuln_type, "SQL Injection")
        self.assertGreater(confidence, 0.8)

        # Test payload reflection - the payload needs to be in the response exactly
        is_vuln, vuln_type, confidence, evidence = self.fuzzer._detect_sqli(
            "found: 1 or 1=1",  # lowercase response text
            "1 OR 1=1",
        )
        self.assertTrue(is_vuln)
        self.assertEqual(vuln_type, "SQL Injection")

        # Test no vulnerability
        is_vuln, vuln_type, confidence, evidence = self.fuzzer._detect_sqli(
            "Normal response", "test"
        )
        self.assertFalse(is_vuln)

    def test_get_vulnerabilities(self):
        """Test vulnerability filtering."""
        # Create test results
        vuln_result = FuzzResult(
            url="http://example.com",
            method="GET",
            payload="test",
            payload_type="xss",
            status_code=200,
            response_time=0.1,
            response_size=100,
            response_headers={},
            response_body="",
            is_vulnerable=True,
            vulnerability_type="XSS",
            confidence=0.8,
            evidence="test",
        )

        normal_result = FuzzResult(
            url="http://example.com",
            method="GET",
            payload="test",
            payload_type="xss",
            status_code=200,
            response_time=0.1,
            response_size=100,
            response_headers={},
            response_body="",
            is_vulnerable=False,
            vulnerability_type=None,
            confidence=0.0,
            evidence=None,
        )

        self.fuzzer.results = [vuln_result, normal_result]
        vulnerabilities = self.fuzzer.get_vulnerabilities()

        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0].vulnerability_type, "XSS")

    def test_get_results_summary(self):
        """Test results summary generation."""
        # Create test results
        self.fuzzer.results = [
            FuzzResult(
                url="http://example.com",
                method="GET",
                payload="test",
                payload_type="xss",
                status_code=200,
                response_time=0.1,
                response_size=100,
                response_headers={},
                response_body="",
                is_vulnerable=True,
                vulnerability_type="XSS",
                confidence=0.8,
                evidence="test",
            )
        ]

        summary = self.fuzzer.get_results_summary()

        self.assertEqual(summary["total_tests"], 1)
        self.assertEqual(summary["vulnerabilities_found"], 1)
        self.assertIn("XSS", summary["vulnerability_types"])
        self.assertIn("xss", summary["payload_types_tested"])

    def test_export_results(self):
        """Test results export functionality."""
        # Create test result
        test_result = FuzzResult(
            url="http://example.com",
            method="GET",
            payload="test",
            payload_type="xss",
            status_code=200,
            response_time=0.1,
            response_size=100,
            response_headers={},
            response_body="",
            is_vulnerable=False,
            vulnerability_type=None,
            confidence=0.0,
            evidence=None,
        )

        self.fuzzer.results = [test_result]

        # Test JSON export
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            temp_file = f.name

        try:
            self.fuzzer.export_results(temp_file, "json")
            self.assertTrue(os.path.exists(temp_file))

            # Verify JSON content
            with open(temp_file, "r") as f:
                data = json.load(f)
                self.assertEqual(len(data), 1)
                self.assertEqual(data[0]["url"], "http://example.com")
        finally:
            os.unlink(temp_file)


class TestPayloadMutator(unittest.TestCase):
    """Test the payload mutator."""

    def setUp(self):
        """Set up test fixtures."""
        self.mutator = PayloadMutator()

    def test_mutator_initialization(self):
        """Test that PayloadMutator initializes correctly."""
        self.assertIsNotNone(self.mutator.encoding_methods)
        self.assertIsNotNone(self.mutator.case_variations)
        self.assertGreater(len(self.mutator.encoding_methods), 0)
        self.assertGreater(len(self.mutator.case_variations), 0)

    def test_mutate_payload_random(self):
        """Test random payload mutations."""
        payload = "test"
        mutations = self.mutator.mutate_payload(payload, "random")

        self.assertIsInstance(mutations, list)
        self.assertIn(payload, mutations)  # Original should be included
        self.assertGreaterEqual(len(mutations), 1)

    def test_mutate_payload_encoding(self):
        """Test encoding mutations."""
        payload = "test<script>"
        mutations = self.mutator.mutate_payload(payload, "encoding")

        self.assertIsInstance(mutations, list)
        self.assertIn(payload, mutations)

        # Check for URL encoding
        url_encoded = self.mutator._url_encode(payload)
        self.assertIn(url_encoded, mutations)

    def test_mutate_payload_case(self):
        """Test case mutations."""
        payload = "test"
        mutations = self.mutator.mutate_payload(payload, "case")

        self.assertIsInstance(mutations, list)
        self.assertIn(payload, mutations)

        # Check for case variations
        upper_mutation = payload.upper()
        if upper_mutation != payload:
            self.assertIn(upper_mutation, mutations)

    def test_encoding_methods(self):
        """Test individual encoding methods."""
        payload = "test<script>"

        # Test URL encoding
        url_encoded = self.mutator._url_encode(payload)
        self.assertNotEqual(url_encoded, payload)
        self.assertIn("%3C", url_encoded)  # < should be encoded as %3C (uppercase)

        # Test HTML encoding
        html_encoded = self.mutator._html_encode(payload)
        self.assertNotEqual(html_encoded, payload)
        self.assertIn("&amp;lt;", html_encoded)  # < should be encoded as &amp;lt;

        # Test double URL encoding
        double_encoded = self.mutator._double_url_encode(payload)
        self.assertNotEqual(double_encoded, payload)
        self.assertNotEqual(double_encoded, url_encoded)

    def test_generate_sql_injection_payloads(self):
        """Test SQL injection payload generation."""
        base_payload = "1 OR 1=1"
        variations = self.mutator.generate_sql_injection_payloads(base_payload)

        self.assertIsInstance(variations, list)
        self.assertIn(base_payload, variations)
        self.assertGreater(len(variations), 1)

        # Check for common SQL patterns
        sql_patterns = ["'1 OR 1=1'", "1 OR 1=1--", "1 OR 1=1#"]
        for pattern in sql_patterns:
            if pattern in variations:
                break
        else:
            self.fail("Expected SQL injection patterns not found")

    def test_generate_xss_payloads(self):
        """Test XSS payload generation."""
        base_payload = "alert('XSS')"
        variations = self.mutator.generate_xss_payloads(base_payload)

        self.assertIsInstance(variations, list)
        self.assertIn(base_payload, variations)
        self.assertGreater(len(variations), 1)

        # Check for common XSS patterns
        xss_patterns = ["<script>alert('XSS')</script>", "javascript:alert('XSS')"]
        for pattern in xss_patterns:
            if pattern in variations:
                break
        else:
            self.fail("Expected XSS patterns not found")

    def test_smart_mutate(self):
        """Test smart mutation based on payload type."""
        # Test SQL injection
        sql_payload = "1 OR 1=1"
        sql_mutations = self.mutator.smart_mutate(sql_payload, "sqli")
        self.assertGreater(len(sql_mutations), 1)

        # Test XSS
        xss_payload = "alert('XSS')"
        xss_mutations = self.mutator.smart_mutate(xss_payload, "xss")
        self.assertGreater(len(xss_mutations), 1)

        # Test unknown type
        unknown_payload = "test"
        unknown_mutations = self.mutator.smart_mutate(unknown_payload, "unknown")
        self.assertGreater(len(unknown_mutations), 1)

    def test_create_custom_payload(self):
        """Test custom payload creation."""
        template = "alert('{message}')"
        custom = self.mutator.create_custom_payload(template, message="test")
        self.assertEqual(custom, "alert('test')")

        # Test with missing variable
        custom = self.mutator.create_custom_payload(template)
        self.assertEqual(custom, template)

    def test_generate_payload_combinations(self):
        """Test payload combination generation."""
        payloads = ["test1", "test2", "test3"]
        combinations = self.mutator.generate_payload_combinations(payloads, max_combinations=5)

        self.assertIsInstance(combinations, list)
        self.assertGreater(len(combinations), 0)
        self.assertLessEqual(len(combinations), 5)


class TestAnomalyDetector(unittest.TestCase):
    """Test the anomaly detector."""

    def setUp(self):
        """Set up test fixtures."""
        self.detector = AnomalyDetector()

    def test_detector_initialization(self):
        """Test that AnomalyDetector initializes correctly."""
        self.assertIsNotNone(self.detector.baseline_stats)
        self.assertIsNotNone(self.detector.response_patterns)
        self.assertIn("error_patterns", self.detector.response_patterns)
        self.assertIn("size_thresholds", self.detector.response_patterns)
        self.assertIn("status_codes", self.detector.response_patterns)

    def test_detect_error_patterns(self):
        """Test error pattern detection."""
        # Test SQL error - use exact pattern from detector
        sql_error_text = "syntax error in your SQL query"
        anomalies = self.detector._detect_error_patterns(sql_error_text)

        self.assertIsInstance(anomalies, list)
        self.assertGreater(len(anomalies), 0)

        sql_anomaly = next((a for a in anomalies if "sql" in a.anomaly_type), None)
        self.assertIsNotNone(sql_anomaly)
        self.assertTrue(sql_anomaly.is_anomaly)
        self.assertGreater(sql_anomaly.confidence, 0.8)

        # Test XSS indicator
        xss_text = "Found: <script>alert('XSS')</script>"
        anomalies = self.detector._detect_error_patterns(xss_text)

        xss_anomaly = next((a for a in anomalies if "xss" in a.anomaly_type), None)
        self.assertIsNotNone(xss_anomaly)
        self.assertTrue(xss_anomaly.is_anomaly)

        # Test normal response
        normal_text = "Normal response without errors"
        anomalies = self.detector._detect_error_patterns(normal_text)
        self.assertEqual(len(anomalies), 0)

    def test_detect_size_anomalies(self):
        """Test size anomaly detection."""
        # Test very small response
        anomalies = self.detector._detect_size_anomalies(50, None)
        self.assertGreater(len(anomalies), 0)

        # Test very large response
        anomalies = self.detector._detect_size_anomalies(60000, None)
        self.assertGreater(len(anomalies), 0)

        # Test normal size
        anomalies = self.detector._detect_size_anomalies(1000, None)
        self.assertEqual(len(anomalies), 0)

        # Test with baseline comparison
        baseline = {"response_size": 1000}
        anomalies = self.detector._detect_size_anomalies(6000, baseline)
        self.assertGreater(len(anomalies), 0)

    def test_detect_status_anomalies(self):
        """Test status code anomaly detection."""
        # Test error status code
        anomalies = self.detector._detect_status_anomalies(500, None)
        self.assertGreater(len(anomalies), 0)

        # Test normal status code
        anomalies = self.detector._detect_status_anomalies(200, None)
        self.assertEqual(len(anomalies), 0)

        # Test with baseline comparison
        baseline = {"status_code": 200}
        anomalies = self.detector._detect_status_anomalies(500, baseline)
        self.assertGreater(len(anomalies), 0)

    def test_detect_content_anomalies(self):
        """Test content anomaly detection."""
        # Test empty response
        anomalies = self.detector._detect_content_anomalies("", None)
        self.assertGreater(len(anomalies), 0)

        # Test debug information
        debug_text = "Debug: stack trace at line 42"
        anomalies = self.detector._detect_content_anomalies(debug_text, None)
        self.assertGreater(len(anomalies), 0)

        # Test normal content
        normal_text = "Normal response content"
        anomalies = self.detector._detect_content_anomalies(normal_text, None)
        self.assertEqual(len(anomalies), 0)

    def test_analyze_response_set(self):
        """Test response set analysis."""
        responses = [
            {
                "status_code": 200,
                "response_size": 1000,
                "response_time": 0.1,
                "response_body": "Normal response",
            },
            {
                "status_code": 500,
                "response_size": 2000,
                "response_time": 0.5,
                "response_body": "Error response",
            },
        ]

        analysis = self.detector.analyze_response_set(responses)

        self.assertIsInstance(analysis, dict)
        self.assertEqual(analysis["total_responses"], 2)
        self.assertIn("status_code_stats", analysis)
        self.assertIn("size_stats", analysis)
        self.assertIn("timing_stats", analysis)

    def test_get_risk_score(self):
        """Test risk score calculation."""
        # Test with no anomalies
        anomalies = []
        score = self.detector.get_risk_score(anomalies)
        self.assertEqual(score, 0.0)

        # Test with low severity anomalies
        anomalies = [AnomalyResult(True, "test", 0.5, "test", "low")]
        score = self.detector.get_risk_score(anomalies)
        self.assertGreater(score, 0.0)
        self.assertLessEqual(score, 1.0)

        # Test with high severity anomalies
        anomalies = [AnomalyResult(True, "test", 0.9, "test", "critical")]
        score = self.detector.get_risk_score(anomalies)
        self.assertGreater(score, 0.8)


if __name__ == "__main__":
    # Set up logging for tests
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Run the tests
    unittest.main(verbosity=2)
