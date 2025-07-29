#!/usr/bin/env python3
"""
Integration tests for the genetic fuzzer with vulnerable containers.
This module tests the genetic mutator with response analysis against real vulnerable applications.
"""

import logging
import os
import sys
import time
import unittest
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import requests

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from dragonshard.fuzzing import (
    AnomalyDetector,
    Fuzzer,
    GeneticMutator,
    GeneticPayload,
    PayloadType,
    ResponseAnalysis,
    ResponseAnalyzer,
    ResponseType,
)

# Set up logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class TestGeneticFuzzerIntegration(unittest.TestCase):
    """Integration tests for the genetic fuzzer with vulnerable containers."""

    @classmethod
    def setUpClass(cls):
        """Set up test class with target URLs."""
        cls.targets = {
            "dvwa": "http://localhost:8080",
            "juice-shop": "http://localhost:3000",
            "webgoat": "http://localhost:8081",
            "vuln-php": "http://localhost:8082",
            "vuln-node": "http://localhost:8083",
            "vuln-python": "http://localhost:8084",
        }

        cls.response_analyzer = ResponseAnalyzer()
        cls.fuzzer = Fuzzer(timeout=10, delay=0.1)
        cls.anomaly_detector = AnomalyDetector()

    def setUp(self):
        """Set up each test."""
        self.mutator = GeneticMutator(
            population_size=10,  # Smaller for faster tests
            mutation_rate=0.2,
            crossover_rate=0.8,
            max_generations=5,  # Fewer generations for faster tests
            response_analyzer=self.response_analyzer,
        )

    def test_target_availability(self):
        """Test if vulnerable containers are available."""
        available_targets = {}

        for name, url in self.targets.items():
            try:
                response = requests.get(url, timeout=5)
                available_targets[name] = response.status_code == 200
                logger.info(f"✓ {name}: {url} - Available")
            except Exception as e:
                available_targets[name] = False
                logger.warning(f"✗ {name}: {url} - Not available: {e}")

        # At least one target should be available for integration tests
        self.assertTrue(
            any(available_targets.values()),
            "No vulnerable containers available. Start containers with: docker-compose -f ../../docker-compose.test.yml up -d",
        )

        # Store available targets for other tests
        self.available_targets = {k: v for k, v in available_targets.items() if v}
        logger.info(f"Available targets: {list(self.available_targets.keys())}")

    def test_baseline_response_setting(self):
        """Test setting baseline responses for available targets."""
        if not hasattr(self, "available_targets"):
            self.test_target_availability()

        for name, url in self.targets.items():
            if not self.available_targets.get(name, False):
                continue

            try:
                response = requests.get(url, timeout=5)
                baseline = self.response_analyzer.analyze_response(
                    status_code=response.status_code,
                    response_time=response.elapsed.total_seconds(),
                    content=response.text,
                    headers=dict(response.headers),
                    url=url,
                )
                self.response_analyzer.set_baseline(url, baseline)
                logger.info(f"Set baseline for {name}")

                # Verify baseline was set
                self.assertIn(url, self.response_analyzer.baseline_responses)

            except Exception as e:
                logger.warning(f"Could not set baseline for {name}: {e}")

    def test_sql_injection_fuzzing(self):
        """Test SQL injection fuzzing against vulnerable containers."""
        if not hasattr(self, "available_targets"):
            self.test_target_availability()

        # Test against PHP app if available
        target_url = self.targets.get("vuln-php")
        if not target_url or not self.available_targets.get("vuln-php", False):
            self.skipTest("vuln-php container not available")

        logger.info(f"Testing SQL injection fuzzing against {target_url}")

        # Initialize genetic mutator for SQL injection
        mutator = GeneticMutator(
            population_size=10,
            mutation_rate=0.2,
            crossover_rate=0.8,
            max_generations=3,  # Fewer generations for faster tests
            response_analyzer=self.response_analyzer,
            target_url=target_url,
        )

        # Base SQL injection payloads
        base_payloads = ["1' OR '1'='1", "1' UNION SELECT 1,2,3--", "admin'--"]

        # Initialize population
        mutator.initialize_population(base_payloads, PayloadType.SQL_INJECTION)

        # Create response-based fitness function
        def fitness_function(payload: GeneticPayload) -> float:
            try:
                # Test the payload
                test_url = f"{target_url}/search"
                data = {"search": payload.payload}

                response = requests.post(test_url, data=data, timeout=5)

                # Analyze response
                analysis = self.response_analyzer.analyze_response(
                    status_code=response.status_code,
                    response_time=response.elapsed.total_seconds(),
                    content=response.text,
                    headers=dict(response.headers),
                    url=test_url,
                )

                # Update payload with response
                baseline = self.response_analyzer.baseline_responses.get(target_url)
                mutator.update_payload_with_response(payload, analysis, baseline)

                return payload.differential_score

            except Exception as e:
                logger.warning(f"Error testing payload {payload.payload}: {e}")
                return 0.0

        # Evolve the population
        best_payloads = mutator.evolve(fitness_function)

        # Verify we got some results
        self.assertGreater(len(best_payloads), 0)

        # Check that payloads have differential scores
        for payload in best_payloads[:3]:
            self.assertIsInstance(payload.differential_score, float)
            self.assertGreaterEqual(payload.differential_score, 0.0)
            self.assertLessEqual(payload.differential_score, 1.0)

        logger.info(f"SQL injection evolution completed. Found {len(best_payloads)} payloads.")
        for i, payload in enumerate(best_payloads[:3]):
            logger.info(f"  {i + 1}. {payload.payload} (score: {payload.differential_score:.3f})")

    def test_xss_fuzzing(self):
        """Test XSS fuzzing against vulnerable containers."""
        if not hasattr(self, "available_targets"):
            self.test_target_availability()

        # Test against PHP app if available
        target_url = self.targets.get("vuln-php")
        if not target_url or not self.available_targets.get("vuln-php", False):
            self.skipTest("vuln-php container not available")

        logger.info(f"Testing XSS fuzzing against {target_url}")

        # Initialize genetic mutator for XSS
        mutator = GeneticMutator(
            population_size=10,
            mutation_rate=0.2,
            crossover_rate=0.8,
            max_generations=3,
            response_analyzer=self.response_analyzer,
            target_url=target_url,
        )

        # Base XSS payloads
        base_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
        ]

        # Initialize population
        mutator.initialize_population(base_payloads, PayloadType.XSS)

        # Create response-based fitness function
        def fitness_function(payload: GeneticPayload) -> float:
            try:
                # Test the payload
                test_url = f"{target_url}/?input={payload.payload}"

                response = requests.get(test_url, timeout=5)

                # Analyze response
                analysis = self.response_analyzer.analyze_response(
                    status_code=response.status_code,
                    response_time=response.elapsed.total_seconds(),
                    content=response.text,
                    headers=dict(response.headers),
                    url=test_url,
                )

                # Update payload with response
                baseline = self.response_analyzer.baseline_responses.get(target_url)
                mutator.update_payload_with_response(payload, analysis, baseline)

                return payload.differential_score

            except Exception as e:
                logger.warning(f"Error testing payload {payload.payload}: {e}")
                return 0.0

        # Evolve the population
        best_payloads = mutator.evolve(fitness_function)

        # Verify we got some results
        self.assertGreater(len(best_payloads), 0)

        # Check that payloads have differential scores
        for payload in best_payloads[:3]:
            self.assertIsInstance(payload.differential_score, float)
            self.assertGreaterEqual(payload.differential_score, 0.0)
            self.assertLessEqual(payload.differential_score, 1.0)

        logger.info(f"XSS evolution completed. Found {len(best_payloads)} payloads.")
        for i, payload in enumerate(best_payloads[:3]):
            logger.info(f"  {i + 1}. {payload.payload} (score: {payload.differential_score:.3f})")

    def test_command_injection_fuzzing(self):
        """Test command injection fuzzing against vulnerable containers."""
        if not hasattr(self, "available_targets"):
            self.test_target_availability()

        # Test against Node.js app if available
        target_url = self.targets.get("vuln-node")
        if not target_url or not self.available_targets.get("vuln-node", False):
            self.skipTest("vuln-node container not available")

        logger.info(f"Testing command injection fuzzing against {target_url}")

        # Initialize genetic mutator for command injection
        mutator = GeneticMutator(
            population_size=10,
            mutation_rate=0.2,
            crossover_rate=0.8,
            max_generations=3,
            response_analyzer=self.response_analyzer,
            target_url=target_url,
        )

        # Base command injection payloads
        base_payloads = ["127.0.0.1; ls", "127.0.0.1 && whoami", "127.0.0.1 | cat /etc/passwd"]

        # Initialize population
        mutator.initialize_population(base_payloads, PayloadType.COMMAND_INJECTION)

        # Create response-based fitness function
        def fitness_function(payload: GeneticPayload) -> float:
            try:
                # Test the payload
                test_url = f"{target_url}/command"
                data = {"command": payload.payload}

                response = requests.post(test_url, data=data, timeout=5)

                # Analyze response
                analysis = self.response_analyzer.analyze_response(
                    status_code=response.status_code,
                    response_time=response.elapsed.total_seconds(),
                    content=response.text,
                    headers=dict(response.headers),
                    url=test_url,
                )

                # Update payload with response
                baseline = self.response_analyzer.baseline_responses.get(target_url)
                mutator.update_payload_with_response(payload, analysis, baseline)

                return payload.differential_score

            except Exception as e:
                logger.warning(f"Error testing payload {payload.payload}: {e}")
                return 0.0

        # Evolve the population
        best_payloads = mutator.evolve(fitness_function)

        # Verify we got some results
        self.assertGreater(len(best_payloads), 0)

        # Check that payloads have differential scores
        for payload in best_payloads[:3]:
            self.assertIsInstance(payload.differential_score, float)
            self.assertGreaterEqual(payload.differential_score, 0.0)
            self.assertLessEqual(payload.differential_score, 1.0)

        logger.info(f"Command injection evolution completed. Found {len(best_payloads)} payloads.")
        for i, payload in enumerate(best_payloads[:3]):
            logger.info(f"  {i + 1}. {payload.payload} (score: {payload.differential_score:.3f})")

    def test_response_analyzer_integration(self):
        """Test response analyzer integration with genetic mutator."""
        if not hasattr(self, "available_targets"):
            self.test_target_availability()

        # Test against any available target
        available_target = None
        for name, url in self.targets.items():
            if self.available_targets.get(name, False):
                available_target = url
                break

        if not available_target:
            self.skipTest("No vulnerable containers available")

        # Test baseline setting
        response = requests.get(available_target, timeout=5)
        baseline = self.response_analyzer.analyze_response(
            status_code=response.status_code,
            response_time=response.elapsed.total_seconds(),
            content=response.text,
            headers=dict(response.headers),
            url=available_target,
        )

        self.response_analyzer.set_baseline(available_target, baseline)
        self.assertIn(available_target, self.response_analyzer.baseline_responses)

        # Test response comparison
        test_response = requests.get(available_target, timeout=5)
        test_analysis = self.response_analyzer.analyze_response(
            status_code=test_response.status_code,
            response_time=test_response.elapsed.total_seconds(),
            content=test_response.text,
            headers=dict(test_response.headers),
            url=available_target,
        )

        differential = self.response_analyzer.compare_responses(baseline, test_analysis)

        self.assertIsInstance(differential.reward_score, float)
        self.assertGreaterEqual(differential.reward_score, 0.0)
        self.assertLessEqual(differential.reward_score, 1.0)

    def test_genetic_mutator_search_statistics(self):
        """Test genetic mutator search statistics and tracking."""
        mutator = GeneticMutator(
            population_size=5,
            mutation_rate=0.2,
            crossover_rate=0.8,
            max_generations=2,
            response_analyzer=self.response_analyzer,
        )

        # Initialize with test payloads
        base_payloads = ["test1", "test2", "test3"]
        mutator.initialize_population(base_payloads, PayloadType.XSS)

        # Mock fitness function
        def mock_fitness(payload: GeneticPayload) -> float:
            payload.differential_score = 0.5
            return 0.5

        # Evolve
        best_payloads = mutator.evolve(mock_fitness)

        # Get statistics
        stats = mutator.get_search_statistics()

        # Verify statistics structure
        self.assertIn("total_paths", stats)
        self.assertIn("dead_end_paths", stats)
        self.assertIn("successful_patterns", stats)
        self.assertIn("mutation_success_rates", stats)
        self.assertIn("response_statistics", stats)

        # Verify statistics are reasonable
        self.assertIsInstance(stats["total_paths"], int)
        self.assertIsInstance(stats["dead_end_paths"], int)
        self.assertIsInstance(stats["successful_patterns"], dict)
        self.assertIsInstance(stats["mutation_success_rates"], dict)
        self.assertIsInstance(stats["response_statistics"], dict)


class TestGeneticFuzzerMocked(unittest.TestCase):
    """Mocked tests for genetic fuzzer when containers are not available."""

    def setUp(self):
        """Set up mocked tests."""
        self.response_analyzer = ResponseAnalyzer()
        self.mutator = GeneticMutator(
            population_size=5,
            mutation_rate=0.2,
            crossover_rate=0.8,
            max_generations=2,
            response_analyzer=self.response_analyzer,
        )

    @patch("requests.get")
    @patch("requests.post")
    def test_mocked_sql_injection_fuzzing(self, mock_post, mock_get):
        """Test SQL injection fuzzing with mocked responses."""
        # Mock successful response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.elapsed.total_seconds.return_value = 0.1
        mock_response.text = "Normal response"
        mock_response.headers = {}
        mock_post.return_value = mock_response

        # Initialize population
        base_payloads = ["1' OR '1'='1", "admin'--"]
        self.mutator.initialize_population(base_payloads, PayloadType.SQL_INJECTION)

        # Mock fitness function
        def mock_fitness(payload: GeneticPayload) -> float:
            # Simulate some payloads getting higher scores
            if "OR" in payload.payload:
                payload.differential_score = 0.8
                return 0.8
            else:
                payload.differential_score = 0.3
                return 0.3

        # Evolve
        best_payloads = self.mutator.evolve(mock_fitness)

        # Verify results
        self.assertGreater(len(best_payloads), 0)
        self.assertIsInstance(best_payloads[0], GeneticPayload)

    def test_mocked_response_analyzer(self):
        """Test response analyzer with mocked data."""
        # Create mock baseline
        baseline = ResponseAnalysis(
            status_code=200,
            response_time=0.1,
            content_length=100,
            content_hash="abc123",
            response_type=ResponseType.NORMAL,
            anomaly_score=0.0,
            vulnerability_indicators=[],
            differential_score=0.0,
            baseline_deviation=0.0,
        )

        # Create mock test response
        test_response = ResponseAnalysis(
            status_code=500,
            response_time=0.5,
            content_length=200,
            content_hash="def456",
            response_type=ResponseType.ERROR,
            anomaly_score=0.8,
            vulnerability_indicators=["sql_injection:error"],
            differential_score=0.0,
            baseline_deviation=0.0,
        )

        # Compare responses
        differential = self.response_analyzer.compare_responses(baseline, test_response)

        # Verify differential
        self.assertIsInstance(differential.reward_score, float)
        self.assertGreater(differential.reward_score, 0.0)  # Should detect difference


if __name__ == "__main__":
    # Set up logging for tests
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Run tests
    unittest.main(verbosity=2)
