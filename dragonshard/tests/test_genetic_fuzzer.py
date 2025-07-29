#!/usr/bin/env python3
"""
Manual test runner for the genetic fuzzer with vulnerable containers.
This script can be run manually to test the genetic fuzzer against the vulnerable containers.
"""

import logging
import os
import sys
import time
from typing import Any, Dict, List

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
)

# Set up logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class GeneticFuzzerTester:
    """Manual test runner for the genetic fuzzer with vulnerable containers."""

    def __init__(self):
        """Initialize the tester."""
        self.response_analyzer = ResponseAnalyzer()
        self.fuzzer = Fuzzer(timeout=10, delay=0.1)
        self.anomaly_detector = AnomalyDetector()

        # Test targets
        self.targets = {
            "dvwa": "http://localhost:8080",
            "juice-shop": "http://localhost:3000",
            "webgoat": "http://localhost:8081",
            "vuln-php": "http://localhost:8082",
            "vuln-node": "http://localhost:8083",
            "vuln-python": "http://localhost:8084",
        }

    def test_target_availability(self) -> Dict[str, bool]:
        """Test if all targets are available."""
        results = {}

        for name, url in self.targets.items():
            try:
                response = requests.get(url, timeout=5)
                results[name] = response.status_code == 200
                logger.info(f"✓ {name}: {url} - Available")
            except Exception as e:
                results[name] = False
                logger.warning(f"✗ {name}: {url} - Not available: {e}")

        return results

    def set_baseline_responses(self) -> None:
        """Set baseline responses for all targets."""
        for name, url in self.targets.items():
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
            except Exception as e:
                logger.warning(f"Could not set baseline for {name}: {e}")

    def test_sql_injection_fuzzing(self, target_url: str) -> List[GeneticPayload]:
        """Test SQL injection fuzzing."""
        logger.info(f"Testing SQL injection fuzzing against {target_url}")

        # Initialize genetic mutator for SQL injection
        mutator = GeneticMutator(
            population_size=20,
            mutation_rate=0.2,
            crossover_rate=0.8,
            max_generations=10,
            response_analyzer=self.response_analyzer,
            target_url=target_url,
        )

        # Base SQL injection payloads
        base_payloads = [
            "1' OR '1'='1",
            "1' UNION SELECT 1,2,3--",
            "admin'--",
            "1' AND 1=1--",
            "1' OR 1=1#",
        ]

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

        logger.info(f"SQL injection evolution completed. Found {len(best_payloads)} payloads.")
        for i, payload in enumerate(best_payloads[:5]):
            logger.info(f"  {i + 1}. {payload.payload} (score: {payload.differential_score:.3f})")

        return best_payloads

    def test_xss_fuzzing(self, target_url: str) -> List[GeneticPayload]:
        """Test XSS fuzzing."""
        logger.info(f"Testing XSS fuzzing against {target_url}")

        # Initialize genetic mutator for XSS
        mutator = GeneticMutator(
            population_size=20,
            mutation_rate=0.2,
            crossover_rate=0.8,
            max_generations=10,
            response_analyzer=self.response_analyzer,
            target_url=target_url,
        )

        # Base XSS payloads
        base_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
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

        logger.info(f"XSS evolution completed. Found {len(best_payloads)} payloads.")
        for i, payload in enumerate(best_payloads[:5]):
            logger.info(f"  {i + 1}. {payload.payload} (score: {payload.differential_score:.3f})")

        return best_payloads

    def test_command_injection_fuzzing(self, target_url: str) -> List[GeneticPayload]:
        """Test command injection fuzzing."""
        logger.info(f"Testing command injection fuzzing against {target_url}")

        # Initialize genetic mutator for command injection
        mutator = GeneticMutator(
            population_size=20,
            mutation_rate=0.2,
            crossover_rate=0.8,
            max_generations=10,
            response_analyzer=self.response_analyzer,
            target_url=target_url,
        )

        # Base command injection payloads
        base_payloads = [
            "127.0.0.1; ls",
            "127.0.0.1 && whoami",
            "127.0.0.1 | cat /etc/passwd",
            "127.0.0.1; id",
            "127.0.0.1 && pwd",
        ]

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

        logger.info(f"Command injection evolution completed. Found {len(best_payloads)} payloads.")
        for i, payload in enumerate(best_payloads[:5]):
            logger.info(f"  {i + 1}. {payload.payload} (score: {payload.differential_score:.3f})")

        return best_payloads

    def run_comprehensive_test(self) -> Dict[str, Any]:
        """Run comprehensive testing against all targets."""
        logger.info("Starting comprehensive genetic fuzzer test")

        # Test target availability
        availability = self.test_target_availability()
        available_targets = {k: v for k, v in availability.items() if v}

        if not available_targets:
            logger.error("No targets available. Please start the containers first.")
            return {"error": "No targets available"}

        logger.info(f"Available targets: {list(available_targets.keys())}")

        # Set baseline responses
        self.set_baseline_responses()

        results = {}

        # Test each available target
        for target_name, target_url in self.targets.items():
            if not availability.get(target_name, False):
                continue

            logger.info(f"\n{'=' * 50}")
            logger.info(f"Testing {target_name}")
            logger.info(f"{'=' * 50}")

            target_results = {}

            # Test SQL injection
            try:
                sql_results = self.test_sql_injection_fuzzing(target_url)
                target_results["sql_injection"] = {
                    "payloads": [p.payload for p in sql_results[:3]],
                    "scores": [p.differential_score for p in sql_results[:3]],
                }
            except Exception as e:
                logger.error(f"SQL injection test failed for {target_name}: {e}")
                target_results["sql_injection"] = {"error": str(e)}

            # Test XSS
            try:
                xss_results = self.test_xss_fuzzing(target_url)
                target_results["xss"] = {
                    "payloads": [p.payload for p in xss_results[:3]],
                    "scores": [p.differential_score for p in xss_results[:3]],
                }
            except Exception as e:
                logger.error(f"XSS test failed for {target_name}: {e}")
                target_results["xss"] = {"error": str(e)}

            # Test command injection
            try:
                cmd_results = self.test_command_injection_fuzzing(target_url)
                target_results["command_injection"] = {
                    "payloads": [p.payload for p in cmd_results[:3]],
                    "scores": [p.differential_score for p in cmd_results[:3]],
                }
            except Exception as e:
                logger.error(f"Command injection test failed for {target_name}: {e}")
                target_results["command_injection"] = {"error": str(e)}

            results[target_name] = target_results

        return results


def main():
    """Main function to run the genetic fuzzer test."""
    print("🧬 Genetic Fuzzer Test with Vulnerable Containers")
    print("=" * 60)

    tester = GeneticFuzzerTester()

    try:
        results = tester.run_comprehensive_test()

        print("\n📊 Test Results Summary")
        print("=" * 60)

        for target_name, target_results in results.items():
            print(f"\n🎯 {target_name.upper()}")
            print("-" * 30)

            for vuln_type, vuln_results in target_results.items():
                if "error" in vuln_results:
                    print(f"  ❌ {vuln_type}: {vuln_results['error']}")
                else:
                    payloads = vuln_results["payloads"]
                    scores = vuln_results["scores"]
                    print(f"  ✅ {vuln_type}:")
                    for i, (payload, score) in enumerate(zip(payloads, scores)):
                        print(f"    {i + 1}. {payload[:50]}... (score: {score:.3f})")

        print("\n🎉 Test completed successfully!")

    except KeyboardInterrupt:
        print("\n⚠️  Test interrupted by user")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        logger.exception("Test failed")


if __name__ == "__main__":
    main()
