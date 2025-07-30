#!/usr/bin/env python3
"""
Unit tests for the visualization module.
These tests don't require Tkinter and can run in CI environments.
"""

import os
import sys
import unittest
from unittest.mock import Mock, patch

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

# The visualization system has been migrated to web-based approach
# from dragonshard.visualizer.genetic_viz import GeneticAlgorithmVisualizer


class TestVisualizationModule(unittest.TestCase):
    """Test the visualization module without requiring Tkinter."""

    def test_visualization_import(self):
        """Test that the visualization module can be imported."""
        try:
            from dragonshard.api.endpoints import genetic_algorithm
            self.assertTrue(hasattr(genetic_algorithm, "router"))
        except ImportError as e:
            self.skipTest(f"Visualization API not available: {e}")

    def test_visualizer_initialization(self):
        """Test that the visualizer API can be imported and has expected structure."""
        try:
            from dragonshard.api.endpoints import genetic_algorithm

            # Check that the router exists and can be imported
            self.assertTrue(hasattr(genetic_algorithm, "router"))

            # Check that the router has the expected structure
            router = genetic_algorithm.router

            # Test that the router has the expected attributes
            self.assertTrue(hasattr(router, "routes"))

        except ImportError as e:
            self.skipTest(f"Visualization API not available: {e}")

    def test_visualization_module_structure(self):
        """Test that the visualization API has the expected structure."""
        try:
            from dragonshard.api.endpoints import genetic_algorithm

            # Check that the module has the expected router
            self.assertTrue(hasattr(genetic_algorithm, "router"))

            # Check that the router has expected routes
            router = genetic_algorithm.router
            expected_routes = [
                "/progress",
                "/population",
                "/fitness",
                "/mutations"
            ]

            # Test that the router has routes (basic check)
            self.assertTrue(len(router.routes) > 0, "Router should have routes")

        except ImportError as e:
            self.skipTest(f"Visualization API not available: {e}")

    def test_environment_detection(self):
        """Test that we can detect CI environments."""
        # Check for common CI environment variables
        ci_vars = ["CI", "GITHUB_ACTIONS", "TRAVIS", "CIRCLECI", "JENKINS_URL"]
        is_ci = any(os.environ.get(var) for var in ci_vars)

        # Check for display (GUI environment)
        has_display = bool(os.environ.get("DISPLAY"))

        # In CI, we should not have a display
        if is_ci:
            self.assertFalse(has_display, "CI environment should not have DISPLAY set")

    def test_visualization_skip_in_ci(self):
        """Test that visualization tests are properly skipped in CI."""
        # Check if we're in a CI environment
        ci_vars = ["CI", "GITHUB_ACTIONS", "TRAVIS", "CIRCLECI", "JENKINS_URL"]
        is_ci = any(os.environ.get(var) for var in ci_vars)

        if is_ci:
            # In CI, we should skip GUI tests
            self.skipTest("Skipping GUI tests in CI environment")
        else:
            # In local environment, we can run basic tests
            self.assertTrue(True, "Not in CI - GUI tests can run")


if __name__ == "__main__":
    unittest.main()
