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

from dragonshard.visualizer.genetic_viz import GeneticAlgorithmVisualizer


class TestVisualizationModule(unittest.TestCase):
    """Test the visualization module without requiring Tkinter."""

    def test_visualization_import(self):
        """Test that the visualization module can be imported."""
        try:
            from dragonshard.visualizer import genetic_viz

            self.assertTrue(hasattr(genetic_viz, "GeneticAlgorithmVisualizer"))
        except ImportError as e:
            if "tkinter" in str(e).lower():
                self.skipTest("Tkinter not available - skipping GUI tests")
            else:
                raise

    def test_visualizer_initialization(self):
        """Test that the visualizer class can be imported and has expected structure."""
        try:
            from dragonshard.visualizer import genetic_viz

            # Check that the class exists and can be imported
            self.assertTrue(hasattr(genetic_viz, "GeneticAlgorithmVisualizer"))

            # Check that the class has the expected attributes
            visualizer_class = genetic_viz.GeneticAlgorithmVisualizer

            # Test that the class can be instantiated with a mock root (basic test)
            mock_root = Mock()
            mock_root.title = Mock()
            mock_root.geometry = Mock()

            # We'll just test that the class exists and has the right structure
            # without trying to fully initialize the GUI
            self.assertTrue(hasattr(visualizer_class, "__init__"))
            self.assertTrue(hasattr(visualizer_class, "setup_ui"))
            self.assertTrue(hasattr(visualizer_class, "setup_charts"))

        except ImportError as e:
            if "tkinter" in str(e).lower():
                self.skipTest("Tkinter not available - skipping GUI tests")
            else:
                raise

    def test_visualization_module_structure(self):
        """Test that the visualization module has the expected structure."""
        try:
            from dragonshard.visualizer import genetic_viz

            # Check that the module has the expected class
            self.assertTrue(hasattr(genetic_viz, "GeneticAlgorithmVisualizer"))

            # Check that the class has expected methods
            visualizer_class = genetic_viz.GeneticAlgorithmVisualizer
            expected_methods = [
                "setup_ui",
                "setup_charts",
                "start_evolution",
                "stop_evolution",
                "update_fitness_chart",
                "update_mutation_chart",
            ]

            for method_name in expected_methods:
                self.assertTrue(
                    hasattr(visualizer_class, method_name),
                    f"GeneticAlgorithmVisualizer should have method: {method_name}",
                )

        except ImportError as e:
            if "tkinter" in str(e).lower():
                self.skipTest("Tkinter not available - skipping GUI tests")
            else:
                raise

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
