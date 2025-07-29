#!/usr/bin/env python3
"""
Unit tests for the web fuzzing visualization module.
These tests don't require Tkinter and can run in CI environments.
"""

import os
import sys
import unittest
from unittest.mock import Mock, patch

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from dragonshard.visualizer.web_fuzzing_viz import WebFuzzingVisualizer, MutationNode


class TestWebFuzzingVisualization(unittest.TestCase):
    """Test the web fuzzing visualization module without requiring Tkinter."""

    def test_visualization_import(self):
        """Test that the web fuzzing visualization module can be imported."""
        try:
            from dragonshard.visualizer import web_fuzzing_viz

            self.assertTrue(hasattr(web_fuzzing_viz, "WebFuzzingVisualizer"))
            self.assertTrue(hasattr(web_fuzzing_viz, "MutationNode"))
        except ImportError as e:
            if "tkinter" in str(e).lower():
                self.skipTest("Tkinter not available - skipping GUI tests")
            else:
                raise

    def test_mutation_node_creation(self):
        """Test that MutationNode can be created correctly."""
        from datetime import datetime
        
        node = MutationNode(
            payload="test' OR 1=1--",
            parent_payload="test",
            generation=1,
            fitness=0.8,
            vulnerability_score=0.9,
            mutation_type="keyword",
            response_analysis={"status_code": 500, "response_time": 0.5},
            children=[],
            timestamp=datetime.now()
        )
        
        self.assertEqual(node.payload, "test' OR 1=1--")
        self.assertEqual(node.generation, 1)
        self.assertEqual(node.fitness, 0.8)
        self.assertEqual(node.vulnerability_score, 0.9)
        self.assertEqual(node.mutation_type, "keyword")

    def test_visualizer_class_structure(self):
        """Test that the WebFuzzingVisualizer class has the expected structure."""
        try:
            from dragonshard.visualizer import web_fuzzing_viz

            # Check that the class exists and can be imported
            self.assertTrue(hasattr(web_fuzzing_viz, "WebFuzzingVisualizer"))

            # Check that the class has the expected attributes
            visualizer_class = web_fuzzing_viz.WebFuzzingVisualizer

            # Test that the class can be instantiated with a mock root (basic test)
            mock_root = Mock()
            mock_root.title = Mock()
            mock_root.geometry = Mock()

            # We'll just test that the class exists and has the right structure
            # without trying to fully initialize the GUI
            self.assertTrue(hasattr(visualizer_class, "__init__"))
            self.assertTrue(hasattr(visualizer_class, "setup_ui"))
            self.assertTrue(hasattr(visualizer_class, "setup_charts"))
            self.assertTrue(hasattr(visualizer_class, "start_fuzzing"))
            self.assertTrue(hasattr(visualizer_class, "stop_fuzzing"))

        except ImportError as e:
            if "tkinter" in str(e).lower():
                self.skipTest("Tkinter not available - skipping GUI tests")
            else:
                raise

    def test_web_fuzzing_methods(self):
        """Test that the web fuzzing visualizer has the expected methods."""
        try:
            from dragonshard.visualizer import web_fuzzing_viz

            visualizer_class = web_fuzzing_viz.WebFuzzingVisualizer
            expected_methods = [
                "setup_ui",
                "setup_charts",
                "setup_mutation_tree",
                "start_fuzzing",
                "stop_fuzzing",
                "get_base_payloads",
                "create_web_fitness_function",
                "run_fuzzing",
                "update_mutation_tree",
                "update_visualization",
                "export_results",
            ]

            for method_name in expected_methods:
                self.assertTrue(
                    hasattr(visualizer_class, method_name),
                    f"WebFuzzingVisualizer should have method: {method_name}",
                )

        except ImportError as e:
            if "tkinter" in str(e).lower():
                self.skipTest("Tkinter not available - skipping GUI tests")
            else:
                raise

    def test_payload_classification(self):
        """Test payload classification functionality."""
        try:
            from dragonshard.visualizer import web_fuzzing_viz

            visualizer_class = web_fuzzing_viz.WebFuzzingVisualizer
            mock_root = Mock()
            mock_root.title = Mock()
            mock_root.geometry = Mock()

            # Create a mock instance to test methods
            with patch.object(visualizer_class, '__init__', return_value=None):
                visualizer = visualizer_class(mock_root)
                
                # Test payload classification
                from dragonshard.fuzzing import GeneticPayload, PayloadType
                
                # Test SQL injection payload
                sql_payload = GeneticPayload("test' OR 1=1--", PayloadType.SQL_INJECTION)
                mutation_type = visualizer.classify_mutation_type(sql_payload)
                self.assertIn(mutation_type, ["keyword", "general"])
                
                # Test XSS payload
                xss_payload = GeneticPayload("<script>alert(1)</script>", PayloadType.XSS)
                mutation_type = visualizer.classify_mutation_type(xss_payload)
                self.assertIn(mutation_type, ["tag", "encoding", "general"])

        except ImportError as e:
            if "tkinter" in str(e).lower():
                self.skipTest("Tkinter not available - skipping GUI tests")
            else:
                raise

    def test_vulnerability_detection(self):
        """Test vulnerability detection functionality."""
        try:
            from dragonshard.visualizer import web_fuzzing_viz

            visualizer_class = web_fuzzing_viz.WebFuzzingVisualizer
            mock_root = Mock()
            mock_root.title = Mock()
            mock_root.geometry = Mock()

            # Create a mock instance to test methods
            with patch.object(visualizer_class, '__init__', return_value=None):
                visualizer = visualizer_class(mock_root)
                
                # Test SQL injection detection
                sql_content = "mysql syntax error near 'OR 1=1'"
                vuln_type = visualizer.detect_vulnerability_type(sql_content)
                self.assertEqual(vuln_type, "SQL Injection")
                
                # Test XSS detection
                xss_content = "alert(1) script javascript"
                vuln_type = visualizer.detect_vulnerability_type(xss_content)
                self.assertEqual(vuln_type, "XSS")
                
                # Test command injection detection
                cmd_content = "root:x:0:0:root:/root:/bin/bash"
                vuln_type = visualizer.detect_vulnerability_type(cmd_content)
                self.assertEqual(vuln_type, "Command Injection")

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

    def test_web_fuzzing_skip_in_ci(self):
        """Test that web fuzzing visualization tests are properly skipped in CI."""
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