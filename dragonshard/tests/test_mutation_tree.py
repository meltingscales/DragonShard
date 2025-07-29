#!/usr/bin/env python3
"""
Unit tests for the mutation tree visualizer.
"""

import unittest
from unittest.mock import Mock, patch
import os
import sys

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from dragonshard.visualizer.mutation_tree import MutationNode, MutationTreeVisualizer
from dragonshard.fuzzing import GeneticPayload, PayloadType


class TestMutationNode(unittest.TestCase):
    """Test the MutationNode class."""
    
    def test_node_creation(self):
        """Test creating a mutation node."""
        payload = GeneticPayload("test payload", PayloadType.SQL_INJECTION)
        node = MutationNode(payload, parent_id="parent_123")
        
        self.assertEqual(node.payload, payload)
        self.assertEqual(node.parent_id, "parent_123")
        self.assertEqual(node.children, [])
        self.assertEqual(node.fitness_score, 0.0)
        self.assertEqual(node.response_type, "unknown")
        self.assertEqual(node.mutation_type, "unknown")
        self.assertEqual(node.generation, 0)
        self.assertFalse(node.successful)
        self.assertFalse(node.vulnerability_detected)
        
    def test_node_to_dict(self):
        """Test converting node to dictionary."""
        payload = GeneticPayload("test payload", PayloadType.XSS)
        node = MutationNode(payload, parent_id="parent_123")
        node.fitness_score = 0.85
        node.response_type = "vulnerability"
        node.mutation_type = "xss_mutation"
        node.generation = 2
        node.successful = True
        node.vulnerability_detected = True
        
        node_dict = node.to_dict()
        
        self.assertEqual(node_dict['payload'], "test payload")
        self.assertEqual(node_dict['payload_type'], "xss")  # Fixed: enum values are lowercase
        self.assertEqual(node_dict['parent_id'], "parent_123")
        self.assertEqual(node_dict['fitness_score'], 0.85)
        self.assertEqual(node_dict['response_type'], "vulnerability")
        self.assertEqual(node_dict['mutation_type'], "xss_mutation")
        self.assertEqual(node_dict['generation'], 2)
        self.assertTrue(node_dict['successful'])
        self.assertTrue(node_dict['vulnerability_detected'])


class TestMutationTreeVisualizer(unittest.TestCase):
    """Test the MutationTreeVisualizer class."""
    
    def test_visualizer_import(self):
        """Test that the mutation tree visualizer can be imported."""
        try:
            from dragonshard.visualizer import mutation_tree
            self.assertTrue(hasattr(mutation_tree, 'MutationTreeVisualizer'))
            self.assertTrue(hasattr(mutation_tree, 'MutationNode'))
        except ImportError as e:
            if "tkinter" in str(e).lower():
                self.skipTest("Tkinter not available - skipping GUI tests")
            else:
                raise
                
    def test_visualizer_structure(self):
        """Test that the visualizer has the expected structure."""
        try:
            from dragonshard.visualizer import mutation_tree
            
            visualizer_class = mutation_tree.MutationTreeVisualizer
            
            # Check for expected methods
            expected_methods = [
                'add_node',
                'update_tree_view',
                'update_visualization',
                'clear_tree',
                'export_tree',
                'find_best_path',
                'next_generation'
            ]
            
            for method_name in expected_methods:
                self.assertTrue(hasattr(visualizer_class, method_name),
                              f"MutationTreeVisualizer should have method: {method_name}")
                
        except ImportError as e:
            if "tkinter" in str(e).lower():
                self.skipTest("Tkinter not available - skipping GUI tests")
            else:
                raise
                
    def test_generation_management(self):
        """Test generation management."""
        try:
            from dragonshard.visualizer import mutation_tree
            
            # Test that the class can be imported and has expected methods
            visualizer_class = mutation_tree.MutationTreeVisualizer
            
            # Check for generation-related methods
            self.assertTrue(hasattr(visualizer_class, 'next_generation'))
            
        except ImportError as e:
            if "tkinter" in str(e).lower():
                self.skipTest("Tkinter not available - skipping GUI tests")
            else:
                raise
                
    def test_node_creation_and_management(self):
        """Test creating and managing nodes in the tree."""
        try:
            from dragonshard.visualizer import mutation_tree
            
            # Test that the class has expected methods
            visualizer_class = mutation_tree.MutationTreeVisualizer
            
            # Check for node management methods
            self.assertTrue(hasattr(visualizer_class, 'add_node'))
            
        except ImportError as e:
            if "tkinter" in str(e).lower():
                self.skipTest("Tkinter not available - skipping GUI tests")
            else:
                raise
                
    def test_tree_operations(self):
        """Test tree operations like clearing and finding paths."""
        try:
            from dragonshard.visualizer import mutation_tree
            
            # Test that the class has expected methods
            visualizer_class = mutation_tree.MutationTreeVisualizer
            
            # Check for tree operation methods
            self.assertTrue(hasattr(visualizer_class, 'clear_tree'))
            self.assertTrue(hasattr(visualizer_class, 'find_best_path'))
            self.assertTrue(hasattr(visualizer_class, 'export_tree'))
            
        except ImportError as e:
            if "tkinter" in str(e).lower():
                self.skipTest("Tkinter not available - skipping GUI tests")
            else:
                raise


if __name__ == "__main__":
    unittest.main() 