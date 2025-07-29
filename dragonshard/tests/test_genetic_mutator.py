#!/usr/bin/env python3
"""
Unit tests for the genetic mutator module.
"""

import unittest
import logging
import tempfile
import json
import os
from unittest.mock import patch, MagicMock
from typing import Dict, List, Any
import sys

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from dragonshard.fuzzing.genetic_mutator import (
    GeneticMutator, GeneticPayload, PayloadType
)


class TestGeneticPayload(unittest.TestCase):
    """Test the GeneticPayload class."""
    
    def test_payload_initialization(self):
        """Test that GeneticPayload initializes correctly."""
        payload = GeneticPayload("<script>alert(1)</script>", PayloadType.XSS)
        
        self.assertEqual(payload.payload, "<script>alert(1)</script>")
        self.assertEqual(payload.payload_type, PayloadType.XSS)
        self.assertEqual(payload.fitness, 0.0)
        self.assertEqual(payload.mutation_count, 0)
        self.assertEqual(payload.generation, 0)
        self.assertIsNotNone(payload.tokens)
        self.assertIsNotNone(payload.syntax_tree)
    
    def test_tokenization(self):
        """Test payload tokenization."""
        payload = GeneticPayload("<script>alert('XSS')</script>", PayloadType.XSS)
        
        self.assertIsInstance(payload.tokens, list)
        self.assertGreater(len(payload.tokens), 0)
        # Check that script is in tokens (might be split)
        script_found = any('script' in token for token in payload.tokens)
        self.assertTrue(script_found)
        # Check that alert is in tokens
        alert_found = any('alert' in token for token in payload.tokens)
        self.assertTrue(alert_found)
    
    def test_syntax_analysis(self):
        """Test syntax analysis."""
        payload = GeneticPayload("<script>alert(1)</script>", PayloadType.XSS)
        
        self.assertIsInstance(payload.syntax_tree, dict)
        self.assertIn("type", payload.syntax_tree)
        self.assertIn("tokens", payload.syntax_tree)
        self.assertIn("structure", payload.syntax_tree)
        self.assertIn("keywords", payload.syntax_tree)
        self.assertIn("syntax_patterns", payload.syntax_tree)
        
        self.assertEqual(payload.syntax_tree["type"], "xss")
    
    def test_structure_analysis(self):
        """Test structure analysis."""
        # XSS payload
        xss_payload = GeneticPayload("<script>alert(1)</script>", PayloadType.XSS)
        self.assertTrue(xss_payload.syntax_tree["structure"]["has_tags"])
        self.assertTrue(xss_payload.syntax_tree["structure"]["has_functions"])
        
        # SQL payload
        sql_payload = GeneticPayload("' OR 1=1--", PayloadType.SQL_INJECTION)
        self.assertTrue(sql_payload.syntax_tree["structure"]["has_quotes"])
        self.assertTrue(sql_payload.syntax_tree["structure"]["has_operators"])
        
        # Path payload
        path_payload = GeneticPayload("../../../etc/passwd", PayloadType.PATH_TRAVERSAL)
        self.assertTrue(path_payload.syntax_tree["structure"]["has_paths"])
    
    def test_keyword_extraction(self):
        """Test keyword extraction."""
        # XSS keywords
        xss_payload = GeneticPayload("<script>alert('XSS')</script>", PayloadType.XSS)
        keywords = xss_payload.syntax_tree["keywords"]
        self.assertIn("script", keywords)
        self.assertIn("alert", keywords)
        
        # SQL keywords
        sql_payload = GeneticPayload("' OR 1=1 UNION SELECT 1--", PayloadType.SQL_INJECTION)
        keywords = sql_payload.syntax_tree["keywords"]
        self.assertIn("or", keywords)
        self.assertIn("union", keywords)
        self.assertIn("select", keywords)
        
        # Command keywords
        cmd_payload = GeneticPayload("; ls -la; whoami", PayloadType.COMMAND_INJECTION)
        keywords = cmd_payload.syntax_tree["keywords"]
        self.assertIn("ls", keywords)
        self.assertIn("whoami", keywords)
    
    def test_syntax_patterns(self):
        """Test syntax pattern identification."""
        # HTML pattern
        html_payload = GeneticPayload("<script>alert(1)</script>", PayloadType.XSS)
        patterns = html_payload.syntax_tree["syntax_patterns"]
        self.assertIn("html_tag", patterns)
        
        # JavaScript pattern
        js_payload = GeneticPayload("javascript:alert(1)", PayloadType.XSS)
        patterns = js_payload.syntax_tree["syntax_patterns"]
        self.assertIn("javascript_protocol", patterns)
        
        # SQL pattern
        sql_payload = GeneticPayload("' OR 1=1", PayloadType.SQL_INJECTION)
        patterns = sql_payload.syntax_tree["syntax_patterns"]
        self.assertIn("sql_keyword", patterns)
        
        # Path pattern
        path_payload = GeneticPayload("../../../etc/passwd", PayloadType.PATH_TRAVERSAL)
        patterns = path_payload.syntax_tree["syntax_patterns"]
        self.assertIn("path_traversal", patterns)
        
        # Encoding pattern
        encoded_payload = GeneticPayload("%3Cscript%3Ealert(1)%3C/script%3E", PayloadType.XSS)
        patterns = encoded_payload.syntax_tree["syntax_patterns"]
        self.assertIn("url_encoding", patterns)


class TestGeneticMutator(unittest.TestCase):
    """Test the GeneticMutator class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mutator = GeneticMutator(population_size=10, max_generations=5)
    
    def test_mutator_initialization(self):
        """Test that GeneticMutator initializes correctly."""
        self.assertEqual(self.mutator.population_size, 10)
        self.assertEqual(self.mutator.mutation_rate, 0.1)
        self.assertEqual(self.mutator.crossover_rate, 0.8)
        self.assertEqual(self.mutator.max_generations, 5)
        self.assertEqual(self.mutator.generation, 0)
        self.assertIsInstance(self.mutator.population, list)
        self.assertIsInstance(self.mutator.best_payloads, list)
        self.assertIsNotNone(self.mutator.mutation_operators)
        self.assertIsNotNone(self.mutator.syntax_patterns)
    
    def test_syntax_patterns_loading(self):
        """Test that syntax patterns are loaded correctly."""
        patterns = self.mutator.syntax_patterns
        
        # Check XSS patterns
        self.assertIn(PayloadType.XSS, patterns)
        xss_patterns = patterns[PayloadType.XSS]
        self.assertIn("tags", xss_patterns)
        self.assertIn("events", xss_patterns)
        self.assertIn("functions", xss_patterns)
        self.assertIn("protocols", xss_patterns)
        
        # Check SQL patterns
        self.assertIn(PayloadType.SQL_INJECTION, patterns)
        sql_patterns = patterns[PayloadType.SQL_INJECTION]
        self.assertIn("keywords", sql_patterns)
        self.assertIn("operators", sql_patterns)
        self.assertIn("comments", sql_patterns)
        self.assertIn("functions", sql_patterns)
        
        # Check command patterns
        self.assertIn(PayloadType.COMMAND_INJECTION, patterns)
        cmd_patterns = patterns[PayloadType.COMMAND_INJECTION]
        self.assertIn("separators", cmd_patterns)
        self.assertIn("commands", cmd_patterns)
        self.assertIn("operators", cmd_patterns)
        
        # Check path patterns
        self.assertIn(PayloadType.PATH_TRAVERSAL, patterns)
        path_patterns = patterns[PayloadType.PATH_TRAVERSAL]
        self.assertIn("sequences", path_patterns)
        self.assertIn("targets", path_patterns)
        self.assertIn("encodings", path_patterns)
    
    def test_population_initialization(self):
        """Test population initialization."""
        base_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>"
        ]
        
        self.mutator.initialize_population(base_payloads, PayloadType.XSS)
        
        self.assertEqual(len(self.mutator.population), 10)
        
        # Check that base payloads are included
        payload_strings = [p.payload for p in self.mutator.population]
        for base_payload in base_payloads:
            self.assertIn(base_payload, payload_strings)
        
        # Check that all payloads have correct type
        for payload in self.mutator.population:
            self.assertEqual(payload.payload_type, PayloadType.XSS)
    
    def test_random_payload_generation(self):
        """Test random payload generation."""
        # Test XSS
        xss_payload = self.mutator._generate_random_payload(PayloadType.XSS)
        self.assertIn("<script>", xss_payload)
        
        # Test SQL
        sql_payload = self.mutator._generate_random_payload(PayloadType.SQL_INJECTION)
        self.assertIn("OR", sql_payload)
        
        # Test command
        cmd_payload = self.mutator._generate_random_payload(PayloadType.COMMAND_INJECTION)
        self.assertIn("ls", cmd_payload)
        
        # Test path
        path_payload = self.mutator._generate_random_payload(PayloadType.PATH_TRAVERSAL)
        self.assertIn("../", path_payload)
    
    def test_xss_mutation(self):
        """Test XSS-specific mutations."""
        base_payload = GeneticPayload("<script>alert(1)</script>", PayloadType.XSS)
        
        mutated = self.mutator._mutate_xss(base_payload)
        
        self.assertIsInstance(mutated, GeneticPayload)
        self.assertEqual(mutated.payload_type, PayloadType.XSS)
        self.assertNotEqual(mutated.payload, base_payload.payload)
        self.assertEqual(mutated.mutation_count, base_payload.mutation_count + 1)
    
    def test_sql_mutation(self):
        """Test SQL-specific mutations."""
        base_payload = GeneticPayload("' OR 1=1--", PayloadType.SQL_INJECTION)
        
        mutated = self.mutator._mutate_sql(base_payload)
        
        self.assertIsInstance(mutated, GeneticPayload)
        self.assertEqual(mutated.payload_type, PayloadType.SQL_INJECTION)
        self.assertNotEqual(mutated.payload, base_payload.payload)
        self.assertEqual(mutated.mutation_count, base_payload.mutation_count + 1)
    
    def test_command_mutation(self):
        """Test command injection mutations."""
        base_payload = GeneticPayload("; ls -la", PayloadType.COMMAND_INJECTION)
        
        mutated = self.mutator._mutate_command(base_payload)
        
        self.assertIsInstance(mutated, GeneticPayload)
        self.assertEqual(mutated.payload_type, PayloadType.COMMAND_INJECTION)
        self.assertNotEqual(mutated.payload, base_payload.payload)
        self.assertEqual(mutated.mutation_count, base_payload.mutation_count + 1)
    
    def test_path_mutation(self):
        """Test path traversal mutations."""
        base_payload = GeneticPayload("../../../etc/passwd", PayloadType.PATH_TRAVERSAL)
        
        mutated = self.mutator._mutate_path(base_payload)
        
        self.assertIsInstance(mutated, GeneticPayload)
        self.assertEqual(mutated.payload_type, PayloadType.PATH_TRAVERSAL)
        self.assertNotEqual(mutated.payload, base_payload.payload)
        self.assertEqual(mutated.mutation_count, base_payload.mutation_count + 1)
    
    def test_general_mutation(self):
        """Test general mutations."""
        base_payload = GeneticPayload("test", PayloadType.XSS)
        
        mutated = self.mutator._mutate_general(base_payload)
        
        self.assertIsInstance(mutated, GeneticPayload)
        self.assertEqual(mutated.payload_type, PayloadType.XSS)
        self.assertEqual(mutated.mutation_count, base_payload.mutation_count + 1)
    
    def test_xss_crossover(self):
        """Test XSS-specific crossover."""
        parent1 = GeneticPayload("<script>alert(1)</script>", PayloadType.XSS)
        parent2 = GeneticPayload("<img src=x onerror=alert(1)>", PayloadType.XSS)
        
        child = self.mutator._crossover_xss(parent1, parent2)
        
        self.assertIsInstance(child, GeneticPayload)
        self.assertEqual(child.payload_type, PayloadType.XSS)
        self.assertNotEqual(child.payload, parent1.payload)
        self.assertNotEqual(child.payload, parent2.payload)
    
    def test_sql_crossover(self):
        """Test SQL-specific crossover."""
        parent1 = GeneticPayload("' OR 1=1--", PayloadType.SQL_INJECTION)
        parent2 = GeneticPayload("' UNION SELECT 1--", PayloadType.SQL_INJECTION)
        
        child = self.mutator._crossover_sql(parent1, parent2)
        
        self.assertIsInstance(child, GeneticPayload)
        self.assertEqual(child.payload_type, PayloadType.SQL_INJECTION)
        self.assertNotEqual(child.payload, parent1.payload)
        self.assertNotEqual(child.payload, parent2.payload)
    
    def test_general_crossover(self):
        """Test general crossover."""
        parent1 = GeneticPayload("test1", PayloadType.XSS)
        parent2 = GeneticPayload("test2", PayloadType.XSS)
        
        child = self.mutator._crossover_general(parent1, parent2)
        
        self.assertIsInstance(child, GeneticPayload)
        self.assertEqual(child.payload_type, PayloadType.XSS)
    
    def test_parent_selection(self):
        """Test parent selection."""
        # Create population with different fitness values
        self.mutator.population = [
            GeneticPayload("payload1", PayloadType.XSS, fitness=0.1),
            GeneticPayload("payload2", PayloadType.XSS, fitness=0.5),
            GeneticPayload("payload3", PayloadType.XSS, fitness=0.9)
        ]
        
        selected = self.mutator._select_parent()
        
        self.assertIsInstance(selected, GeneticPayload)
        self.assertIn(selected, self.mutator.population)
    
    def test_evolution(self):
        """Test the evolution process."""
        # Initialize population
        base_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>"
        ]
        self.mutator.initialize_population(base_payloads, PayloadType.XSS)
        
        # Define a simple fitness function
        def fitness_function(payload: GeneticPayload) -> float:
            score = 0.0
            if "script" in payload.payload.lower():
                score += 0.5
            if "alert" in payload.payload.lower():
                score += 0.3
            return score
        
        # Run evolution
        best_payloads = self.mutator.evolve(fitness_function)
        
        self.assertIsInstance(best_payloads, list)
        self.assertGreater(len(best_payloads), 0)
        
        # Check that best payloads are sorted by fitness
        for i in range(len(best_payloads) - 1):
            self.assertGreaterEqual(best_payloads[i].fitness, best_payloads[i + 1].fitness)
    
    def test_get_best_payloads(self):
        """Test getting best payloads."""
        # Create some test payloads with different fitness values
        self.mutator.best_payloads = [
            GeneticPayload("payload1", PayloadType.XSS, fitness=0.1),
            GeneticPayload("payload2", PayloadType.XSS, fitness=0.5),
            GeneticPayload("payload3", PayloadType.XSS, fitness=0.9),
            GeneticPayload("payload4", PayloadType.XSS, fitness=0.3)
        ]
        
        best = self.mutator.get_best_payloads(count=2)
        
        self.assertEqual(len(best), 2)
        self.assertEqual(best[0].fitness, 0.9)
        self.assertEqual(best[1].fitness, 0.5)
    
    def test_export_evolution_data(self):
        """Test evolution data export."""
        # Create test data
        self.mutator.generation = 10
        self.mutator.best_payloads = [
            GeneticPayload("test_payload", PayloadType.XSS, fitness=0.8, generation=5, mutation_count=2)
        ]
        
        # Export data
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_file = f.name
        
        try:
            self.mutator.export_evolution_data(temp_file)
            self.assertTrue(os.path.exists(temp_file))
            
            # Verify JSON content
            with open(temp_file, 'r') as f:
                data = json.load(f)
                self.assertEqual(data["generations"], 10)
                self.assertEqual(data["population_size"], 10)
                self.assertEqual(len(data["best_payloads"]), 1)
                self.assertEqual(data["best_payloads"][0]["payload"], "test_payload")
        finally:
            os.unlink(temp_file)


if __name__ == '__main__':
    # Set up logging for tests
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run the tests
    unittest.main(verbosity=2) 