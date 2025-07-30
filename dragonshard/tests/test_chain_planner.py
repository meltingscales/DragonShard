#!/usr/bin/env python3
"""
Unit tests for DragonShard Chain Planner Module

Tests the chain planner functionality including vulnerability analysis,
attack chain generation, and planning features.
"""

import json
import tempfile
import unittest
from typing import List
from unittest.mock import Mock, patch

from dragonshard.planner.attack_strategies import AttackStrategies, StrategyType
from dragonshard.planner.chain_planner import (
    AttackChain,
    AttackComplexity,
    AttackImpact,
    AttackStep,
    AttackType,
    ChainPlanner,
    Vulnerability,
)
from dragonshard.planner.vulnerability_prioritization import (
    RiskLevel,
    VulnerabilityPrioritizer,
    VulnerabilityScore,
)


class TestChainPlanner(unittest.TestCase):
    """Test cases for ChainPlanner class."""

    def setUp(self):
        """Set up test fixtures."""
        self.planner = ChainPlanner()
        self.sample_vulnerabilities = [
            Vulnerability(
                target_url="http://example.com/search.php",
                vulnerability_type=AttackType.SQL_INJECTION,
                payload="' OR 1=1--",
                confidence=0.9,
                evidence="SQL syntax error in response",
                impact=AttackImpact.HIGH,
                complexity=AttackComplexity.MEDIUM,
                exploitability=0.8,
                description="SQL injection vulnerability in search parameter",
                remediation="Use parameterized queries",
            ),
            Vulnerability(
                target_url="http://example.com/comment.php",
                vulnerability_type=AttackType.XSS,
                payload="<script>alert('XSS')</script>",
                confidence=0.7,
                evidence="JavaScript executed in response",
                impact=AttackImpact.MEDIUM,
                complexity=AttackComplexity.LOW,
                exploitability=0.6,
                description="Reflected XSS vulnerability",
                remediation="Implement output encoding",
            ),
            Vulnerability(
                target_url="http://example.com/upload.php",
                vulnerability_type=AttackType.COMMAND_INJECTION,
                payload="; ls -la",
                confidence=0.8,
                evidence="Command output in response",
                impact=AttackImpact.CRITICAL,
                complexity=AttackComplexity.HIGH,
                exploitability=0.9,
                description="Command injection vulnerability",
                remediation="Avoid command execution",
            ),
        ]

    def test_planner_initialization(self):
        """Test ChainPlanner initialization."""
        self.assertIsNotNone(self.planner)
        self.assertEqual(len(self.planner.discovered_vulnerabilities), 0)
        self.assertEqual(len(self.planner.generated_chains), 0)
        self.assertEqual(len(self.planner.target_information), 0)

    def test_add_vulnerability(self):
        """Test adding vulnerabilities to planner."""
        vuln = self.sample_vulnerabilities[0]
        self.planner.add_vulnerability(vuln)

        self.assertEqual(len(self.planner.discovered_vulnerabilities), 1)
        self.assertEqual(self.planner.discovered_vulnerabilities[0], vuln)

    def test_add_target_information(self):
        """Test adding target information."""
        host = "example.com"
        info = {"ports": [80, 443], "services": ["http", "https"]}

        self.planner.add_target_information(host, info)

        self.assertIn(host, self.planner.target_information)
        self.assertEqual(self.planner.target_information[host], info)

    def test_analyze_vulnerabilities_empty(self):
        """Test vulnerability analysis with no vulnerabilities."""
        analysis = self.planner.analyze_vulnerabilities()

        self.assertIn("message", analysis)
        self.assertEqual(analysis["message"], "No vulnerabilities to analyze")

    def test_analyze_vulnerabilities_with_data(self):
        """Test vulnerability analysis with vulnerabilities."""
        for vuln in self.sample_vulnerabilities:
            self.planner.add_vulnerability(vuln)

        analysis = self.planner.analyze_vulnerabilities()

        self.assertEqual(analysis["total_vulnerabilities"], 3)
        self.assertIn("sql_injection", analysis["vulnerability_types"])
        self.assertIn("xss", analysis["vulnerability_types"])
        self.assertIn("command_injection", analysis["vulnerability_types"])
        self.assertIn("attack_opportunities", analysis)

    def test_generate_attack_chains_empty(self):
        """Test attack chain generation with no vulnerabilities."""
        chains = self.planner.generate_attack_chains()

        self.assertEqual(len(chains), 0)

    def test_generate_attack_chains_with_sql_injection(self):
        """Test attack chain generation for SQL injection."""
        sql_vuln = self.sample_vulnerabilities[0]
        self.planner.add_vulnerability(sql_vuln)

        chains = self.planner.generate_attack_chains()

        self.assertGreater(len(chains), 0)
        sql_chains = [c for c in chains if "SQL Injection" in c.chain_name]
        self.assertGreater(len(sql_chains), 0)

    def test_generate_attack_chains_with_xss(self):
        """Test attack chain generation for XSS."""
        xss_vuln = self.sample_vulnerabilities[1]
        self.planner.add_vulnerability(xss_vuln)

        chains = self.planner.generate_attack_chains()

        self.assertGreater(len(chains), 0)
        xss_chains = [c for c in chains if "XSS" in c.chain_name]
        self.assertGreater(len(xss_chains), 0)

    def test_generate_attack_chains_with_rce(self):
        """Test attack chain generation for RCE."""
        rce_vuln = self.sample_vulnerabilities[2]
        self.planner.add_vulnerability(rce_vuln)

        chains = self.planner.generate_attack_chains()

        self.assertGreater(len(chains), 0)
        rce_chains = [c for c in chains if "RCE" in c.chain_name]
        self.assertGreater(len(rce_chains), 0)

    def test_get_attack_chains_filtered(self):
        """Test getting attack chains filtered by target."""
        for vuln in self.sample_vulnerabilities:
            self.planner.add_vulnerability(vuln)

        self.planner.generate_attack_chains()

        # Test filtering by target
        example_chains = self.planner.get_attack_chains("example.com")
        self.assertGreater(len(example_chains), 0)

        # Test filtering by non-existent target
        empty_chains = self.planner.get_attack_chains("nonexistent.com")
        self.assertEqual(len(empty_chains), 0)

    def test_export_chains(self):
        """Test exporting attack chains."""
        for vuln in self.sample_vulnerabilities:
            self.planner.add_vulnerability(vuln)

        self.planner.generate_attack_chains()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            filename = f.name

        try:
            self.planner.export_chains(filename)

            with open(filename, "r") as f:
                data = json.load(f)

            self.assertIn("generated_at", data)
            self.assertIn("total_chains", data)
            self.assertIn("chains", data)
            self.assertGreater(data["total_chains"], 0)

        finally:
            import os

            os.unlink(filename)

    def test_export_chains_invalid_format(self):
        """Test exporting chains with invalid format."""
        for vuln in self.sample_vulnerabilities:
            self.planner.add_vulnerability(vuln)

        self.planner.generate_attack_chains()

        with self.assertRaises(ValueError):
            self.planner.export_chains("test.csv", format="csv")

    def test_get_planning_summary(self):
        """Test getting planning summary."""
        for vuln in self.sample_vulnerabilities:
            self.planner.add_vulnerability(vuln)

        self.planner.generate_attack_chains()
        summary = self.planner.get_planning_summary()

        self.assertIn("total_vulnerabilities", summary)
        self.assertIn("total_chains", summary)
        self.assertIn("targets_analyzed", summary)
        self.assertIn("high_risk_chains", summary)
        self.assertIn("average_success_probability", summary)
        self.assertIn("recommendations", summary)

        self.assertEqual(summary["total_vulnerabilities"], 3)
        self.assertGreater(summary["total_chains"], 0)

    def test_attack_step_creation(self):
        """Test AttackStep creation and validation."""
        step = AttackStep(
            step_id="test_step",
            step_name="Test Step",
            attack_type=AttackType.SQL_INJECTION,
            target_url="http://example.com/test",
            payload="' OR 1=1--",
            expected_outcome="SQL injection successful",
            success_criteria="Database error returned",
            dependencies=["previous_step"],
            estimated_time=60,
        )

        self.assertEqual(step.step_id, "test_step")
        self.assertEqual(step.step_name, "Test Step")
        self.assertEqual(step.attack_type, AttackType.SQL_INJECTION)
        self.assertEqual(step.target_url, "http://example.com/test")
        self.assertEqual(step.payload, "' OR 1=1--")
        self.assertEqual(step.expected_outcome, "SQL injection successful")
        self.assertEqual(step.success_criteria, "Database error returned")
        self.assertEqual(step.dependencies, ["previous_step"])
        self.assertEqual(step.estimated_time, 60)

    def test_attack_chain_creation(self):
        """Test AttackChain creation and validation."""
        steps = [
            AttackStep(
                step_id="step1",
                step_name="Step 1",
                attack_type=AttackType.SQL_INJECTION,
                target_url="http://example.com/test",
                payload="test",
                expected_outcome="Success",
                success_criteria="Criteria met",
                estimated_time=30,
            )
        ]

        chain = AttackChain(
            chain_id="test_chain",
            chain_name="Test Chain",
            description="Test attack chain",
            target_host="http://example.com",
            attack_steps=steps,
            total_impact=AttackImpact.HIGH,
            total_complexity=AttackComplexity.MEDIUM,
            success_probability=0.8,
            estimated_duration=30,
            risk_assessment="High risk test",
        )

        self.assertEqual(chain.chain_id, "test_chain")
        self.assertEqual(chain.chain_name, "Test Chain")
        self.assertEqual(chain.description, "Test attack chain")
        self.assertEqual(chain.target_host, "http://example.com")
        self.assertEqual(len(chain.attack_steps), 1)
        self.assertEqual(chain.total_impact, AttackImpact.HIGH)
        self.assertEqual(chain.total_complexity, AttackComplexity.MEDIUM)
        self.assertEqual(chain.success_probability, 0.8)
        self.assertEqual(chain.estimated_duration, 30)
        self.assertEqual(chain.risk_assessment, "High risk test")


class TestAttackStrategies(unittest.TestCase):
    """Test cases for AttackStrategies class."""

    def setUp(self):
        """Set up test fixtures."""
        self.strategies = AttackStrategies()

    def test_strategies_initialization(self):
        """Test AttackStrategies initialization."""
        self.assertIsNotNone(self.strategies)
        self.assertGreater(len(self.strategies.strategies), 0)

    def test_get_strategy(self):
        """Test getting a specific strategy."""
        strategy = self.strategies.get_strategy("web_app_comprehensive")

        self.assertIsNotNone(strategy)
        self.assertEqual(strategy.strategy_id, "web_app_comprehensive")
        self.assertEqual(strategy.name, "Comprehensive Web Application Attack")

    def test_get_strategy_nonexistent(self):
        """Test getting a non-existent strategy."""
        strategy = self.strategies.get_strategy("nonexistent_strategy")

        self.assertIsNone(strategy)

    def test_get_strategies_by_type(self):
        """Test getting strategies by type."""
        web_strategies = self.strategies.get_strategies_by_type(StrategyType.WEB_APPLICATION)

        self.assertGreater(len(web_strategies), 0)
        for strategy in web_strategies:
            self.assertEqual(strategy.strategy_type, StrategyType.WEB_APPLICATION)

    def test_get_strategies_for_vulnerability(self):
        """Test getting strategies for specific vulnerability types."""
        sql_strategies = self.strategies.get_strategies_for_vulnerability(AttackType.SQL_INJECTION)

        self.assertGreater(len(sql_strategies), 0)
        for strategy in sql_strategies:
            self.assertIn("sql_injection", strategy.strategy_id)

    def test_convert_strategy_to_chain(self):
        """Test converting strategy to attack chain."""
        strategy = self.strategies.get_strategy("sql_injection_chain")
        vulnerabilities = []

        chain = self.strategies.convert_strategy_to_chain(
            strategy, "http://example.com", vulnerabilities
        )

        self.assertIsNotNone(chain)
        self.assertIn("sql_injection_chain", chain.chain_id)
        self.assertEqual(chain.target_host, "http://example.com")
        self.assertGreater(len(chain.attack_steps), 0)

    def test_get_all_strategies(self):
        """Test getting all strategies."""
        all_strategies = self.strategies.get_all_strategies()

        self.assertGreater(len(all_strategies), 0)
        self.assertEqual(len(all_strategies), len(self.strategies.strategies))

    def test_export_strategies(self):
        """Test exporting strategies to JSON."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            filename = f.name

        try:
            self.strategies.export_strategies(filename)

            with open(filename, "r") as f:
                data = json.load(f)

            self.assertIn("strategies", data)
            self.assertGreater(len(data["strategies"]), 0)

        finally:
            import os

            os.unlink(filename)


class TestVulnerabilityPrioritizer(unittest.TestCase):
    """Test cases for VulnerabilityPrioritizer class."""

    def setUp(self):
        """Set up test fixtures."""
        self.prioritizer = VulnerabilityPrioritizer()
        self.sample_vulnerabilities = [
            Vulnerability(
                target_url="http://example.com/search.php",
                vulnerability_type=AttackType.SQL_INJECTION,
                payload="' OR 1=1--",
                confidence=0.9,
                evidence="SQL syntax error in response",
                impact=AttackImpact.HIGH,
                complexity=AttackComplexity.MEDIUM,
                exploitability=0.8,
                description="SQL injection vulnerability in search parameter",
                remediation="Use parameterized queries",
            ),
            Vulnerability(
                target_url="http://example.com/comment.php",
                vulnerability_type=AttackType.XSS,
                payload="<script>alert('XSS')</script>",
                confidence=0.7,
                evidence="JavaScript executed in response",
                impact=AttackImpact.MEDIUM,
                complexity=AttackComplexity.LOW,
                exploitability=0.6,
                description="Reflected XSS vulnerability",
                remediation="Implement output encoding",
            ),
            Vulnerability(
                target_url="http://example.com/upload.php",
                vulnerability_type=AttackType.COMMAND_INJECTION,
                payload="; ls -la",
                confidence=0.8,
                evidence="Command output in response",
                impact=AttackImpact.CRITICAL,
                complexity=AttackComplexity.HIGH,
                exploitability=0.9,
                description="Command injection vulnerability",
                remediation="Avoid command execution",
            ),
        ]

    def test_prioritizer_initialization(self):
        """Test VulnerabilityPrioritizer initialization."""
        self.assertIsNotNone(self.prioritizer)
        self.assertIsNotNone(self.prioritizer.impact_weights)
        self.assertIsNotNone(self.prioritizer.complexity_weights)
        self.assertIsNotNone(self.prioritizer.exploitability_factors)

    def test_calculate_risk_score(self):
        """Test risk score calculation."""
        vuln = self.sample_vulnerabilities[0]  # SQL injection
        risk_score = self.prioritizer.calculate_risk_score(vuln)

        self.assertGreater(risk_score, 0)
        self.assertLessEqual(risk_score, 10.0)

    def test_determine_risk_level(self):
        """Test risk level determination."""
        # Test different risk levels
        self.assertEqual(self.prioritizer.determine_risk_level(9.0), RiskLevel.CRITICAL)
        self.assertEqual(self.prioritizer.determine_risk_level(7.0), RiskLevel.HIGH)
        self.assertEqual(self.prioritizer.determine_risk_level(5.0), RiskLevel.MEDIUM)
        self.assertEqual(self.prioritizer.determine_risk_level(3.0), RiskLevel.LOW)
        self.assertEqual(self.prioritizer.determine_risk_level(1.0), RiskLevel.INFO)

    def test_calculate_exploitability_score(self):
        """Test exploitability score calculation."""
        vuln = self.sample_vulnerabilities[0]  # SQL injection
        exploitability_score = self.prioritizer.calculate_exploitability_score(vuln)

        self.assertGreater(exploitability_score, 0)
        self.assertLessEqual(exploitability_score, 1.0)

    def test_calculate_impact_score(self):
        """Test impact score calculation."""
        vuln = self.sample_vulnerabilities[0]  # SQL injection
        impact_score = self.prioritizer.calculate_impact_score(vuln)

        self.assertGreater(impact_score, 0)
        self.assertLessEqual(impact_score, 1.0)

    def test_calculate_complexity_score(self):
        """Test complexity score calculation."""
        vuln = self.sample_vulnerabilities[0]  # SQL injection
        complexity_score = self.prioritizer.calculate_complexity_score(vuln)

        self.assertGreater(complexity_score, 0)
        self.assertLessEqual(complexity_score, 1.0)

    def test_estimate_time_to_exploit(self):
        """Test time to exploit estimation."""
        vuln = self.sample_vulnerabilities[0]  # SQL injection
        estimated_time = self.prioritizer.estimate_time_to_exploit(vuln)

        self.assertGreater(estimated_time, 0)
        self.assertGreaterEqual(estimated_time, 5)  # Minimum 5 minutes

    def test_assess_business_impact(self):
        """Test business impact assessment."""
        vuln = self.sample_vulnerabilities[0]  # SQL injection
        business_impact = self.prioritizer.assess_business_impact(vuln)

        self.assertIsInstance(business_impact, str)
        self.assertGreater(len(business_impact), 0)

    def test_assess_technical_impact(self):
        """Test technical impact assessment."""
        vuln = self.sample_vulnerabilities[0]  # SQL injection
        technical_impact = self.prioritizer.assess_technical_impact(vuln)

        self.assertIsInstance(technical_impact, str)
        self.assertGreater(len(technical_impact), 0)

    def test_prioritize_vulnerabilities(self):
        """Test vulnerability prioritization."""
        scored_vulns = self.prioritizer.prioritize_vulnerabilities(self.sample_vulnerabilities)

        self.assertEqual(len(scored_vulns), len(self.sample_vulnerabilities))

        # Check that vulnerabilities are sorted by risk score (descending)
        for i in range(len(scored_vulns) - 1):
            self.assertGreaterEqual(scored_vulns[i].risk_score, scored_vulns[i + 1].risk_score)

    def test_get_critical_vulnerabilities(self):
        """Test getting critical vulnerabilities."""
        critical_vulns = self.prioritizer.get_critical_vulnerabilities(self.sample_vulnerabilities)

        # Should find the command injection vulnerability as critical
        self.assertGreater(len(critical_vulns), 0)
        for vuln in critical_vulns:
            # Check that it's either command injection or has critical impact
            self.assertTrue(
                vuln.vulnerability_type == AttackType.COMMAND_INJECTION
                or vuln.impact == AttackImpact.CRITICAL
            )

    def test_get_high_risk_vulnerabilities(self):
        """Test getting high-risk vulnerabilities."""
        high_risk_vulns = self.prioritizer.get_high_risk_vulnerabilities(
            self.sample_vulnerabilities
        )

        # Should find high and critical impact vulnerabilities
        self.assertGreater(len(high_risk_vulns), 0)
        for vuln in high_risk_vulns:
            # Check that it has high or critical impact
            self.assertTrue(vuln.impact in [AttackImpact.HIGH, AttackImpact.CRITICAL])

    def test_generate_prioritization_report(self):
        """Test prioritization report generation."""
        report = self.prioritizer.generate_prioritization_report(self.sample_vulnerabilities)

        self.assertIn("summary", report)
        self.assertIn("top_vulnerabilities", report)
        self.assertIn("recommendations", report)
        self.assertIn("detailed_scores", report)

        self.assertEqual(report["summary"]["total_vulnerabilities"], 3)
        self.assertGreater(len(report["top_vulnerabilities"]), 0)
        self.assertGreater(len(report["recommendations"]), 0)
        self.assertEqual(len(report["detailed_scores"]), 3)


if __name__ == "__main__":
    unittest.main()
