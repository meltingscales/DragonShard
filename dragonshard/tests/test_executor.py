#!/usr/bin/env python3
"""
Unit tests for DragonShard Executor Module

Tests for executor.py, session_manager.py, and state_graph.py
"""

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

from dragonshard.executor.executor import (
    AttackExecutor,
    ExecutionConfig,
    ExecutionResult,
    ExecutionSession,
    ExecutionStatus,
    ExecutionStep,
)
from dragonshard.executor.session_manager import (
    AuthCredentials,
    AuthMethod,
    SessionData,
    SessionManager,
    SessionState,
)
from dragonshard.executor.state_graph import (
    ConnectionInfo,
    HostInfo,
    HostStatus,
    ServiceInfo,
    ServiceType,
    StateGraph,
    VulnerabilityInfo,
    VulnerabilityLevel,
)
from dragonshard.planner.chain_planner import (
    AttackChain,
    AttackComplexity,
    AttackImpact,
    AttackStep,
    AttackType,
)


class TestExecutionConfig(unittest.TestCase):
    """Test ExecutionConfig dataclass."""

    def test_default_config(self):
        """Test default configuration values."""
        config = ExecutionConfig()

        self.assertEqual(config.timeout, 30)
        self.assertEqual(config.max_retries, 3)
        self.assertEqual(config.retry_delay, 1.0)
        self.assertTrue(config.follow_redirects)
        self.assertFalse(config.verify_ssl)
        self.assertEqual(config.user_agent, "DragonShard/1.0")
        self.assertIsNotNone(config.default_headers)

    def test_custom_config(self):
        """Test custom configuration values."""
        config = ExecutionConfig(timeout=60, max_retries=5, rate_limit=10.0)

        self.assertEqual(config.timeout, 60)
        self.assertEqual(config.max_retries, 5)
        self.assertEqual(config.rate_limit, 10.0)


class TestExecutionStep(unittest.TestCase):
    """Test ExecutionStep dataclass."""

    def test_execution_step_creation(self):
        """Test creating an execution step."""
        step = ExecutionStep(
            step_id="test_step",
            step_name="Test Step",
            target_url="http://example.com",
            payload="test payload",
            status=ExecutionStatus.COMPLETED,
            result=ExecutionResult.SUCCESS,
        )

        self.assertEqual(step.step_id, "test_step")
        self.assertEqual(step.step_name, "Test Step")
        self.assertEqual(step.target_url, "http://example.com")
        self.assertEqual(step.payload, "test payload")
        self.assertEqual(step.status, ExecutionStatus.COMPLETED)
        self.assertEqual(step.result, ExecutionResult.SUCCESS)
        self.assertIsNotNone(step.timestamp)

    def test_execution_step_with_results(self):
        """Test execution step with response results."""
        step = ExecutionStep(
            step_id="test_step",
            step_name="Test Step",
            target_url="http://example.com",
            payload="test payload",
            status=ExecutionStatus.COMPLETED,
            result=ExecutionResult.SUCCESS,
            response_code=200,
            response_time=1.5,
            response_size=1024,
            evidence="Vulnerability confirmed",
        )

        self.assertEqual(step.response_code, 200)
        self.assertEqual(step.response_time, 1.5)
        self.assertEqual(step.response_size, 1024)
        self.assertEqual(step.evidence, "Vulnerability confirmed")


class TestExecutionSession(unittest.TestCase):
    """Test ExecutionSession dataclass."""

    def test_session_creation(self):
        """Test creating an execution session."""
        session = ExecutionSession(
            session_id="test_session",
            chain_id="test_chain",
            target_host="http://example.com",
            status=ExecutionStatus.RUNNING,
            start_time=time.time(),
        )

        self.assertEqual(session.session_id, "test_session")
        self.assertEqual(session.chain_id, "test_chain")
        self.assertEqual(session.target_host, "http://example.com")
        self.assertEqual(session.status, ExecutionStatus.RUNNING)
        self.assertEqual(session.total_steps, 0)
        self.assertEqual(session.completed_steps, 0)
        self.assertEqual(session.failed_steps, 0)
        self.assertEqual(session.success_rate, 0.0)
        self.assertIsNotNone(session.results_summary)
        self.assertIsNotNone(session.error_log)


class TestAttackExecutor(unittest.TestCase):
    """Test AttackExecutor class."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = ExecutionConfig(timeout=5, max_retries=1)
        self.executor = AttackExecutor(self.config)

    def test_initialization(self):
        """Test executor initialization."""
        self.assertIsNotNone(self.executor.config)
        self.assertIsNotNone(self.executor.client)
        self.assertIsNotNone(self.executor.fuzzer)
        self.assertIsNotNone(self.executor.crawler)
        self.assertEqual(len(self.executor.active_sessions), 0)
        self.assertEqual(len(self.executor.completed_sessions), 0)

    def test_execute_attack_chain(self):
        """Test executing an attack chain."""
        # Create a simple attack chain
        steps = [
            AttackStep(
                step_id="test_step",
                step_name="Test SQL Injection",
                attack_type=AttackType.SQL_INJECTION,
                target_url="http://example.com/search.php",
                payload="' OR 1=1--",
                expected_outcome="SQL injection successful",
                success_criteria="Database error returned",
                estimated_time=30,
            )
        ]

        chain = AttackChain(
            chain_id="test_chain",
            chain_name="Test Attack Chain",
            description="Test attack chain",
            target_host="http://example.com",
            attack_steps=steps,
            total_impact=AttackImpact.HIGH,
            total_complexity=AttackComplexity.MEDIUM,
            success_probability=0.8,
            estimated_duration=30,
        )

        # Mock the fuzzer to avoid actual HTTP requests
        with patch.object(self.executor.fuzzer, "_test_payload") as mock_test:
            mock_result = Mock()
            mock_result.is_vulnerable = False
            mock_result.status_code = 200
            mock_result.response_time = 1.0
            mock_result.response_size = 100
            mock_result.evidence = None
            mock_test.return_value = mock_result

            session = self.executor.execute_attack_chain(chain)

        self.assertIsInstance(session, ExecutionSession)
        self.assertEqual(session.chain_id, "test_chain")
        self.assertEqual(session.target_host, "http://example.com")
        self.assertEqual(session.total_steps, 1)
        self.assertEqual(session.completed_steps, 1)

    def test_execute_multiple_chains(self):
        """Test executing multiple attack chains."""
        # Create multiple chains
        chains = []
        for i in range(3):
            steps = [
                AttackStep(
                    step_id=f"step_{i}",
                    step_name=f"Test Step {i}",
                    attack_type=AttackType.SQL_INJECTION,
                    target_url=f"http://example{i}.com/test.php",
                    payload="test payload",
                    expected_outcome="Test outcome",
                    success_criteria="Test criteria",
                    estimated_time=30,
                )
            ]

            chain = AttackChain(
                chain_id=f"chain_{i}",
                chain_name=f"Test Chain {i}",
                description=f"Test chain {i}",
                target_host=f"http://example{i}.com",
                attack_steps=steps,
                total_impact=AttackImpact.MEDIUM,
                total_complexity=AttackComplexity.LOW,
                success_probability=0.5,
                estimated_duration=30,
            )
            chains.append(chain)

        # Mock the fuzzer
        with patch.object(self.executor.fuzzer, "_test_payload") as mock_test:
            mock_result = Mock()
            mock_result.is_vulnerable = False
            mock_result.status_code = 200
            mock_result.response_time = 1.0
            mock_result.response_size = 100
            mock_result.evidence = None
            mock_test.return_value = mock_result

            sessions = self.executor.execute_multiple_chains(chains)

        self.assertEqual(len(sessions), 3)
        for session in sessions:
            self.assertIsInstance(session, ExecutionSession)

    def test_get_execution_summary(self):
        """Test getting execution summary."""
        # Add some completed sessions
        session1 = ExecutionSession(
            session_id="session1",
            chain_id="chain1",
            target_host="http://example1.com",
            status=ExecutionStatus.COMPLETED,
            start_time=time.time() - 100,
            end_time=time.time() - 50,
            total_steps=2,
            completed_steps=2,
            failed_steps=0,
            success_rate=1.0,
            total_execution_time=50.0,
        )

        session2 = ExecutionSession(
            session_id="session2",
            chain_id="chain2",
            target_host="http://example2.com",
            status=ExecutionStatus.COMPLETED,
            start_time=time.time() - 200,
            end_time=time.time() - 150,
            total_steps=1,
            completed_steps=1,
            failed_steps=1,
            success_rate=0.0,
            total_execution_time=50.0,
        )

        self.executor.completed_sessions = [session1, session2]

        summary = self.executor.get_execution_summary()

        self.assertEqual(summary["total_sessions"], 2)
        self.assertEqual(summary["completed_sessions"], 2)
        self.assertEqual(summary["failed_sessions"], 0)
        self.assertEqual(summary["total_steps"], 3)
        self.assertEqual(summary["successful_steps"], 2)
        self.assertAlmostEqual(summary["avg_session_success_rate"], 0.5)

    def test_export_execution_results(self):
        """Test exporting execution results."""
        # Add a completed session
        session = ExecutionSession(
            session_id="test_session",
            chain_id="test_chain",
            target_host="http://example.com",
            status=ExecutionStatus.COMPLETED,
            start_time=time.time() - 100,
            end_time=time.time() - 50,
            total_steps=1,
            completed_steps=1,
            success_rate=1.0,
            total_execution_time=50.0,
        )

        self.executor.completed_sessions = [session]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            temp_file = f.name

        try:
            self.executor.export_execution_results(temp_file)

            # Verify the file was created and contains valid JSON
            with open(temp_file, "r") as f:
                data = json.load(f)

            self.assertIn("exported_at", data)
            self.assertIn("config", data)
            self.assertIn("sessions", data)
            self.assertIn("summary", data)

        finally:
            Path(temp_file).unlink(missing_ok=True)

    def test_stop_execution(self):
        """Test stopping execution."""
        self.executor.stop_execution()
        self.assertTrue(self.executor._stop_event.is_set())


class TestSessionManager(unittest.TestCase):
    """Test SessionManager class."""

    def setUp(self):
        """Set up test fixtures."""
        self.session_manager = SessionManager()

    def test_create_session(self):
        """Test creating a session."""
        session_id = self.session_manager.create_session("http://example.com", AuthMethod.FORM)

        self.assertIsNotNone(session_id)
        self.assertIn(session_id, self.session_manager.sessions)

        session = self.session_manager.sessions[session_id]
        self.assertEqual(session.target_host, "http://example.com")
        self.assertEqual(session.auth_method, AuthMethod.FORM)
        self.assertEqual(session.state, SessionState.UNAUTHENTICATED)

    def test_authenticate_session_form(self):
        """Test form-based authentication."""
        session_id = self.session_manager.create_session("http://example.com", AuthMethod.FORM)

        credentials = AuthCredentials(username="admin", password="password123")

        # Mock HTTP client to avoid actual requests
        with (
            patch.object(self.session_manager.client, "get") as mock_get,
            patch.object(self.session_manager.client, "post") as mock_post,
        ):
            # Mock login page response
            mock_get.return_value = Mock(
                status_code=200, text='<input name="csrf_token" value="test_token">'
            )

            # Mock login response
            mock_post.return_value = Mock(status_code=200, text="Welcome to dashboard", cookies={})

            success = self.session_manager.authenticate_session(session_id, credentials)

            self.assertTrue(success)

            session = self.session_manager.sessions[session_id]
            self.assertEqual(session.state, SessionState.AUTHENTICATED)

    def test_get_session_headers(self):
        """Test getting session headers."""
        session_id = self.session_manager.create_session("http://example.com")

        headers = self.session_manager.get_session_headers(session_id)

        self.assertIsInstance(headers, dict)
        self.assertIn("User-Agent", headers)

    def test_get_session_cookies(self):
        """Test getting session cookies."""
        session_id = self.session_manager.create_session("http://example.com")

        # Add some cookies
        self.session_manager.sessions[session_id].cookies = {
            "session_id": "test_session",
            "user_id": "123",
        }

        cookies = self.session_manager.get_session_cookies(session_id)

        self.assertEqual(cookies["session_id"], "test_session")
        self.assertEqual(cookies["user_id"], "123")

    def test_check_session_validity(self):
        """Test checking session validity."""
        session_id = self.session_manager.create_session("http://example.com")

        # Test unauthenticated session
        self.assertFalse(self.session_manager.check_session_validity(session_id))

        # Authenticate session
        self.session_manager.sessions[session_id].state = SessionState.AUTHENTICATED

        # Test valid session
        self.assertTrue(self.session_manager.check_session_validity(session_id))

        # Test expired session
        self.session_manager.sessions[session_id].last_used = time.time() - 7200
        self.assertFalse(self.session_manager.check_session_validity(session_id))

    def test_logout_session(self):
        """Test logging out from a session."""
        session_id = self.session_manager.create_session("http://example.com")

        # Authenticate first
        self.session_manager.sessions[session_id].state = SessionState.AUTHENTICATED
        self.session_manager.sessions[session_id].cookies = {"session": "test"}

        success = self.session_manager.logout_session(session_id)

        self.assertTrue(success)

        session = self.session_manager.sessions[session_id]
        self.assertEqual(session.state, SessionState.UNAUTHENTICATED)
        self.assertEqual(len(session.cookies), 0)

    def test_destroy_session(self):
        """Test destroying a session."""
        session_id = self.session_manager.create_session("http://example.com")

        success = self.session_manager.destroy_session(session_id)

        self.assertTrue(success)
        self.assertNotIn(session_id, self.session_manager.sessions)

    def test_get_session_info(self):
        """Test getting session information."""
        session_id = self.session_manager.create_session("http://example.com")

        info = self.session_manager.get_session_info(session_id)

        self.assertIsNotNone(info)
        self.assertEqual(info["session_id"], session_id)
        self.assertEqual(info["target_host"], "http://example.com")

    def test_cleanup_expired_sessions(self):
        """Test cleaning up expired sessions."""
        # Create sessions
        session1 = self.session_manager.create_session("http://example1.com")
        session2 = self.session_manager.create_session("http://example2.com")

        # Make one session expired
        self.session_manager.sessions[session1].last_used = time.time() - 7200

        cleaned = self.session_manager.cleanup_expired_sessions()

        self.assertEqual(cleaned, 1)
        self.assertNotIn(session1, self.session_manager.sessions)
        self.assertIn(session2, self.session_manager.sessions)

    def test_export_sessions(self):
        """Test exporting sessions."""
        session_id = self.session_manager.create_session("http://example.com")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            temp_file = f.name

        try:
            self.session_manager.export_sessions(temp_file)

            # Verify the file was created
            with open(temp_file, "r") as f:
                data = json.load(f)

            self.assertIn("exported_at", data)
            self.assertIn("sessions", data)

        finally:
            Path(temp_file).unlink(missing_ok=True)


class TestStateGraph(unittest.TestCase):
    """Test StateGraph class."""

    def setUp(self):
        """Set up test fixtures."""
        self.state_graph = StateGraph()

    def test_add_host(self):
        """Test adding a host."""
        host_id = self.state_graph.add_host("test.example.com", "192.168.1.10")

        self.assertIsNotNone(host_id)
        self.assertIn(host_id, self.state_graph.hosts)

        host = self.state_graph.hosts[host_id]
        self.assertEqual(host.hostname, "test.example.com")
        self.assertEqual(host.ip_address, "192.168.1.10")
        self.assertEqual(host.status, HostStatus.DISCOVERED)

    def test_add_service(self):
        """Test adding a service."""
        host_id = self.state_graph.add_host("test.example.com", "192.168.1.10")
        service_id = self.state_graph.add_service(host_id, 80, ServiceType.HTTP)

        self.assertIsNotNone(service_id)
        self.assertIn(service_id, self.state_graph.services)

        service = self.state_graph.services[service_id]
        self.assertEqual(service.host, host_id)
        self.assertEqual(service.port, 80)
        self.assertEqual(service.service_type, ServiceType.HTTP)

    def test_add_vulnerability(self):
        """Test adding a vulnerability."""
        host_id = self.state_graph.add_host("test.example.com", "192.168.1.10")
        service_id = self.state_graph.add_service(host_id, 80, ServiceType.HTTP)

        vuln_id = self.state_graph.add_vulnerability(
            service_id,
            "sql_injection",
            VulnerabilityLevel.HIGH,
            "SQL injection vulnerability found",
            "Evidence here",
        )

        self.assertIsNotNone(vuln_id)
        self.assertIn(vuln_id, self.state_graph.vulnerabilities)

        vuln = self.state_graph.vulnerabilities[vuln_id]
        self.assertEqual(vuln.service_id, service_id)
        self.assertEqual(vuln.vuln_type, "sql_injection")
        self.assertEqual(vuln.severity, VulnerabilityLevel.HIGH)

    def test_add_connection(self):
        """Test adding a connection."""
        host1 = self.state_graph.add_host("host1.example.com", "192.168.1.10")
        host2 = self.state_graph.add_host("host2.example.com", "192.168.1.20")

        conn_id = self.state_graph.add_connection(host1, host2, "http_request", "tcp", 80)

        self.assertIsNotNone(conn_id)
        self.assertIn(conn_id, self.state_graph.connections)

        conn = self.state_graph.connections[conn_id]
        self.assertEqual(conn.source_host, host1)
        self.assertEqual(conn.target_host, host2)
        self.assertEqual(conn.connection_type, "http_request")

    def test_get_host_services(self):
        """Test getting services for a host."""
        host_id = self.state_graph.add_host("test.example.com", "192.168.1.10")
        service1 = self.state_graph.add_service(host_id, 80, ServiceType.HTTP)
        service2 = self.state_graph.add_service(host_id, 443, ServiceType.HTTPS)

        services = self.state_graph.get_host_services(host_id)

        self.assertEqual(len(services), 2)
        service_types = [s.service_type for s in services]
        self.assertIn(ServiceType.HTTP, service_types)
        self.assertIn(ServiceType.HTTPS, service_types)

    def test_get_host_vulnerabilities(self):
        """Test getting vulnerabilities for a host."""
        host_id = self.state_graph.add_host("test.example.com", "192.168.1.10")
        service_id = self.state_graph.add_service(host_id, 80, ServiceType.HTTP)

        vuln_id = self.state_graph.add_vulnerability(
            service_id,
            "sql_injection",
            VulnerabilityLevel.HIGH,
            "SQL injection vulnerability found",
        )

        vulnerabilities = self.state_graph.get_host_vulnerabilities(host_id)

        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0].vuln_id, vuln_id)

    def test_get_service_vulnerabilities(self):
        """Test getting vulnerabilities for a service."""
        host_id = self.state_graph.add_host("test.example.com", "192.168.1.10")
        service_id = self.state_graph.add_service(host_id, 80, ServiceType.HTTP)

        vuln_id = self.state_graph.add_vulnerability(
            service_id,
            "sql_injection",
            VulnerabilityLevel.HIGH,
            "SQL injection vulnerability found",
        )

        vulnerabilities = self.state_graph.get_service_vulnerabilities(service_id)

        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0].vuln_id, vuln_id)

    def test_get_connected_hosts(self):
        """Test getting connected hosts."""
        host1 = self.state_graph.add_host("host1.example.com", "192.168.1.10")
        host2 = self.state_graph.add_host("host2.example.com", "192.168.1.20")

        self.state_graph.add_connection(host1, host2, "http_request", "tcp", 80)

        connected = self.state_graph.get_connected_hosts(host1)

        self.assertIn(host2, connected)

    def test_get_path_between_hosts(self):
        """Test getting path between hosts."""
        host1 = self.state_graph.add_host("host1.example.com", "192.168.1.10")
        host2 = self.state_graph.add_host("host2.example.com", "192.168.1.20")
        host3 = self.state_graph.add_host("host3.example.com", "192.168.1.30")

        self.state_graph.add_connection(host1, host2, "http_request", "tcp", 80)
        self.state_graph.add_connection(host2, host3, "database_query", "tcp", 3306)

        path = self.state_graph.get_path_between_hosts(host1, host3)

        self.assertEqual(len(path), 3)
        self.assertEqual(path[0], host1)
        self.assertEqual(path[1], host2)
        self.assertEqual(path[2], host3)

    def test_get_vulnerability_summary(self):
        """Test getting vulnerability summary."""
        host_id = self.state_graph.add_host("test.example.com", "192.168.1.10")
        service_id = self.state_graph.add_service(host_id, 80, ServiceType.HTTP)

        self.state_graph.add_vulnerability(
            service_id,
            "sql_injection",
            VulnerabilityLevel.HIGH,
            "SQL injection vulnerability found",
        )

        self.state_graph.add_vulnerability(
            service_id, "xss", VulnerabilityLevel.MEDIUM, "Cross-site scripting vulnerability"
        )

        summary = self.state_graph.get_vulnerability_summary()

        self.assertEqual(summary["total_vulnerabilities"], 2)
        self.assertEqual(summary["by_severity"]["high"], 1)
        self.assertEqual(summary["by_severity"]["medium"], 1)

    def test_get_network_topology(self):
        """Test getting network topology."""
        host1 = self.state_graph.add_host("host1.example.com", "192.168.1.10")
        host2 = self.state_graph.add_host("host2.example.com", "192.168.1.20")

        self.state_graph.add_service(host1, 80, ServiceType.HTTP)
        self.state_graph.add_service(host2, 443, ServiceType.HTTPS)

        topology = self.state_graph.get_network_topology()

        self.assertEqual(topology["total_hosts"], 2)
        self.assertEqual(topology["total_services"], 2)
        self.assertIn("http", topology["services_by_type"])
        self.assertIn("https", topology["services_by_type"])

    def test_export_graph(self):
        """Test exporting the state graph."""
        host_id = self.state_graph.add_host("test.example.com", "192.168.1.10")
        service_id = self.state_graph.add_service(host_id, 80, ServiceType.HTTP)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            temp_file = f.name

        try:
            self.state_graph.export_graph(temp_file)

            # Verify the file was created
            with open(temp_file, "r") as f:
                data = json.load(f)

            self.assertIn("exported_at", data)
            self.assertIn("metadata", data)
            self.assertIn("hosts", data)
            self.assertIn("services", data)

        finally:
            Path(temp_file).unlink(missing_ok=True)

    def test_clear(self):
        """Test clearing the state graph."""
        host_id = self.state_graph.add_host("test.example.com", "192.168.1.10")
        service_id = self.state_graph.add_service(host_id, 80, ServiceType.HTTP)

        self.state_graph.clear()

        self.assertEqual(len(self.state_graph.hosts), 0)
        self.assertEqual(len(self.state_graph.services), 0)
        self.assertEqual(len(self.state_graph.vulnerabilities), 0)
        self.assertEqual(len(self.state_graph.connections), 0)


if __name__ == "__main__":
    unittest.main()
