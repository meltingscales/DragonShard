#!/usr/bin/env python3
"""
DragonShard Attack Strategies Module

Provides predefined attack strategies and templates for different
vulnerability types and attack scenarios.
"""

import json
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

from .chain_planner import AttackType, AttackComplexity, AttackImpact, AttackStep, AttackChain

logger = logging.getLogger(__name__)


class StrategyType(Enum):
    """Types of attack strategies."""
    WEB_APPLICATION = "web_application"
    API_ATTACK = "api_attack"
    NETWORK_PENETRATION = "network_penetration"
    SOCIAL_ENGINEERING = "social_engineering"
    PHYSICAL_ACCESS = "physical_access"
    WIRELESS_ATTACK = "wireless_attack"


@dataclass
class AttackStrategy:
    """Represents a predefined attack strategy."""
    strategy_id: str
    name: str
    description: str
    strategy_type: StrategyType
    target_scope: List[str]
    prerequisites: List[str]
    attack_steps: List[Dict[str, Any]]
    success_criteria: List[str]
    risk_level: AttackComplexity
    estimated_duration: int  # minutes
    required_tools: List[str]
    mitigation_strategies: List[str]


class AttackStrategies:
    """Collection of predefined attack strategies."""

    def __init__(self):
        """Initialize attack strategies."""
        self.strategies = self._load_strategies()
        logger.info(f"Loaded {len(self.strategies)} attack strategies")

    def _load_strategies(self) -> Dict[str, AttackStrategy]:
        """Load predefined attack strategies."""
        strategies = {
            "web_app_comprehensive": AttackStrategy(
                strategy_id="web_app_comprehensive",
                name="Comprehensive Web Application Attack",
                description="Full web application penetration testing strategy",
                strategy_type=StrategyType.WEB_APPLICATION,
                target_scope=["web_applications", "apis", "authentication"],
                prerequisites=["target_identification", "scope_definition"],
                attack_steps=[
                    {
                        "step_id": "reconnaissance",
                        "name": "Information Gathering",
                        "description": "Collect information about the target application",
                        "duration": 30,
                        "tools": ["browser", "curl", "nmap"]
                    },
                    {
                        "step_id": "enumeration",
                        "name": "Endpoint Discovery",
                        "description": "Discover all accessible endpoints and parameters",
                        "duration": 45,
                        "tools": ["crawler", "dirb", "burp_suite"]
                    },
                    {
                        "step_id": "vulnerability_scanning",
                        "name": "Vulnerability Assessment",
                        "description": "Identify potential vulnerabilities",
                        "duration": 60,
                        "tools": ["fuzzer", "scanner", "manual_testing"]
                    },
                    {
                        "step_id": "exploitation",
                        "name": "Vulnerability Exploitation",
                        "description": "Exploit discovered vulnerabilities",
                        "duration": 90,
                        "tools": ["custom_payloads", "exploit_frameworks"]
                    },
                    {
                        "step_id": "post_exploitation",
                        "name": "Post-Exploitation",
                        "description": "Maintain access and gather additional information",
                        "duration": 120,
                        "tools": ["shell", "data_exfiltration_tools"]
                    }
                ],
                success_criteria=[
                    "All endpoints discovered and tested",
                    "Vulnerabilities identified and exploited",
                    "Access maintained and documented",
                    "Comprehensive report generated"
                ],
                risk_level=AttackComplexity.HIGH,
                estimated_duration=345,  # 5 hours 45 minutes
                required_tools=["nmap", "burp_suite", "custom_scripts", "reporting_tools"],
                mitigation_strategies=[
                    "Implement comprehensive input validation",
                    "Use secure coding practices",
                    "Regular security assessments",
                    "Implement defense in depth"
                ]
            ),
            "sql_injection_chain": AttackStrategy(
                strategy_id="sql_injection_chain",
                name="SQL Injection Attack Chain",
                description="Specialized strategy for SQL injection vulnerabilities",
                strategy_type=StrategyType.WEB_APPLICATION,
                target_scope=["databases", "web_applications"],
                prerequisites=["sql_injection_vulnerability_identified"],
                attack_steps=[
                    {
                        "step_id": "vulnerability_confirmation",
                        "name": "Confirm SQL Injection",
                        "description": "Verify SQL injection vulnerability exists",
                        "duration": 15,
                        "tools": ["sqlmap", "manual_testing"]
                    },
                    {
                        "step_id": "database_enumeration",
                        "name": "Database Enumeration",
                        "description": "Enumerate database structure and contents",
                        "duration": 30,
                        "tools": ["sqlmap", "custom_queries"]
                    },
                    {
                        "step_id": "data_extraction",
                        "name": "Data Extraction",
                        "description": "Extract sensitive data from database",
                        "duration": 45,
                        "tools": ["sqlmap", "custom_scripts"]
                    },
                    {
                        "step_id": "privilege_escalation",
                        "name": "Privilege Escalation",
                        "description": "Attempt to gain elevated database privileges",
                        "duration": 60,
                        "tools": ["custom_queries", "exploit_techniques"]
                    }
                ],
                success_criteria=[
                    "SQL injection vulnerability confirmed",
                    "Database structure enumerated",
                    "Sensitive data extracted",
                    "Privilege escalation achieved"
                ],
                risk_level=AttackComplexity.MEDIUM,
                estimated_duration=150,  # 2 hours 30 minutes
                required_tools=["sqlmap", "custom_scripts", "database_tools"],
                mitigation_strategies=[
                    "Use parameterized queries",
                    "Implement input validation",
                    "Apply principle of least privilege",
                    "Regular security testing"
                ]
            ),
            "xss_attack_chain": AttackStrategy(
                strategy_id="xss_attack_chain",
                name="Cross-Site Scripting Attack Chain",
                description="Specialized strategy for XSS vulnerabilities",
                strategy_type=StrategyType.WEB_APPLICATION,
                target_scope=["web_applications", "user_sessions"],
                prerequisites=["xss_vulnerability_identified"],
                attack_steps=[
                    {
                        "step_id": "payload_development",
                        "name": "Payload Development",
                        "description": "Develop effective XSS payloads",
                        "duration": 20,
                        "tools": ["payload_generators", "manual_testing"]
                    },
                    {
                        "step_id": "session_hijacking",
                        "name": "Session Hijacking",
                        "description": "Attempt to hijack user sessions",
                        "duration": 30,
                        "tools": ["custom_scripts", "session_analysis"]
                    },
                    {
                        "step_id": "data_exfiltration",
                        "name": "Data Exfiltration",
                        "description": "Extract sensitive data via XSS",
                        "duration": 40,
                        "tools": ["custom_payloads", "data_collection"]
                    }
                ],
                success_criteria=[
                    "XSS vulnerability confirmed",
                    "Session hijacking successful",
                    "Data exfiltration achieved"
                ],
                risk_level=AttackComplexity.LOW,
                estimated_duration=90,  # 1 hour 30 minutes
                required_tools=["payload_generators", "session_analysis_tools"],
                mitigation_strategies=[
                    "Implement output encoding",
                    "Use Content Security Policy",
                    "Input validation and sanitization",
                    "Regular security assessments"
                ]
            ),
            "rce_attack_chain": AttackStrategy(
                strategy_id="rce_attack_chain",
                name="Remote Code Execution Attack Chain",
                description="Specialized strategy for command injection vulnerabilities",
                strategy_type=StrategyType.WEB_APPLICATION,
                target_scope=["servers", "applications"],
                prerequisites=["command_injection_vulnerability_identified"],
                attack_steps=[
                    {
                        "step_id": "vulnerability_confirmation",
                        "name": "Confirm Command Injection",
                        "description": "Verify command injection vulnerability",
                        "duration": 20,
                        "tools": ["manual_testing", "payload_generators"]
                    },
                    {
                        "step_id": "shell_establishment",
                        "name": "Shell Establishment",
                        "description": "Establish reverse shell connection",
                        "duration": 30,
                        "tools": ["netcat", "custom_payloads"]
                    },
                    {
                        "step_id": "privilege_escalation",
                        "name": "Privilege Escalation",
                        "description": "Attempt to gain elevated system privileges",
                        "duration": 60,
                        "tools": ["exploit_frameworks", "manual_techniques"]
                    },
                    {
                        "step_id": "persistence",
                        "name": "Persistence Establishment",
                        "description": "Establish persistent access to the system",
                        "duration": 45,
                        "tools": ["custom_scripts", "system_tools"]
                    }
                ],
                success_criteria=[
                    "Command injection confirmed",
                    "Reverse shell established",
                    "Privilege escalation achieved",
                    "Persistent access maintained"
                ],
                risk_level=AttackComplexity.HIGH,
                estimated_duration=155,  # 2 hours 35 minutes
                required_tools=["netcat", "exploit_frameworks", "custom_scripts"],
                mitigation_strategies=[
                    "Avoid command execution",
                    "Implement proper input validation",
                    "Use secure coding practices",
                    "Regular security monitoring"
                ]
            ),
            "api_attack_chain": AttackStrategy(
                strategy_id="api_attack_chain",
                name="API Attack Chain",
                description="Specialized strategy for API endpoint testing",
                strategy_type=StrategyType.API_ATTACK,
                target_scope=["apis", "web_services"],
                prerequisites=["api_endpoints_identified"],
                attack_steps=[
                    {
                        "step_id": "endpoint_discovery",
                        "name": "API Endpoint Discovery",
                        "description": "Discover all API endpoints and methods",
                        "duration": 30,
                        "tools": ["crawler", "manual_testing", "documentation"]
                    },
                    {
                        "step_id": "authentication_bypass",
                        "name": "Authentication Bypass",
                        "description": "Attempt to bypass API authentication",
                        "duration": 45,
                        "tools": ["custom_scripts", "manual_testing"]
                    },
                    {
                        "step_id": "data_extraction",
                        "name": "Data Extraction",
                        "description": "Extract sensitive data from API endpoints",
                        "duration": 60,
                        "tools": ["custom_scripts", "data_analysis"]
                    },
                    {
                        "step_id": "privilege_escalation",
                        "name": "Privilege Escalation",
                        "description": "Attempt to gain elevated API privileges",
                        "duration": 45,
                        "tools": ["custom_scripts", "manual_techniques"]
                    }
                ],
                success_criteria=[
                    "All API endpoints discovered",
                    "Authentication bypassed",
                    "Sensitive data extracted",
                    "Elevated privileges obtained"
                ],
                risk_level=AttackComplexity.MEDIUM,
                estimated_duration=180,  # 3 hours
                required_tools=["custom_scripts", "api_testing_tools", "data_analysis"],
                mitigation_strategies=[
                    "Implement proper authentication",
                    "Use API security best practices",
                    "Regular security testing",
                    "Implement rate limiting"
                ]
            )
        }
        return strategies

    def get_strategy(self, strategy_id: str) -> Optional[AttackStrategy]:
        """
        Get a specific attack strategy.

        Args:
            strategy_id: The strategy identifier

        Returns:
            AttackStrategy object or None if not found
        """
        return self.strategies.get(strategy_id)

    def get_strategies_by_type(self, strategy_type: StrategyType) -> List[AttackStrategy]:
        """
        Get all strategies of a specific type.

        Args:
            strategy_type: The strategy type

        Returns:
            List of AttackStrategy objects
        """
        return [s for s in self.strategies.values() if s.strategy_type == strategy_type]

    def get_strategies_for_vulnerability(self, vulnerability_type: AttackType) -> List[AttackStrategy]:
        """
        Get strategies suitable for a specific vulnerability type.

        Args:
            vulnerability_type: The vulnerability type

        Returns:
            List of suitable AttackStrategy objects
        """
        # Map vulnerability types to strategy IDs
        vulnerability_strategy_map = {
            AttackType.SQL_INJECTION: ["sql_injection_chain"],
            AttackType.XSS: ["xss_attack_chain"],
            AttackType.COMMAND_INJECTION: ["rce_attack_chain"],
            AttackType.AUTHENTICATION_BYPASS: ["api_attack_chain"],
        }

        strategy_ids = vulnerability_strategy_map.get(vulnerability_type, [])
        return [self.strategies[sid] for sid in strategy_ids if sid in self.strategies]

    def convert_strategy_to_chain(self, strategy: AttackStrategy, target_host: str, 
                                 vulnerabilities: List[Any]) -> AttackChain:
        """
        Convert an attack strategy to an attack chain.

        Args:
            strategy: The attack strategy
            target_host: The target host
            vulnerabilities: List of discovered vulnerabilities

        Returns:
            AttackChain object
        """
        # Convert strategy steps to attack steps
        attack_steps = []
        for i, step in enumerate(strategy.attack_steps):
            attack_step = AttackStep(
                step_id=step["step_id"],
                step_name=step["name"],
                attack_type=AttackType.SQL_INJECTION,  # Default, should be determined by context
                target_url=target_host,
                payload="",  # Should be populated based on vulnerabilities
                expected_outcome=step["description"],
                success_criteria=f"Step {step['step_id']} completed successfully",
                dependencies=[s["step_id"] for s in strategy.attack_steps[:i]],
                estimated_time=step["duration"] * 60  # Convert to seconds
            )
            attack_steps.append(attack_step)

        # Calculate success probability based on vulnerabilities
        success_probability = min(0.9, len(vulnerabilities) * 0.2)

        chain = AttackChain(
            chain_id=f"{strategy.strategy_id}_chain",
            chain_name=f"{strategy.name} - {target_host}",
            description=strategy.description,
            target_host=target_host,
            attack_steps=attack_steps,
            total_impact=AttackImpact.HIGH,  # Should be calculated based on vulnerabilities
            total_complexity=strategy.risk_level,
            success_probability=success_probability,
            estimated_duration=strategy.estimated_duration * 60,  # Convert to seconds
            risk_assessment=f"Risk level: {strategy.risk_level.value}",
            mitigation_strategies=strategy.mitigation_strategies
        )

        return chain

    def get_all_strategies(self) -> List[AttackStrategy]:
        """
        Get all available attack strategies.

        Returns:
            List of all AttackStrategy objects
        """
        return list(self.strategies.values())

    def export_strategies(self, filename: str) -> None:
        """
        Export all strategies to a JSON file.

        Args:
            filename: Output filename
        """
        data = {
            "strategies": [
                {
                    "strategy_id": s.strategy_id,
                    "name": s.name,
                    "description": s.description,
                    "strategy_type": s.strategy_type.value,
                    "target_scope": s.target_scope,
                    "prerequisites": s.prerequisites,
                    "attack_steps": s.attack_steps,
                    "success_criteria": s.success_criteria,
                    "risk_level": s.risk_level.value,
                    "estimated_duration": s.estimated_duration,
                    "required_tools": s.required_tools,
                    "mitigation_strategies": s.mitigation_strategies
                }
                for s in self.strategies.values()
            ]
        }

        with open(filename, "w") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Exported {len(self.strategies)} strategies to {filename}")


if __name__ == "__main__":
    # Example usage
    import logging
    logging.basicConfig(level=logging.INFO)

    # Initialize attack strategies
    strategies = AttackStrategies()

    # Get all strategies
    all_strategies = strategies.get_all_strategies()
    print(f"Available strategies: {len(all_strategies)}")

    for strategy in all_strategies:
        print(f"- {strategy.name}: {strategy.description}")

    # Get strategies for SQL injection
    sql_strategies = strategies.get_strategies_for_vulnerability(AttackType.SQL_INJECTION)
    print(f"\nSQL Injection strategies: {len(sql_strategies)}")

    # Export strategies
    strategies.export_strategies("attack_strategies.json") 