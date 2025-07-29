#!/usr/bin/env python3
"""
Response Analyzer for Genetic Algorithm Reward Signals

This module analyzes HTTP responses to provide intelligent reward signals
for the genetic algorithm, focusing on response differentials and
anomaly detection.
"""

import re
import hashlib
import difflib
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ResponseType(Enum):
    """Types of response analysis."""
    NORMAL = "normal"
    ERROR = "error"
    ANOMALY = "anomaly"
    VULNERABILITY = "vulnerability"
    BLOCKED = "blocked"


@dataclass
class ResponseAnalysis:
    """Analysis result for a single response."""
    status_code: int
    response_time: float
    content_length: int
    content_hash: str
    response_type: ResponseType
    anomaly_score: float
    vulnerability_indicators: List[str]
    differential_score: float = 0.0
    baseline_deviation: float = 0.0


@dataclass
class ResponseDifferential:
    """Comparison between two responses."""
    baseline_response: ResponseAnalysis
    test_response: ResponseAnalysis
    similarity_score: float
    differential_indicators: List[str]
    reward_score: float


class ResponseAnalyzer:
    """Analyzes HTTP responses for genetic algorithm rewards."""
    
    def __init__(self):
        """Initialize the response analyzer."""
        self.baseline_responses: Dict[str, ResponseAnalysis] = {}
        self.response_history: List[ResponseAnalysis] = []
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        self.anomaly_thresholds = self._load_anomaly_thresholds()
    
    def _load_vulnerability_patterns(self) -> Dict[str, List[str]]:
        """Load patterns for vulnerability detection."""
        return {
            'sql_injection': [
                r'sql syntax.*error',
                r'mysql.*error',
                r'oracle.*error',
                r'postgresql.*error',
                r'sql.*exception',
                r'division by zero',
                r'column.*not found'
            ],
            'xss': [
                r'<script.*>.*</script>',
                r'javascript:',
                r'onload=',
                r'onerror=',
                r'alert\(',
                r'confirm\(',
                r'prompt\('
            ],
            'command_injection': [
                r'command.*not found',
                r'permission denied',
                r'access denied',
                r'cannot execute',
                r'exec.*failed'
            ],
            'path_traversal': [
                r'file.*not found',
                r'no such file',
                r'cannot open',
                r'access denied',
                r'permission denied'
            ],
            'lfi': [
                r'include.*failed',
                r'require.*failed',
                r'file.*not found',
                r'cannot open.*file'
            ],
            'xxe': [
                r'xml.*error',
                r'entity.*not found',
                r'xml.*parse.*error',
                r'external.*entity'
            ]
        }
    
    def _load_anomaly_thresholds(self) -> Dict[str, float]:
        """Load thresholds for anomaly detection."""
        return {
            'response_time_deviation': 2.0,  # 2x baseline
            'content_length_deviation': 0.5,  # 50% change
            'status_code_anomaly': 0.8,  # 80% different status codes
            'content_similarity_threshold': 0.3  # 30% similarity threshold
        }
    
    def analyze_response(self, 
                        status_code: int,
                        response_time: float,
                        content: str,
                        headers: Dict[str, str],
                        url: str) -> ResponseAnalysis:
        """Analyze a single HTTP response."""
        
        # Calculate content hash for comparison
        content_hash = hashlib.md5(content.encode()).hexdigest()
        
        # Detect vulnerability indicators
        vulnerability_indicators = self._detect_vulnerabilities(content)
        
        # Determine response type
        response_type = self._classify_response(status_code, vulnerability_indicators)
        
        # Calculate anomaly score
        anomaly_score = self._calculate_anomaly_score(status_code, response_time, len(content))
        
        # Calculate baseline deviation if baseline exists
        baseline_deviation = 0.0
        if url in self.baseline_responses:
            baseline = self.baseline_responses[url]
            baseline_deviation = self._calculate_baseline_deviation(
                status_code, response_time, len(content), baseline
            )
        
        return ResponseAnalysis(
            status_code=status_code,
            response_time=response_time,
            content_length=len(content),
            content_hash=content_hash,
            response_type=response_type,
            anomaly_score=anomaly_score,
            vulnerability_indicators=vulnerability_indicators,
            baseline_deviation=baseline_deviation
        )
    
    def _detect_vulnerabilities(self, content: str) -> List[str]:
        """Detect vulnerability indicators in response content."""
        indicators = []
        content_lower = content.lower()
        
        for vuln_type, patterns in self.vulnerability_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    indicators.append(f"{vuln_type}:{pattern}")
        
        return indicators
    
    def _classify_response(self, status_code: int, vulnerability_indicators: List[str]) -> ResponseType:
        """Classify the response type based on status code and indicators."""
        if vulnerability_indicators:
            return ResponseType.VULNERABILITY
        elif status_code >= 500:
            return ResponseType.ERROR
        elif status_code == 403:
            return ResponseType.BLOCKED
        elif status_code >= 400:
            return ResponseType.ANOMALY
        else:
            return ResponseType.NORMAL
    
    def _calculate_anomaly_score(self, status_code: int, response_time: float, content_length: int) -> float:
        """Calculate anomaly score based on response characteristics."""
        score = 0.0
        
        # Status code anomalies
        if status_code >= 500:
            score += 0.8
        elif status_code >= 400:
            score += 0.4
        
        # Response time anomalies (if we have baseline)
        if self.response_history:
            avg_time = sum(r.response_time for r in self.response_history) / len(self.response_history)
            if response_time > avg_time * self.anomaly_thresholds['response_time_deviation']:
                score += 0.6
        
        # Content length anomalies
        if self.response_history:
            avg_length = sum(r.content_length for r in self.response_history) / len(self.response_history)
            if abs(content_length - avg_length) / avg_length > self.anomaly_thresholds['content_length_deviation']:
                score += 0.5
        
        return min(1.0, score)
    
    def _calculate_baseline_deviation(self, status_code: int, response_time: float, 
                                    content_length: int, baseline: ResponseAnalysis) -> float:
        """Calculate deviation from baseline response."""
        deviations = []
        
        # Status code deviation
        if status_code != baseline.status_code:
            deviations.append(1.0)
        
        # Response time deviation
        if baseline.response_time > 0:
            time_deviation = abs(response_time - baseline.response_time) / baseline.response_time
            deviations.append(min(1.0, time_deviation))
        
        # Content length deviation
        if baseline.content_length > 0:
            length_deviation = abs(content_length - baseline.content_length) / baseline.content_length
            deviations.append(min(1.0, length_deviation))
        
        return sum(deviations) / len(deviations) if deviations else 0.0
    
    def set_baseline(self, url: str, response_analysis: ResponseAnalysis) -> None:
        """Set a baseline response for a URL."""
        self.baseline_responses[url] = response_analysis
        logger.info(f"Set baseline for {url}")
    
    def compare_responses(self, baseline: ResponseAnalysis, test: ResponseAnalysis) -> ResponseDifferential:
        """Compare two responses and calculate differential."""
        
        # Calculate similarity score
        similarity_score = self._calculate_similarity(baseline, test)
        
        # Find differential indicators
        differential_indicators = self._find_differential_indicators(baseline, test)
        
        # Calculate reward score
        reward_score = self._calculate_reward_score(baseline, test, differential_indicators)
        
        return ResponseDifferential(
            baseline_response=baseline,
            test_response=test,
            similarity_score=similarity_score,
            differential_indicators=differential_indicators,
            reward_score=reward_score
        )
    
    def _calculate_similarity(self, baseline: ResponseAnalysis, test: ResponseAnalysis) -> float:
        """Calculate similarity between two responses."""
        similarities = []
        
        # Status code similarity
        if baseline.status_code == test.status_code:
            similarities.append(1.0)
        else:
            similarities.append(0.0)
        
        # Content hash similarity
        if baseline.content_hash == test.content_hash:
            similarities.append(1.0)
        else:
            similarities.append(0.0)
        
        # Response time similarity (within 20% threshold)
        if baseline.response_time > 0:
            time_diff = abs(test.response_time - baseline.response_time) / baseline.response_time
            similarities.append(1.0 - min(1.0, time_diff))
        
        # Content length similarity (within 30% threshold)
        if baseline.content_length > 0:
            length_diff = abs(test.content_length - baseline.content_length) / baseline.content_length
            similarities.append(1.0 - min(1.0, length_diff))
        
        return sum(similarities) / len(similarities)
    
    def _find_differential_indicators(self, baseline: ResponseAnalysis, test: ResponseAnalysis) -> List[str]:
        """Find indicators of differences between responses."""
        indicators = []
        
        # Status code differences
        if baseline.status_code != test.status_code:
            indicators.append(f"status_code_change:{baseline.status_code}->{test.status_code}")
        
        # Response time differences
        if abs(test.response_time - baseline.response_time) > baseline.response_time * 0.2:
            indicators.append("response_time_anomaly")
        
        # Content length differences
        if abs(test.content_length - baseline.content_length) > baseline.content_length * 0.3:
            indicators.append("content_length_anomaly")
        
        # Vulnerability indicators
        if test.vulnerability_indicators and not baseline.vulnerability_indicators:
            indicators.append("vulnerability_detected")
        
        # Response type changes
        if baseline.response_type != test.response_type:
            indicators.append(f"response_type_change:{baseline.response_type.value}->{test.response_type.value}")
        
        return indicators
    
    def _calculate_reward_score(self, baseline: ResponseAnalysis, test: ResponseAnalysis, 
                              differential_indicators: List[str]) -> float:
        """Calculate reward score based on differential analysis."""
        score = 0.0
        
        # High reward for vulnerability detection
        if "vulnerability_detected" in differential_indicators:
            score += 0.9
        
        # Reward for server errors (potential vulnerabilities)
        if test.status_code >= 500:
            score += 0.7
        
        # Reward for response time anomalies (potential injection)
        if "response_time_anomaly" in differential_indicators:
            score += 0.6
        
        # Reward for content length anomalies (potential data leakage)
        if "content_length_anomaly" in differential_indicators:
            score += 0.5
        
        # Reward for status code changes (different behavior)
        if any("status_code_change" in indicator for indicator in differential_indicators):
            score += 0.4
        
        # Penalty for WAF blocks (payload was detected)
        if test.status_code == 403:
            score -= 0.3
        
        # Penalty for no change (payload had no effect)
        if not differential_indicators:
            score -= 0.2
        
        return max(0.0, min(1.0, score))
    
    def add_to_history(self, response_analysis: ResponseAnalysis) -> None:
        """Add response to history for statistical analysis."""
        self.response_history.append(response_analysis)
        
        # Keep only last 100 responses to avoid memory bloat
        if len(self.response_history) > 100:
            self.response_history = self.response_history[-100:]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistical analysis of response history."""
        if not self.response_history:
            return {}
        
        return {
            'total_responses': len(self.response_history),
            'avg_response_time': sum(r.response_time for r in self.response_history) / len(self.response_history),
            'avg_content_length': sum(r.content_length for r in self.response_history) / len(self.response_history),
            'vulnerability_rate': len([r for r in self.response_history if r.vulnerability_indicators]) / len(self.response_history),
            'error_rate': len([r for r in self.response_history if r.status_code >= 400]) / len(self.response_history)
        }
    