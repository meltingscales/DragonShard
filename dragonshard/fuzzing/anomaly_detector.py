"""
DragonShard Anomaly Detector Module

Detects unusual responses and potential vulnerabilities.
"""

import re
import statistics
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class AnomalyResult:
    """Result of anomaly detection."""
    is_anomaly: bool
    anomaly_type: Optional[str]
    confidence: float
    evidence: Optional[str]
    severity: str  # low, medium, high, critical


class AnomalyDetector:
    """
    Detects anomalies in HTTP responses that might indicate vulnerabilities.
    """
    
    def __init__(self):
        """Initialize the anomaly detector."""
        self.baseline_stats = {}
        self.response_patterns = self._load_response_patterns()
        
    def _load_response_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load response patterns for anomaly detection."""
        return {
            "error_patterns": {
                "sql_errors": [
                    r"sql syntax.*mysql",
                    r"mysql.*error",
                    r"oracle.*error",
                    r"postgresql.*error",
                    r"sqlite.*error",
                    r"syntax error",
                    r"unclosed quotation mark",
                    r"quoted string",
                    r"mysql_fetch_array",
                    r"mysql_fetch_object",
                    r"mysql_num_rows"
                ],
                "xss_indicators": [
                    r"<script",
                    r"javascript:",
                    r"onerror",
                    r"onload",
                    r"onclick",
                    r"alert\(",
                    r"confirm\(",
                    r"prompt\(",
                    r"eval\("
                ],
                "command_injection": [
                    r"root:",
                    r"uid=\d+",
                    r"gid=\d+",
                    r"groups=",
                    r"total \d+",
                    r"drwx",
                    r"ls -la",
                    r"whoami",
                    r"id",
                    r"pwd",
                    r"uname",
                    r"cat "
                ],
                "path_traversal": [
                    r"root:x:",
                    r"bin:x:",
                    r"daemon:x:",
                    r"sys:x:",
                    r"sync:x:",
                    r"games:x:",
                    r"man:x:",
                    r"lp:x:",
                    r"mail:x:",
                    r"news:x:",
                    r"uucp:x:",
                    r"proxy:x:",
                    r"www-data:x:",
                    r"backup:x:",
                    r"list:x:",
                    r"irc:x:",
                    r"gnats:x:",
                    r"nobody:x:",
                    r"systemd-network:x:"
                ],
                "server_errors": [
                    r"internal server error",
                    r"500 internal server error",
                    r"server error",
                    r"application error",
                    r"runtime error",
                    r"fatal error",
                    r"exception",
                    r"stack trace"
                ]
            },
            "size_thresholds": {
                "very_small": 100,
                "small": 500,
                "large": 10000,
                "very_large": 50000
            },
            "status_codes": {
                "error_codes": [400, 401, 403, 404, 500, 501, 502, 503, 504],
                "success_codes": [200, 201, 202, 204],
                "redirect_codes": [301, 302, 303, 307, 308]
            }
        }
    
    def detect_anomalies(self, response_text: str, response_headers: Dict[str, str],
                         status_code: int, response_size: int, 
                         baseline_response: Optional[Dict] = None) -> List[AnomalyResult]:
        """
        Detect anomalies in the response.
        
        Args:
            response_text: Response body text
            response_headers: Response headers
            status_code: HTTP status code
            response_size: Size of response in bytes
            baseline_response: Baseline response for comparison
            
        Returns:
            List of AnomalyResult objects
        """
        anomalies = []
        
        # Check for error patterns
        error_anomalies = self._detect_error_patterns(response_text)
        anomalies.extend(error_anomalies)
        
        # Check for size anomalies
        size_anomalies = self._detect_size_anomalies(response_size, baseline_response)
        anomalies.extend(size_anomalies)
        
        # Check for status code anomalies
        status_anomalies = self._detect_status_anomalies(status_code, baseline_response)
        anomalies.extend(status_anomalies)
        
        # Check for timing anomalies
        timing_anomalies = self._detect_timing_anomalies(response_headers, baseline_response)
        anomalies.extend(timing_anomalies)
        
        # Check for content anomalies
        content_anomalies = self._detect_content_anomalies(response_text, baseline_response)
        anomalies.extend(content_anomalies)
        
        return anomalies
    
    def _detect_error_patterns(self, response_text: str) -> List[AnomalyResult]:
        """Detect error patterns in response text."""
        anomalies = []
        response_lower = response_text.lower()
        
        for error_type, patterns in self.response_patterns["error_patterns"].items():
            for pattern in patterns:
                if re.search(pattern, response_lower, re.IGNORECASE):
                    confidence = 0.9 if error_type in ["sql_errors", "command_injection"] else 0.7
                    severity = "high" if error_type in ["sql_errors", "command_injection"] else "medium"
                    
                    anomalies.append(AnomalyResult(
                        is_anomaly=True,
                        anomaly_type=f"{error_type}_detected",
                        confidence=confidence,
                        evidence=f"Pattern matched: {pattern}",
                        severity=severity
                    ))
        
        return anomalies
    
    def _detect_size_anomalies(self, response_size: int, 
                              baseline_response: Optional[Dict]) -> List[AnomalyResult]:
        """Detect size-based anomalies."""
        anomalies = []
        thresholds = self.response_patterns["size_thresholds"]
        
        # Check against thresholds
        if response_size < thresholds["very_small"]:
            anomalies.append(AnomalyResult(
                is_anomaly=True,
                anomaly_type="very_small_response",
                confidence=0.6,
                evidence=f"Response size ({response_size} bytes) is very small",
                severity="medium"
            ))
        elif response_size > thresholds["very_large"]:
            anomalies.append(AnomalyResult(
                is_anomaly=True,
                anomaly_type="very_large_response",
                confidence=0.7,
                evidence=f"Response size ({response_size} bytes) is very large - possible data leakage",
                severity="high"
            ))
        
        # Compare with baseline if available
        if baseline_response and "response_size" in baseline_response:
            baseline_size = baseline_response["response_size"]
            size_ratio = response_size / baseline_size if baseline_size > 0 else 1
            
            if size_ratio > 5:
                anomalies.append(AnomalyResult(
                    is_anomaly=True,
                    anomaly_type="size_increase",
                    confidence=0.8,
                    evidence=f"Response size increased by {size_ratio:.1f}x",
                    severity="high"
                ))
            elif size_ratio < 0.2:
                anomalies.append(AnomalyResult(
                    is_anomaly=True,
                    anomaly_type="size_decrease",
                    confidence=0.6,
                    evidence=f"Response size decreased by {1/size_ratio:.1f}x",
                    severity="medium"
                ))
        
        return anomalies
    
    def _detect_status_anomalies(self, status_code: int, 
                                baseline_response: Optional[Dict]) -> List[AnomalyResult]:
        """Detect status code anomalies."""
        anomalies = []
        status_codes = self.response_patterns["status_codes"]
        
        # Check for error status codes
        if status_code in status_codes["error_codes"]:
            severity = "critical" if status_code >= 500 else "high"
            anomalies.append(AnomalyResult(
                is_anomaly=True,
                anomaly_type="error_status_code",
                confidence=0.8,
                evidence=f"HTTP {status_code} error status code",
                severity=severity
            ))
        
        # Compare with baseline
        if baseline_response and "status_code" in baseline_response:
            baseline_status = baseline_response["status_code"]
            if status_code != baseline_status:
                severity = "high" if status_code >= 500 else "medium"
                anomalies.append(AnomalyResult(
                    is_anomaly=True,
                    anomaly_type="status_code_change",
                    confidence=0.7,
                    evidence=f"Status code changed from {baseline_status} to {status_code}",
                    severity=severity
                ))
        
        return anomalies
    
    def _detect_timing_anomalies(self, response_headers: Dict[str, str],
                                baseline_response: Optional[Dict]) -> List[AnomalyResult]:
        """Detect timing-based anomalies."""
        anomalies = []
        
        # Check for unusual response times in headers
        if "x-response-time" in response_headers:
            try:
                response_time = float(response_headers["x-response-time"])
                if response_time > 5.0:  # More than 5 seconds
                    anomalies.append(AnomalyResult(
                        is_anomaly=True,
                        anomaly_type="slow_response",
                        confidence=0.7,
                        evidence=f"Slow response time: {response_time}s",
                        severity="medium"
                    ))
            except ValueError:
                pass
        
        return anomalies
    
    def _detect_content_anomalies(self, response_text: str, 
                                 baseline_response: Optional[Dict]) -> List[AnomalyResult]:
        """Detect content-based anomalies."""
        anomalies = []
        
        # Check for empty responses
        if not response_text.strip():
            anomalies.append(AnomalyResult(
                is_anomaly=True,
                anomaly_type="empty_response",
                confidence=0.6,
                evidence="Empty response body",
                severity="medium"
            ))
        
        # Check for unusual content types
        if "<?xml" in response_text and "xml" not in response_text.lower():
            anomalies.append(AnomalyResult(
                is_anomaly=True,
                anomaly_type="xml_content",
                confidence=0.5,
                evidence="XML content detected",
                severity="low"
            ))
        
        # Check for debug information
        debug_indicators = [
            "debug", "stack trace", "exception", "error", "warning",
            "notice", "deprecated", "undefined", "null pointer"
        ]
        
        for indicator in debug_indicators:
            if indicator in response_text.lower():
                anomalies.append(AnomalyResult(
                    is_anomaly=True,
                    anomaly_type="debug_info",
                    confidence=0.8,
                    evidence=f"Debug information found: {indicator}",
                    severity="high"
                ))
        
        return anomalies
    
    def analyze_response_set(self, responses: List[Dict]) -> Dict[str, Any]:
        """
        Analyze a set of responses to establish baseline and detect patterns.
        
        Args:
            responses: List of response dictionaries
            
        Returns:
            Analysis results
        """
        if not responses:
            return {}
        
        # Calculate baseline statistics
        status_codes = [r.get("status_code", 0) for r in responses]
        response_sizes = [r.get("response_size", 0) for r in responses]
        response_times = [r.get("response_time", 0) for r in responses]
        
        analysis = {
            "total_responses": len(responses),
            "status_code_stats": {
                "mean": statistics.mean(status_codes) if status_codes else 0,
                "median": statistics.median(status_codes) if status_codes else 0,
                "mode": statistics.mode(status_codes) if status_codes else 0,
                "std_dev": statistics.stdev(status_codes) if len(status_codes) > 1 else 0
            },
            "size_stats": {
                "mean": statistics.mean(response_sizes) if response_sizes else 0,
                "median": statistics.median(response_sizes) if response_sizes else 0,
                "std_dev": statistics.stdev(response_sizes) if len(response_sizes) > 1 else 0
            },
            "timing_stats": {
                "mean": statistics.mean(response_times) if response_times else 0,
                "median": statistics.median(response_times) if response_times else 0,
                "std_dev": statistics.stdev(response_times) if len(response_times) > 1 else 0
            },
            "anomaly_count": 0,
            "vulnerability_indicators": []
        }
        
        # Detect anomalies in each response
        for response in responses:
            anomalies = self.detect_anomalies(
                response.get("response_body", ""),
                response.get("response_headers", {}),
                response.get("status_code", 0),
                response.get("response_size", 0)
            )
            
            analysis["anomaly_count"] += len([a for a in anomalies if a.is_anomaly])
            
            # Collect vulnerability indicators
            for anomaly in anomalies:
                if anomaly.is_anomaly and anomaly.confidence > 0.7:
                    analysis["vulnerability_indicators"].append({
                        "type": anomaly.anomaly_type,
                        "confidence": anomaly.confidence,
                        "evidence": anomaly.evidence,
                        "severity": anomaly.severity
                    })
        
        return analysis
    
    def get_risk_score(self, anomalies: List[AnomalyResult]) -> float:
        """
        Calculate a risk score based on detected anomalies.
        
        Args:
            anomalies: List of AnomalyResult objects
            
        Returns:
            Risk score between 0.0 and 1.0
        """
        if not anomalies:
            return 0.0
        
        severity_weights = {
            "low": 0.1,
            "medium": 0.3,
            "high": 0.6,
            "critical": 1.0
        }
        
        total_score = 0.0
        total_weight = 0.0
        
        for anomaly in anomalies:
            if anomaly.is_anomaly:
                weight = severity_weights.get(anomaly.severity, 0.3)
                score = anomaly.confidence * weight
                total_score += score
                total_weight += weight
        
        return total_score / total_weight if total_weight > 0 else 0.0


if __name__ == "__main__":
    # Example usage
    detector = AnomalyDetector()
    
    # Test anomaly detection
    test_response = {
        "response_body": "You have an error in your SQL syntax",
        "response_headers": {"content-type": "text/html"},
        "status_code": 500,
        "response_size": 15000
    }
    
    anomalies = detector.detect_anomalies(
        test_response["response_body"],
        test_response["response_headers"],
        test_response["status_code"],
        test_response["response_size"]
    )
    
    print(f"Detected {len(anomalies)} anomalies")
    for anomaly in anomalies:
        print(f"- {anomaly.anomaly_type}: {anomaly.evidence} (confidence: {anomaly.confidence})")
    
    risk_score = detector.get_risk_score(anomalies)
    print(f"Risk score: {risk_score:.2f}") 