#!/usr/bin/env python3
"""
Test utilities for DragonShard.
Consolidates common test patterns, Docker container management, and shared test data.
"""

import functools
import logging
import os
import subprocess
import sys
import time
import unittest
from typing import Any, Dict, List, Optional, Set

import requests

# Set up logging
logger = logging.getLogger(__name__)


def setup_test_imports():
    """Add the parent directory to the path so we can import our modules."""
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


class TestTargets:
    """Common test targets used across multiple test files."""
    
    # Standard vulnerable application targets
    TARGETS = {
        "dvwa": "http://localhost:8080",
        "juice-shop": "http://localhost:3000", 
        "webgoat": "http://localhost:8081",
        "vuln-php": "http://localhost:8082",
        "vuln-node": "http://localhost:8083",
        "vuln-python": "http://localhost:8084",
    }
    
    # Targets that are known to have startup issues
    PROBLEMATIC_TARGETS = {'webgoat', 'vuln-python'}
    
    @classmethod
    def get_available_targets(cls, exclude_problematic: bool = True) -> Dict[str, str]:
        """Get available targets, optionally excluding problematic ones."""
        if exclude_problematic:
            return {k: v for k, v in cls.TARGETS.items() if k not in cls.PROBLEMATIC_TARGETS}
        return cls.TARGETS.copy()


class TestPayloads:
    """Common test payloads used across multiple test files."""
    
    # SQL Injection payloads
    SQL_PAYLOADS = [
        "1' OR '1'='1",
        "1' UNION SELECT 1,2,3--",
        "admin'--",
        "1' OR 1=1#",
        "1' OR 1=1/*",
        "'; DROP TABLE users;--",
        "1' AND (SELECT COUNT(*) FROM users)>0--",
        "1' AND (SELECT LENGTH(password) FROM users LIMIT 1)>5--",
    ]
    
    # XSS payloads
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')></iframe>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<details open ontoggle=alert('XSS')>",
    ]
    
    # Command Injection payloads
    COMMAND_PAYLOADS = [
        "127.0.0.1; ls",
        "127.0.0.1 && whoami",
        "127.0.0.1 | cat /etc/passwd",
        "127.0.0.1; id",
        "127.0.0.1 && pwd",
        "127.0.0.1 | uname -a",
        "127.0.0.1; cat /etc/hosts",
        "127.0.0.1 && ls -la",
    ]
    
    # Path Traversal payloads
    PATH_PAYLOADS = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "....//....//....//etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..%252F..%252F..%252Fetc%252Fpasswd",
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        "..%255c..%255c..%255cwindows%255csystem32%255cdrivers%255cetc%255chosts",
    ]
    
    # Basic test payloads
    BASIC_PAYLOADS = [
        "test1",
        "test2", 
        "test3",
        "admin",
        "password",
        "123456",
    ]
    
    @classmethod
    def get_payloads_by_type(cls, payload_type: str) -> List[str]:
        """Get payloads by type."""
        payload_map = {
            'sql': cls.SQL_PAYLOADS,
            'xss': cls.XSS_PAYLOADS,
            'command': cls.COMMAND_PAYLOADS,
            'path': cls.PATH_PAYLOADS,
            'basic': cls.BASIC_PAYLOADS,
        }
        return payload_map.get(payload_type, [])


class DockerContainerManager:
    """Manages Docker containers for integration tests."""
    
    def __init__(self):
        self.containers = []
    
    def wait_for_container_ready(self, container_name: str, max_wait: int = 60) -> bool:
        """
        Wait for a container to be ready by checking its status.

        Args:
            container_name: Name of the container to check
            max_wait: Maximum time to wait in seconds

        Returns:
            True if container is ready, False if timeout
        """
        logger.info(f"Waiting for container {container_name} to be ready...")

        start_time = time.time()
        while time.time() - start_time < max_wait:
            try:
                # Check if container is running
                result = subprocess.run(
                    ["docker", "inspect", "-f", "{{.State.Status}}", container_name],
                    capture_output=True,
                    text=True,
                    check=True,
                )

                status = result.stdout.strip()
                if status == "running":
                    # Check if container is healthy (if health check is configured)
                    try:
                        health_result = subprocess.run(
                            ["docker", "inspect", "-f", "{{.State.Health.Status}}", container_name],
                            capture_output=True,
                            text=True,
                            check=True,
                        )

                        health_status = health_result.stdout.strip()
                        if health_status == "healthy" or health_status == "<nil>":
                            logger.info(f"Container {container_name} is ready!")
                            return True
                        elif health_status == "unhealthy":
                            logger.error(f"Container {container_name} is unhealthy")
                            return False
                        else:
                            logger.info(f"Container {container_name} status: {health_status}")
                    except subprocess.CalledProcessError:
                        # No health check configured, assume ready if running
                        logger.info(f"Container {container_name} is ready (no health check)")
                        return True
                elif status == "exited":
                    logger.error(f"Container {container_name} has exited")
                    return False
                else:
                    logger.info(f"Container {container_name} status: {status}")

            except subprocess.CalledProcessError as e:
                logger.warning(f"Error checking container {container_name}: {e}")

            time.sleep(2)

        logger.error(f"Container {container_name} did not become ready within {max_wait} seconds")
        return False

    def check_container_health(self, container_name: str) -> bool:
        """
        Check if a container is healthy.

        Args:
            container_name: Name of the container to check

        Returns:
            True if container is healthy, False otherwise
        """
        try:
            result = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Health.Status}}", container_name],
                capture_output=True,
                text=True,
                check=True,
            )

            health_status = result.stdout.strip()
            return health_status == "healthy" or health_status == "<nil>"

        except subprocess.CalledProcessError:
            return False

    def start_dvwa_container(self) -> str:
        """Start a DVWA container for testing."""
        container_name = f"dvwa-test-{int(time.time())}"
        
        try:
            # Start DVWA container
            subprocess.run([
                "docker", "run", "-d",
                "--name", container_name,
                "-p", "8080:80",
                "vulnerables/web-dvwa"
            ], check=True, capture_output=True)
            
            self.containers.append(container_name)
            logger.info(f"Started DVWA container: {container_name}")
            
            # Wait for container to be ready
            if self.wait_for_container_ready(container_name):
                return container_name
            else:
                raise RuntimeError(f"DVWA container {container_name} failed to start properly")
                
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to start DVWA container: {e}")
            raise

    def cleanup_containers(self):
        """Clean up all managed containers."""
        for container_name in self.containers:
            try:
                subprocess.run(["docker", "stop", container_name], capture_output=True, timeout=10)
                subprocess.run(["docker", "rm", container_name], capture_output=True, timeout=10)
                logger.info(f"Cleaned up container: {container_name}")
            except Exception as e:
                logger.warning(f"Failed to clean up container {container_name}: {e}")


class TargetAvailabilityChecker:
    """Checks availability of test targets."""
    
    def __init__(self, targets: Optional[Dict[str, str]] = None):
        self.targets = targets or TestTargets.get_available_targets()
    
    def check_target_availability(self) -> Dict[str, bool]:
        """Check if all targets are available."""
        results = {}

        for name, url in self.targets.items():
            try:
                response = requests.get(url, timeout=5)
                results[name] = response.status_code == 200
                logger.info(f"✓ {name}: {url} - Available")
            except Exception as e:
                results[name] = False
                logger.warning(f"✗ {name}: {url} - Not available: {e}")

        return results
    
    def get_available_targets(self) -> Dict[str, str]:
        """Get only the available targets."""
        availability = self.check_target_availability()
        return {k: v for k, v in self.targets.items() if availability.get(k, False)}


def requires_nmap(func):
    """Decorator to check if nmap is available before running a test."""
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        try:
            subprocess.run(["nmap", "--version"], capture_output=True, check=True, timeout=5)
            logger.info("nmap is available")
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            logger.warning("nmap not available, skipping test")
            self.skipTest("nmap not available")
        return func(self, *args, **kwargs)
    return wrapper


class BaseTestCase(unittest.TestCase):
    """Base test case with common setup and utilities."""
    
    def setUp(self):
        """Set up test fixtures."""
        setup_test_imports()
        self.targets = TestTargets.get_available_targets()
        self.payloads = TestPayloads()
        self.container_manager = DockerContainerManager()
        self.target_checker = TargetAvailabilityChecker(self.targets)
    
    def tearDown(self):
        """Clean up after tests."""
        self.container_manager.cleanup_containers()
    
    def wait_for_target(self, url: str, timeout: int = 30) -> bool:
        """Wait for a target to become available."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    return True
            except Exception:
                pass
            time.sleep(1)
        return False 