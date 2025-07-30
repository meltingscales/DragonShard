#!/usr/bin/env python3
"""
Utility functions for DragonShard.
Consolidates common utility functions used across the codebase.
"""

import hashlib
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
from urllib.parse import urljoin, urlparse

import requests

logger = logging.getLogger(__name__)


class URLUtils:
    """URL manipulation and validation utilities."""

    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Check if a URL is valid."""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False

    @staticmethod
    def normalize_url(url: str, base_url: Optional[str] = None) -> str:
        """Normalize a URL, optionally resolving relative URLs."""
        if base_url and not url.startswith(("http://", "https://")):
            return urljoin(base_url, url)
        return url

    @staticmethod
    def extract_domain(url: str) -> str:
        """Extract domain from URL."""
        return urlparse(url).netloc

    @staticmethod
    def is_same_domain(url1: str, url2: str) -> bool:
        """Check if two URLs are from the same domain."""
        return URLUtils.extract_domain(url1) == URLUtils.extract_domain(url2)

    @staticmethod
    def filter_urls(urls: Set[str], allowed_domains: Optional[List[str]] = None) -> Set[str]:
        """Filter URLs based on allowed domains."""
        if not allowed_domains:
            return urls

        filtered = set()
        for url in urls:
            domain = URLUtils.extract_domain(url)
            if domain in allowed_domains:
                filtered.add(url)
        return filtered


class ContentUtils:
    """Content analysis and manipulation utilities."""

    @staticmethod
    def calculate_hash(content: Union[str, bytes], algorithm: str = "sha256") -> str:
        """Calculate hash of content."""
        if isinstance(content, str):
            content = content.encode("utf-8")

        if algorithm == "md5":
            return hashlib.md5(content).hexdigest()
        elif algorithm == "sha1":
            return hashlib.sha1(content).hexdigest()
        elif algorithm == "sha256":
            return hashlib.sha256(content).hexdigest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    @staticmethod
    def extract_links(html: str, base_url: str) -> Set[str]:
        """Extract links from HTML content."""
        links = set()

        # Simple regex-based link extraction
        link_patterns = [
            r'href=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']',
        ]

        for pattern in link_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                if match.startswith(("http://", "https://")):
                    links.add(match)
                elif not match.startswith(("javascript:", "mailto:", "tel:", "#")):
                    normalized = URLUtils.normalize_url(match, base_url)
                    links.add(normalized)

        return links

    @staticmethod
    def is_html_content(content: str) -> bool:
        """Check if content appears to be HTML."""
        html_indicators = ["<html", "<!DOCTYPE", "<head", "<body", "<div", "<span"]
        content_lower = content.lower()
        return any(indicator in content_lower for indicator in html_indicators)

    @staticmethod
    def extract_forms(html: str) -> List[Dict[str, Any]]:
        """Extract form information from HTML."""
        forms = []
        form_pattern = r"<form[^>]*>(.*?)</form>"

        for form_match in re.finditer(form_pattern, html, re.DOTALL | re.IGNORECASE):
            form_html = form_match.group(0)
            form_data = {"action": "", "method": "GET", "inputs": []}

            # Extract action
            action_match = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            if action_match:
                form_data["action"] = action_match.group(1)

            # Extract method
            method_match = re.search(r'method=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            if method_match:
                form_data["method"] = method_match.group(1).upper()

            # Extract inputs
            input_pattern = r"<input[^>]*>"
            for input_match in re.finditer(input_pattern, form_html, re.IGNORECASE):
                input_html = input_match.group(0)
                input_data = {}

                # Extract input attributes
                for attr in ["name", "type", "value", "placeholder"]:
                    attr_match = re.search(f"{attr}=[\"']([^\"']+)[\"']", input_html, re.IGNORECASE)
                    if attr_match:
                        input_data[attr] = attr_match.group(1)

                if input_data:
                    form_data["inputs"].append(input_data)

            forms.append(form_data)

        return forms


class FileUtils:
    """File and directory utilities."""

    @staticmethod
    def ensure_directory(path: str) -> None:
        """Ensure a directory exists, creating it if necessary."""
        Path(path).mkdir(parents=True, exist_ok=True)

    @staticmethod
    def safe_filename(filename: str) -> str:
        """Convert a string to a safe filename."""
        # Remove or replace unsafe characters
        unsafe_chars = '<>:"/\\|?*'
        for char in unsafe_chars:
            filename = filename.replace(char, "_")
        return filename

    @staticmethod
    def load_json_file(filepath: str) -> Dict[str, Any]:
        """Load JSON file with error handling."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load JSON file {filepath}: {e}")
            return {}

    @staticmethod
    def save_json_file(filepath: str, data: Dict[str, Any], indent: int = 2) -> bool:
        """Save data to JSON file with error handling."""
        try:
            FileUtils.ensure_directory(os.path.dirname(filepath))
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=indent, ensure_ascii=False)
            return True
        except Exception as e:
            logger.error(f"Failed to save JSON file {filepath}: {e}")
            return False


class NetworkUtils:
    """Network-related utilities."""

    @staticmethod
    def is_port_open(host: str, port: int, timeout: int = 5) -> bool:
        """Check if a port is open on a host."""
        try:
            import socket

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    @staticmethod
    def get_local_ip() -> str:
        """Get the local IP address."""
        try:
            import socket

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    @staticmethod
    def ping_host(host: str, timeout: int = 5) -> bool:
        """Ping a host to check if it's reachable."""
        try:
            import subprocess

            subprocess.run(
                ["ping", "-c", "1", "-W", str(timeout), host], capture_output=True, check=True
            )
            return True
        except Exception:
            return False


class TimeUtils:
    """Time-related utilities."""

    @staticmethod
    def format_duration(seconds: float) -> str:
        """Format duration in seconds to human-readable string."""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f}m"
        else:
            hours = seconds / 3600
            return f"{hours:.1f}h"

    @staticmethod
    def format_timestamp(timestamp: Optional[float] = None) -> str:
        """Format timestamp to human-readable string."""
        if timestamp is None:
            timestamp = time.time()
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))

    @staticmethod
    def measure_time(func):
        """Decorator to measure execution time of a function."""

        def wrapper(*args, **kwargs):
            start_time = time.time()
            result = func(*args, **kwargs)
            end_time = time.time()
            duration = end_time - start_time
            logger.debug(f"{func.__name__} took {TimeUtils.format_duration(duration)}")
            return result

        return wrapper


class ValidationUtils:
    """Data validation utilities."""

    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Check if a string is a valid IP address."""
        try:
            import ipaddress

            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_valid_port(port: Union[int, str]) -> bool:
        """Check if a port number is valid."""
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except (ValueError, TypeError):
            return False

    @staticmethod
    def is_valid_email(email: str) -> bool:
        """Check if a string is a valid email address."""
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, email))

    @staticmethod
    def sanitize_input(input_str: str) -> str:
        """Sanitize user input to prevent injection attacks."""
        # Remove potentially dangerous characters
        dangerous_chars = ["<", ">", '"', "'", "&", ";", "|", "`", "$", "(", ")", "{", "}"]
        sanitized = input_str
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, "")
        return sanitized.strip()


class LoggingUtils:
    """Logging utilities."""

    @staticmethod
    def setup_logging(
        level: str = "INFO", format_str: Optional[str] = None, log_file: Optional[str] = None
    ) -> None:
        """Set up logging configuration."""
        if format_str is None:
            format_str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

        log_level = getattr(logging, level.upper())
        logging.basicConfig(level=log_level, format=format_str, filename=log_file, force=True)

    @staticmethod
    def get_logger(name: str) -> logging.Logger:
        """Get a logger with the specified name."""
        return logging.getLogger(name)

    @staticmethod
    def log_function_call(func_name: str, args: tuple = (), kwargs: dict = None):
        """Decorator to log function calls."""

        def decorator(func):
            def wrapper(*args, **kwargs):
                logger.debug(f"Calling {func_name} with args={args}, kwargs={kwargs}")
                result = func(*args, **kwargs)
                logger.debug(f"{func_name} returned {result}")
                return result

            return wrapper

        return decorator
