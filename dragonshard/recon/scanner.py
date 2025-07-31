#!/usr/bin/env python3
"""
DragonShard Network Scanner

Handles network scanning with proper privilege management for nmap operations.
"""

import logging
import subprocess
from typing import Any, Dict, Optional

import nmap

logger = logging.getLogger(__name__)


def check_privileges() -> bool:
    """
    Check if the current process has admin privileges.
    
    Returns:
        True if running with admin privileges, False otherwise
    """
    try:
        # Try to run a simple privileged command
        result = subprocess.run(
            ["sudo", "-n", "true"],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def get_scan_capabilities() -> Dict[str, bool]:
    """
    Get information about scan capabilities based on privileges.
    
    Returns:
        Dictionary with capability information
    """
    has_privileges = check_privileges()
    
    return {
        "has_admin_privileges": has_privileges,
        "can_run_syn_scans": has_privileges,
        "can_run_udp_scans": True,  # UDP scans work without privileges
        "can_run_comprehensive_scans": has_privileges,
        "can_run_quick_scans": True,  # Quick scans work without privileges
        "fallback_available": True,
    }


def run_scan(target: str, scan_type: str = "comprehensive") -> Dict[str, Any]:
    """
    Run a network scan on the target with proper privilege handling.

    Args:
        target: IP address or hostname to scan
        scan_type: Type of scan - "quick", "comprehensive", or "udp"

    Returns:
        Dictionary with scan results including TCP and UDP ports
    """
    nm = nmap.PortScanner()
    
    # Check privileges and adjust scan arguments accordingly
    has_privileges = check_privileges()
    
    # Define scan arguments based on scan type and privileges
    if scan_type == "quick":
        arguments = "-T4 -F"  # Fast scan of common ports
    elif scan_type == "udp":
        arguments = "-T4 -sU -F"  # UDP scan of common ports
    else:  # comprehensive
        # Use TCP connect scan as default since SYN scans are often blocked
        # even with sudo in containerized environments
        arguments = "-T4 -sT -p- --version-intensity 5"
        if has_privileges:
            logger.info("Using TCP connect scan for comprehensive scan (SYN scans may be blocked)")
        else:
            logger.info("Using unprivileged TCP connect scan for comprehensive scan")

    logger.info(f"Running {scan_type} scan with arguments: {arguments}")
    
    try:
        nm.scan(hosts=target, arguments=arguments)
        results = {}

        for host in nm.all_hosts():
            host_data = nm[host]
            results[host] = {"status": host_data.state(), "tcp": {}, "udp": {}}

            # Process TCP ports
            if "tcp" in host_data:
                for port in host_data.all_tcp():
                    port_data = host_data["tcp"][port]
                    results[host]["tcp"][port] = {
                        "state": port_data["state"],
                        "service": port_data.get("name", "unknown"),
                        "version": port_data.get("version", ""),
                        "product": port_data.get("product", ""),
                        "extrainfo": port_data.get("extrainfo", ""),
                    }

            # Process UDP ports
            if "udp" in host_data:
                for port in host_data.all_udp():
                    port_data = host_data["udp"][port]
                    results[host]["udp"][port] = {
                        "state": port_data["state"],
                        "service": port_data.get("name", "unknown"),
                        "version": port_data.get("version", ""),
                        "product": port_data.get("product", ""),
                        "extrainfo": port_data.get("extrainfo", ""),
                    }

        return results
        
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        # Return empty results on failure
        return {target: {"status": "down", "tcp": {}, "udp": {}}}


def get_open_ports(results: Dict[str, Any]) -> Dict[str, Dict[str, list]]:
    """
    Extract only open ports from scan results.

    Args:
        results: Results from run_scan()

    Returns:
        Dictionary with open TCP and UDP ports for each host
    """
    open_ports = {}

    for host, host_data in results.items():
        open_ports[host] = {"tcp": [], "udp": []}

        # Get open TCP ports
        for port, port_data in host_data.get("tcp", {}).items():
            if port_data["state"] == "open":
                open_ports[host]["tcp"].append(
                    {
                        "port": port,
                        "service": port_data["service"],
                        "version": port_data["version"],
                        "product": port_data["product"],
                    }
                )

        # Get open UDP ports
        for port, port_data in host_data.get("udp", {}).items():
            if port_data["state"] == "open":
                open_ports[host]["udp"].append(
                    {
                        "port": port,
                        "service": port_data["service"],
                        "version": port_data["version"],
                        "product": port_data["product"],
                    }
                )

    return open_ports


def scan_common_services(target: str) -> Dict[str, Any]:
    """
    Scan for common services on well-known ports.

    Args:
        target: IP address or hostname to scan

    Returns:
        Dictionary with common service information
    """
    nm = nmap.PortScanner()
    common_ports = "21,22,23,25,53,80,110,143,443,993,995,3306,5432,6379,8080,8443"

    # Use unprivileged scan for common services
    nm.scan(hosts=target, ports=common_ports, arguments="-T4 -sT -sV")
    results = {}

    for host in nm.all_hosts():
        host_data = nm[host]
        results[host] = {"status": host_data.state(), "services": {}}

        # Process TCP ports
        if "tcp" in host_data:
            for port in host_data.all_tcp():
                port_data = host_data["tcp"][port]
                if port_data["state"] == "open":
                    results[host]["services"][port] = {
                        "protocol": "tcp",
                        "service": port_data.get("name", "unknown"),
                        "version": port_data.get("version", ""),
                        "product": port_data.get("product", ""),
                        "extrainfo": port_data.get("extrainfo", ""),
                    }

    return results


def get_scan_recommendations() -> Dict[str, str]:
    """
    Get recommendations for improving scan capabilities.
    
    Returns:
        Dictionary with recommendations
    """
    has_privileges = check_privileges()
    
    recommendations = {
        "current_status": "unprivileged" if not has_privileges else "privileged",
        "recommendations": []
    }
    
    if not has_privileges:
        recommendations["recommendations"].extend([
            "Run DragonShard with sudo for better scan capabilities",
            "Use 'sudo make start-api' to run with admin privileges",
            "Quick scans and UDP scans work without privileges",
            "TCP connect scans (-sT) are used for comprehensive scans"
        ])
    else:
        recommendations["recommendations"].extend([
            "Running with admin privileges - all scan types available",
            "TCP connect scans (-sT) are used by default for better compatibility",
            "SYN scans (-sS) may be blocked in containerized environments",
            "UDP scans work with or without privileges"
        ])
    
    return recommendations
