from typing import Any, Dict

import nmap


def run_scan(target: str, scan_type: str = "comprehensive") -> Dict[str, Any]:
    """
    Run a network scan on the target.

    Args:
        target: IP address or hostname to scan
        scan_type: Type of scan - "quick", "comprehensive", or "udp"

    Returns:
        Dictionary with scan results including TCP and UDP ports
    """
    nm = nmap.PortScanner()

    # Define scan arguments based on scan type
    if scan_type == "quick":
        arguments = '-T4 -F'  # Fast scan of common ports
    elif scan_type == "udp":
        arguments = '-T4 -sU -F'  # UDP scan of common ports
    else:  # comprehensive
        arguments = '-T4 -sS -sU -p- --version-intensity 5'  # Full TCP/UDP scan with service detection

    nm.scan(hosts=target, arguments=arguments)
    results = {}

    for host in nm.all_hosts():
        host_data = nm[host]
        results[host] = {
            "status": host_data.state(),
            "tcp": {},
            "udp": {}
        }

        # Process TCP ports
        if "tcp" in host_data:
            for port in host_data.all_tcp():
                port_data = host_data["tcp"][port]
                results[host]["tcp"][port] = {
                    "state": port_data["state"],
                    "service": port_data.get("name", "unknown"),
                    "version": port_data.get("version", ""),
                    "product": port_data.get("product", ""),
                    "extrainfo": port_data.get("extrainfo", "")
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
                    "extrainfo": port_data.get("extrainfo", "")
                }

    return results


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
        open_ports[host] = {
            "tcp": [],
            "udp": []
        }

        # Get open TCP ports
        for port, port_data in host_data.get("tcp", {}).items():
            if port_data["state"] == "open":
                open_ports[host]["tcp"].append({
                    "port": port,
                    "service": port_data["service"],
                    "version": port_data["version"],
                    "product": port_data["product"]
                })

        # Get open UDP ports
        for port, port_data in host_data.get("udp", {}).items():
            if port_data["state"] == "open":
                open_ports[host]["udp"].append({
                    "port": port,
                    "service": port_data["service"],
                    "version": port_data["version"],
                    "product": port_data["product"]
                })

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

    nm.scan(hosts=target, ports=common_ports, arguments='-T4 -sS -sV')
    results = {}

    for host in nm.all_hosts():
        host_data = nm[host]
        results[host] = {
            "status": host_data.state(),
            "services": {}
        }

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
                        "extrainfo": port_data.get("extrainfo", "")
                    }

    return results
