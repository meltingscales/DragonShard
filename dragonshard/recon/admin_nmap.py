#!/usr/bin/env python3
"""
Admin-privileged nmap scanner for DragonShard.
This script runs with elevated privileges to perform nmap scans.
"""

import json
import sys
import nmap
from pathlib import Path

def run_privileged_scan(target: str, scan_type: str, output_file: str):
    """Run nmap scan with admin privileges and save results to file."""
    try:
        nm = nmap.PortScanner()
        
        # Define scan arguments based on scan type
        if scan_type == "quick":
            arguments = "-T4 -F"
        elif scan_type == "udp":
            arguments = "-T4 -sU -F"
        else:  # comprehensive
            arguments = "-T4 -sS -sU -p- --version-intensity 5"
        
        # Run the scan
        nm.scan(hosts=target, arguments=arguments)
        
        # Convert results to JSON-serializable format
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
        
        # Save results to file
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Write success marker
        success_file = output_file.replace('.json', '.success')
        with open(success_file, 'w') as f:
            f.write('success')
            
    except Exception as e:
        # Write error to file
        error_file = output_file.replace('.json', '.error')
        with open(error_file, 'w') as f:
            f.write(str(e))

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: admin_nmap.py <target> <scan_type> <output_file>")
        sys.exit(1)
    
    target = sys.argv[1]
    scan_type = sys.argv[2]
    output_file = sys.argv[3]
    
    run_privileged_scan(target, scan_type, output_file)
