import nmap


def run_scan(target: str) -> dict:
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-T4 -F')
    results = {}
    for host in nm.all_hosts():
        results[host] = {
            "status": nm[host].state(),
            "tcp": {port: nm[host]["tcp"][port]["name"] for port in nm[host].all_tcp()}
        }
    return results
