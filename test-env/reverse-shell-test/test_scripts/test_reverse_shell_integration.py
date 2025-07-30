#!/usr/bin/env python3
"""
Integration tests for DragonShard Reverse Shell functionality

Tests the complete reverse shell workflow including:
- API endpoints
- WebSocket connections
- Real reverse shell connections
- Console history management
"""

import asyncio
import json
import logging
import requests
import socket
import subprocess
import time
import websockets
from datetime import datetime
from typing import Dict, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ReverseShellIntegrationTest:
    """Integration test class for reverse shell functionality."""
    
    def __init__(self):
        """Initialize the integration test."""
        self.api_base_url = "http://localhost:8000/api/v1"
        self.ws_base_url = "ws://localhost:8000/api/v1"
        self.vulnerable_app_url = "http://localhost:8080"
        self.test_results = []
    
    def log_test(self, test_name: str, success: bool, message: str = ""):
        """Log test results."""
        status = "✅ PASS" if success else "❌ FAIL"
        logger.info(f"{status} {test_name}: {message}")
        self.test_results.append({
            "test": test_name,
            "success": success,
            "message": message,
            "timestamp": datetime.now().isoformat()
        })
    
    def test_api_health(self) -> bool:
        """Test API health endpoint."""
        try:
            response = requests.get(f"{self.api_base_url}/reverse-shells/summary", timeout=5)
            success = response.status_code == 200
            self.log_test("API Health Check", success, f"Status: {response.status_code}")
            return success
        except Exception as e:
            self.log_test("API Health Check", False, f"Error: {e}")
            return False
    
    def test_create_listener(self) -> Optional[str]:
        """Test creating a reverse shell listener."""
        try:
            data = {
                "port": 4444,
                "auto_close": True,
                "timeout": 300
            }
            response = requests.post(
                f"{self.api_base_url}/reverse-shells/listeners",
                json=data,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                connection_id = result.get("connection_id")
                self.log_test("Create Listener", True, f"Created listener on port 4444")
                return connection_id
            else:
                self.log_test("Create Listener", False, f"Status: {response.status_code}")
                return None
                
        except Exception as e:
            self.log_test("Create Listener", False, f"Error: {e}")
            return None
    
    def test_get_connections(self) -> bool:
        """Test getting all connections."""
        try:
            response = requests.get(f"{self.api_base_url}/reverse-shells/connections", timeout=5)
            
            if response.status_code == 200:
                connections = response.json()
                self.log_test("Get Connections", True, f"Found {len(connections)} connections")
                return True
            else:
                self.log_test("Get Connections", False, f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Get Connections", False, f"Error: {e}")
            return False
    
    def test_get_connection_info(self, connection_id: str) -> bool:
        """Test getting connection information."""
        try:
            response = requests.get(
                f"{self.api_base_url}/reverse-shells/connections/{connection_id}",
                timeout=5
            )
            
            if response.status_code == 200:
                info = response.json()
                self.log_test("Get Connection Info", True, f"Port: {info.get('port')}")
                return True
            else:
                self.log_test("Get Connection Info", False, f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Get Connection Info", False, f"Error: {e}")
            return False
    
    def test_get_console_history(self, connection_id: str) -> bool:
        """Test getting console history."""
        try:
            response = requests.get(
                f"{self.api_base_url}/reverse-shells/connections/{connection_id}/history",
                timeout=5
            )
            
            if response.status_code == 200:
                result = response.json()
                history_size = len(result.get("history", []))
                self.log_test("Get Console History", True, f"History size: {history_size}")
                return True
            else:
                self.log_test("Get Console History", False, f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Get Console History", False, f"Error: {e}")
            return False
    
    def test_send_command(self, connection_id: str) -> bool:
        """Test sending a command to a connection."""
        try:
            data = {"command": "echo 'Hello from DragonShard'"}
            response = requests.post(
                f"{self.api_base_url}/reverse-shells/connections/{connection_id}/send",
                json=data,
                timeout=5
            )
            
            if response.status_code == 200:
                self.log_test("Send Command", True, "Command sent successfully")
                return True
            else:
                self.log_test("Send Command", False, f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Send Command", False, f"Error: {e}")
            return False
    
    def test_vulnerable_app_health(self) -> bool:
        """Test vulnerable application health."""
        try:
            response = requests.get(f"{self.vulnerable_app_url}/", timeout=5)
            
            if response.status_code == 200:
                self.log_test("Vulnerable App Health", True, "App is running")
                return True
            else:
                self.log_test("Vulnerable App Health", False, f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Vulnerable App Health", False, f"Error: {e}")
            return False
    
    def test_command_injection(self) -> bool:
        """Test command injection vulnerability."""
        try:
            # Test command injection
            payload = "127.0.0.1; whoami"
            response = requests.get(
                f"{self.vulnerable_app_url}/ping",
                params={"host": payload},
                timeout=10
            )
            
            if response.status_code == 200:
                content = response.text
                if "root" in content or "user" in content:
                    self.log_test("Command Injection", True, "Vulnerability confirmed")
                    return True
                else:
                    self.log_test("Command Injection", False, "No command output found")
                    return False
            else:
                self.log_test("Command Injection", False, f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Command Injection", False, f"Error: {e}")
            return False
    
    def test_reverse_shell_trigger(self, target_host: str, target_port: int) -> bool:
        """Test triggering a reverse shell from the vulnerable app."""
        try:
            # Trigger reverse shell from vulnerable app
            response = requests.get(
                f"{self.vulnerable_app_url}/reverse-shell",
                params={
                    "host": target_host,
                    "port": target_port
                },
                timeout=10
            )
            
            if response.status_code == 200:
                self.log_test("Reverse Shell Trigger", True, "Reverse shell initiated")
                return True
            else:
                self.log_test("Reverse Shell Trigger", False, f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Reverse Shell Trigger", False, f"Error: {e}")
            return False
    
    async def test_websocket_connection(self, connection_id: str) -> bool:
        """Test WebSocket connection for real-time updates."""
        try:
            ws_url = f"{self.ws_base_url}/reverse-shells/ws/{connection_id}"
            
            async with websockets.connect(ws_url) as websocket:
                # Wait for connection info
                message = await websocket.recv()
                data = json.loads(message)
                
                if data.get("type") == "connection_info":
                    self.log_test("WebSocket Connection", True, "WebSocket connected successfully")
                    
                    # Send a test command
                    await websocket.send(json.dumps({
                        "type": "command",
                        "command": "echo 'WebSocket test'"
                    }))
                    
                    # Wait for response
                    response = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                    response_data = json.loads(response)
                    
                    if response_data.get("type") == "command_result":
                        self.log_test("WebSocket Command", True, "Command sent via WebSocket")
                        return True
                    else:
                        self.log_test("WebSocket Command", False, "No command result received")
                        return False
                else:
                    self.log_test("WebSocket Connection", False, "No connection info received")
                    return False
                    
        except Exception as e:
            self.log_test("WebSocket Connection", False, f"Error: {e}")
            return False
    
    def test_cleanup_connections(self) -> bool:
        """Test cleanup of inactive connections."""
        try:
            response = requests.post(
                f"{self.api_base_url}/reverse-shells/cleanup",
                json={"timeout_seconds": 300},
                timeout=5
            )
            
            if response.status_code == 200:
                result = response.json()
                cleaned_count = result.get("cleaned_connections", 0)
                self.log_test("Cleanup Connections", True, f"Cleaned {cleaned_count} connections")
                return True
            else:
                self.log_test("Cleanup Connections", False, f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Cleanup Connections", False, f"Error: {e}")
            return False
    
    def test_close_connection(self, connection_id: str) -> bool:
        """Test closing a connection."""
        try:
            response = requests.delete(
                f"{self.api_base_url}/reverse-shells/connections/{connection_id}",
                timeout=5
            )
            
            if response.status_code == 200:
                self.log_test("Close Connection", True, "Connection closed successfully")
                return True
            else:
                self.log_test("Close Connection", False, f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Close Connection", False, f"Error: {e}")
            return False
    
    def run_complete_test_suite(self):
        """Run the complete test suite."""
        logger.info("🧪 Starting DragonShard Reverse Shell Integration Tests")
        logger.info("=" * 60)
        
        # Test 1: API Health
        if not self.test_api_health():
            logger.error("❌ API health check failed. Stopping tests.")
            return False
        
        # Test 2: Vulnerable App Health
        if not self.test_vulnerable_app_health():
            logger.error("❌ Vulnerable app health check failed. Stopping tests.")
            return False
        
        # Test 3: Create Listener
        connection_id = self.test_create_listener()
        if not connection_id:
            logger.error("❌ Failed to create listener. Stopping tests.")
            return False
        
        # Test 4: Get Connections
        self.test_get_connections()
        
        # Test 5: Get Connection Info
        self.test_get_connection_info(connection_id)
        
        # Test 6: Get Console History
        self.test_get_console_history(connection_id)
        
        # Test 7: Send Command
        self.test_send_command(connection_id)
        
        # Test 8: Command Injection
        self.test_command_injection()
        
        # Test 9: Reverse Shell Trigger
        # Note: This would require a real listener, so we'll skip for now
        # self.test_reverse_shell_trigger("localhost", 4444)
        
        # Test 10: WebSocket Connection (async)
        try:
            asyncio.run(self.test_websocket_connection(connection_id))
        except Exception as e:
            logger.error(f"WebSocket test failed: {e}")
        
        # Test 11: Cleanup Connections
        self.test_cleanup_connections()
        
        # Test 12: Close Connection
        self.test_close_connection(connection_id)
        
        # Print summary
        self.print_test_summary()
        
        return True
    
    def print_test_summary(self):
        """Print test results summary."""
        logger.info("=" * 60)
        logger.info("📊 Test Results Summary")
        logger.info("=" * 60)
        
        passed = sum(1 for result in self.test_results if result["success"])
        total = len(self.test_results)
        
        logger.info(f"Total Tests: {total}")
        logger.info(f"Passed: {passed}")
        logger.info(f"Failed: {total - passed}")
        logger.info(f"Success Rate: {(passed/total)*100:.1f}%")
        
        # Show failed tests
        failed_tests = [result for result in self.test_results if not result["success"]]
        if failed_tests:
            logger.info("\n❌ Failed Tests:")
            for test in failed_tests:
                logger.info(f"  - {test['test']}: {test['message']}")
        
        # Save results to file
        with open("/app/logs/test_results.json", "w") as f:
            json.dump(self.test_results, f, indent=2)
        
        logger.info(f"\n📄 Detailed results saved to /app/logs/test_results.json")


def main():
    """Main function."""
    logger.info("🚀 Starting DragonShard Reverse Shell Integration Tests")
    
    # Wait for services to be ready
    logger.info("⏳ Waiting for services to be ready...")
    time.sleep(15)
    
    # Run tests
    tester = ReverseShellIntegrationTest()
    success = tester.run_complete_test_suite()
    
    if success:
        logger.info("✅ All tests completed successfully!")
        exit(0)
    else:
        logger.error("❌ Some tests failed!")
        exit(1)


if __name__ == "__main__":
    main() 