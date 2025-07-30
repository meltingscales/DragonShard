#!/usr/bin/env python3
"""
DragonShard Reverse Shell Demo Script

Demonstrates the reverse shell handler functionality including:
- Creating listeners
- Handling connections
- Managing console history
- WebSocket integration
"""

import asyncio
import json
import logging
import sys
import time
import threading
from datetime import datetime

# Add the dragonshard package to the path
sys.path.insert(0, '../..')

from dragonshard.executor.reverse_shell import ReverseShellHandler, ShellStatus

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ReverseShellDemo:
    """Demonstration class for reverse shell functionality."""
    
    def __init__(self):
        """Initialize the demo."""
        self.handler = ReverseShellHandler(base_port=4444, max_ports=10)
        self.running = False
        
        # Register callbacks for demo
        self.handler.register_callback('connection', self.on_connection)
        self.handler.register_callback('data', self.on_data)
        self.handler.register_callback('disconnect', self.on_disconnect)
        self.handler.register_callback('error', self.on_error)
    
    def on_connection(self, connection_id: str, data: dict):
        """Handle new connection events."""
        logger.info(f"🟢 New connection established: {connection_id}")
        if data:
            logger.info(f"   Remote: {data.get('remote_address')}:{data.get('remote_port')}")
    
    def on_data(self, connection_id: str, data: str):
        """Handle data received from reverse shell."""
        logger.info(f"📥 Data from {connection_id}: {data.strip()}")
    
    def on_disconnect(self, connection_id: str, data: any):
        """Handle disconnection events."""
        logger.info(f"🔴 Connection disconnected: {connection_id}")
    
    def on_error(self, connection_id: str, error: str):
        """Handle error events."""
        logger.error(f"❌ Error in connection {connection_id}: {error}")
    
    def create_demo_listeners(self):
        """Create demo listeners on different ports."""
        logger.info("🚀 Creating demo reverse shell listeners...")
        
        # Create listeners on different ports
        ports = [4444, 4445, 4446]
        connection_ids = []
        
        for port in ports:
            try:
                connection_id = self.handler.create_listener(port=port)
                connection_ids.append(connection_id)
                logger.info(f"   ✅ Listener created on port {port} (ID: {connection_id})")
            except Exception as e:
                logger.error(f"   ❌ Failed to create listener on port {port}: {e}")
        
        return connection_ids
    
    def simulate_connection_activity(self, connection_id: str):
        """Simulate connection activity for demo purposes."""
        logger.info(f"🎭 Simulating activity for connection {connection_id}")
        
        # Simulate some console output
        connection = self.handler.connections[connection_id]
        if connection:
            # Add some demo console history
            demo_outputs = [
                f"[{datetime.now().isoformat()}] Connected to reverse shell",
                f"[{datetime.now().isoformat()}] > whoami",
                f"[{datetime.now().isoformat()}] root",
                f"[{datetime.now().isoformat()}] > pwd",
                f"[{datetime.now().isoformat()}] /home/user",
                f"[{datetime.now().isoformat()}] > ls -la",
                f"[{datetime.now().isoformat()}] total 8",
                f"[{datetime.now().isoformat()}] drwxr-xr-x 2 user user 4096 Jan 1 12:00 .",
                f"[{datetime.now().isoformat()}] drwxr-xr-x 3 root root 4096 Jan 1 12:00 ..",
            ]
            
            connection.console_history.extend(demo_outputs)
            connection.last_activity = datetime.now()
            
            logger.info(f"   📝 Added {len(demo_outputs)} lines to console history")
    
    def demonstrate_console_history(self, connection_id: str):
        """Demonstrate console history functionality."""
        logger.info(f"📋 Demonstrating console history for {connection_id}")
        
        # Get full history
        history = self.handler.get_console_history(connection_id)
        logger.info(f"   Full history ({len(history)} lines):")
        for line in history[-5:]:  # Show last 5 lines
            logger.info(f"   {line}")
        
        # Get limited history
        limited_history = self.handler.get_console_history(connection_id, limit=3)
        logger.info(f"   Limited history ({len(limited_history)} lines):")
        for line in limited_history:
            logger.info(f"   {line}")
    
    def demonstrate_command_sending(self, connection_id: str):
        """Demonstrate command sending functionality."""
        logger.info(f"📤 Demonstrating command sending for {connection_id}")
        
        # Simulate sending commands
        commands = ["ls", "pwd", "whoami", "echo 'Hello from DragonShard'"]
        
        for command in commands:
            logger.info(f"   Sending command: {command}")
            success = self.handler.send_command(connection_id, command)
            if success:
                logger.info(f"   ✅ Command sent successfully")
            else:
                logger.info(f"   ❌ Failed to send command")
            
            time.sleep(0.5)  # Small delay for demo
    
    def demonstrate_connection_management(self):
        """Demonstrate connection management features."""
        logger.info("🔧 Demonstrating connection management...")
        
        # Get all connections
        connections = self.handler.get_all_connections()
        logger.info(f"   Total connections: {len(connections)}")
        
        # Show connection details
        for conn in connections:
            logger.info(f"   Connection {conn['connection_id']}:")
            logger.info(f"     Port: {conn['port']}")
            logger.info(f"     Status: {conn['status']}")
            logger.info(f"     Remote: {conn.get('remote_address', 'N/A')}:{conn.get('remote_port', 'N/A')}")
            logger.info(f"     History size: {len(conn['console_history'])}")
        
        # Demonstrate cleanup
        logger.info("🧹 Demonstrating connection cleanup...")
        cleaned = self.handler.cleanup_inactive_connections(timeout_seconds=300)
        logger.info(f"   Cleaned up {cleaned} inactive connections")
    
    def demonstrate_port_allocation(self):
        """Demonstrate port allocation features."""
        logger.info("🔌 Demonstrating port allocation...")
        
        # Show allocated ports
        allocated_ports = self.handler.port_allocator.get_allocated_ports()
        logger.info(f"   Currently allocated ports: {sorted(allocated_ports)}")
        
        # Test port availability
        test_port = 4447
        available = self.handler.port_allocator.is_port_available(test_port)
        logger.info(f"   Port {test_port} available: {available}")
        
        # Reserve a port
        success = self.handler.port_allocator.reserve_port(test_port)
        logger.info(f"   Reserved port {test_port}: {success}")
        
        # Check availability again
        available = self.handler.port_allocator.is_port_available(test_port)
        logger.info(f"   Port {test_port} available after reservation: {available}")
        
        # Release the port
        success = self.handler.port_allocator.release_port(test_port)
        logger.info(f"   Released port {test_port}: {success}")
    
    def run_interactive_demo(self):
        """Run an interactive demo."""
        logger.info("🎮 Starting interactive demo...")
        logger.info("Commands:")
        logger.info("  'list' - List all connections")
        logger.info("  'history <id>' - Show console history for connection")
        logger.info("  'send <id> <command>' - Send command to connection")
        logger.info("  'info <id>' - Show connection info")
        logger.info("  'cleanup' - Clean up inactive connections")
        logger.info("  'stats' - Show statistics")
        logger.info("  'quit' - Exit demo")
        
        while True:
            try:
                command = input("\n🐉 DragonShard> ").strip()
                
                if command == 'quit':
                    break
                elif command == 'list':
                    connections = self.handler.get_all_connections()
                    if connections:
                        logger.info(f"📋 Found {len(connections)} connections:")
                        for conn in connections:
                            logger.info(f"   {conn['connection_id']}: Port {conn['port']} ({conn['status']})")
                    else:
                        logger.info("📋 No connections found")
                
                elif command.startswith('history '):
                    parts = command.split(' ', 2)
                    if len(parts) >= 2:
                        connection_id = parts[1]
                        history = self.handler.get_console_history(connection_id)
                        if history:
                            logger.info(f"📜 History for {connection_id}:")
                            for line in history[-10:]:  # Last 10 lines
                                logger.info(f"   {line}")
                        else:
                            logger.info(f"📜 No history for {connection_id}")
                    else:
                        logger.error("❌ Usage: history <connection_id>")
                
                elif command.startswith('send '):
                    parts = command.split(' ', 3)
                    if len(parts) >= 3:
                        connection_id = parts[1]
                        cmd = parts[2]
                        success = self.handler.send_command(connection_id, cmd)
                        if success:
                            logger.info(f"✅ Command sent: {cmd}")
                        else:
                            logger.error(f"❌ Failed to send command: {cmd}")
                    else:
                        logger.error("❌ Usage: send <connection_id> <command>")
                
                elif command.startswith('info '):
                    parts = command.split(' ', 2)
                    if len(parts) >= 2:
                        connection_id = parts[1]
                        info = self.handler.get_connection_info(connection_id)
                        if info:
                            logger.info(f"ℹ️  Info for {connection_id}:")
                            for key, value in info.items():
                                logger.info(f"   {key}: {value}")
                        else:
                            logger.error(f"❌ Connection {connection_id} not found")
                    else:
                        logger.error("❌ Usage: info <connection_id>")
                
                elif command == 'cleanup':
                    cleaned = self.handler.cleanup_inactive_connections()
                    logger.info(f"🧹 Cleaned up {cleaned} inactive connections")
                
                elif command == 'stats':
                    connections = self.handler.get_all_connections()
                    status_counts = {}
                    for conn in connections:
                        status = conn['status']
                        status_counts[status] = status_counts.get(status, 0) + 1
                    
                    logger.info("📊 Statistics:")
                    logger.info(f"   Total connections: {len(connections)}")
                    for status, count in status_counts.items():
                        logger.info(f"   {status}: {count}")
                
                else:
                    logger.error("❌ Unknown command. Type 'help' for available commands.")
                    
            except KeyboardInterrupt:
                logger.info("\n👋 Demo interrupted by user")
                break
            except Exception as e:
                logger.error(f"❌ Error: {e}")
    
    def run_full_demo(self):
        """Run the full demonstration."""
        logger.info("🎬 Starting DragonShard Reverse Shell Demo")
        logger.info("=" * 50)
        
        try:
            # Create demo listeners
            connection_ids = self.create_demo_listeners()
            
            if not connection_ids:
                logger.error("❌ No listeners created. Exiting.")
                return
            
            # Wait a moment for listeners to start
            time.sleep(1)
            
            # Demonstrate port allocation
            self.demonstrate_port_allocation()
            
            # Demonstrate connection management
            self.demonstrate_connection_management()
            
            # Simulate activity for first connection
            if connection_ids:
                self.simulate_connection_activity(connection_ids[0])
                self.demonstrate_console_history(connection_ids[0])
                self.demonstrate_command_sending(connection_ids[0])
            
            logger.info("=" * 50)
            logger.info("🎬 Demo completed successfully!")
            
            # Run interactive demo
            self.run_interactive_demo()
            
        except Exception as e:
            logger.error(f"❌ Demo failed: {e}")
        finally:
            # Cleanup
            logger.info("🧹 Cleaning up...")
            for conn_id in list(self.handler.connections.keys()):
                self.handler.close_connection(conn_id)
            logger.info("✅ Cleanup completed")


def main():
    """Main function."""
    print("🐉 DragonShard Reverse Shell Handler Demo")
    print("=" * 50)
    
    demo = ReverseShellDemo()
    demo.run_full_demo()


if __name__ == "__main__":
    main() 