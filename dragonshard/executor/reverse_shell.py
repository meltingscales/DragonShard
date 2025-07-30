#!/usr/bin/env python3
"""
DragonShard Reverse Shell Handler Module

Manages reverse shell connections, port allocation, console history,
and interactive session handling.
"""

import asyncio
import json
import logging
import queue
import select
import socket
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class ShellStatus(Enum):
    """Reverse shell connection states."""

    LISTENING = "listening"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    CLOSED = "closed"


@dataclass
class ShellConnection:
    """Reverse shell connection data."""

    connection_id: str
    port: int
    status: ShellStatus
    remote_address: Optional[str] = None
    remote_port: Optional[int] = None
    created_at: datetime = None
    last_activity: datetime = None
    console_history: List[str] = None
    max_history_size: int = 1000
    auto_close: bool = True
    timeout: int = 300  # 5 minutes default timeout

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.last_activity is None:
            self.last_activity = datetime.now()
        if self.console_history is None:
            self.console_history = []

    def add_to_history(self, line: str) -> None:
        """Add a line to console history with automatic trimming."""
        self.console_history.append(line)
        if len(self.console_history) > self.max_history_size:
            self.console_history = self.console_history[-self.max_history_size :]


class ReverseShellHandler:
    """
    Manages reverse shell connections with dynamic port allocation,
    console history, and interactive session handling.
    """

    def __init__(self, base_port: int = 4444, max_ports: int = 100):
        """
        Initialize the reverse shell handler.

        Args:
            base_port: Starting port for dynamic allocation
            max_ports: Maximum number of ports to allocate
        """
        self.base_port = base_port
        self.max_ports = max_ports
        self.connections: Dict[str, ShellConnection] = {}
        self.port_allocator = PortAllocator(base_port, max_ports)
        self.lock = threading.RLock()
        self.callbacks: Dict[str, List[Callable]] = {
            "connection": [],
            "data": [],
            "disconnect": [],
            "error": [],
        }

        logger.info(
            f"ReverseShellHandler initialized with base_port={base_port}, max_ports={max_ports}"
        )

    def create_listener(self, port: Optional[int] = None) -> str:
        """
        Create a new reverse shell listener.

        Args:
            port: Specific port to use (optional, will auto-allocate if None)

        Returns:
            Connection ID for the new listener
        """
        with self.lock:
            if port is None:
                port = self.port_allocator.allocate_port()
            else:
                if not self.port_allocator.is_port_available(port):
                    raise ValueError(f"Port {port} is not available")
                self.port_allocator.reserve_port(port)

            connection_id = str(uuid.uuid4())

            connection = ShellConnection(
                connection_id=connection_id, port=port, status=ShellStatus.LISTENING
            )

            self.connections[connection_id] = connection

            # Start listener in background thread
            listener_thread = threading.Thread(
                target=self._start_listener, args=(connection_id,), daemon=True
            )
            listener_thread.start()

            logger.info(f"Created reverse shell listener on port {port} with ID {connection_id}")
            return connection_id

    def _start_listener(self, connection_id: str) -> None:
        """Start listening for reverse shell connections."""
        connection = self.connections[connection_id]

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind(("0.0.0.0", connection.port))
                server_socket.listen(1)
                server_socket.settimeout(1.0)  # 1 second timeout for checking stop flag

                logger.info(f"Listening for reverse shell on port {connection.port}")

                while connection.status == ShellStatus.LISTENING:
                    try:
                        client_socket, address = server_socket.accept()
                        logger.info(f"Reverse shell connection from {address}")

                        connection.remote_address = address[0]
                        connection.remote_port = address[1]
                        connection.status = ShellStatus.CONNECTED
                        connection.last_activity = datetime.now()

                        # Start handling the connection
                        self._handle_connection(connection_id, client_socket)
                        break

                    except socket.timeout:
                        continue
                    except Exception as e:
                        logger.error(f"Error accepting connection: {e}")
                        connection.status = ShellStatus.ERROR
                        break

        except Exception as e:
            logger.error(f"Error starting listener on port {connection.port}: {e}")
            connection.status = ShellStatus.ERROR
            self._trigger_callbacks("error", connection_id, str(e))

    def _handle_connection(self, connection_id: str, client_socket: socket.socket) -> None:
        """Handle an active reverse shell connection."""
        connection = self.connections[connection_id]

        try:
            # Create input/output queues for the connection
            input_queue = queue.Queue()
            output_queue = queue.Queue()

            # Start reader thread
            reader_thread = threading.Thread(
                target=self._read_from_shell,
                args=(connection_id, client_socket, output_queue),
                daemon=True,
            )
            reader_thread.start()

            # Start writer thread
            writer_thread = threading.Thread(
                target=self._write_to_shell,
                args=(connection_id, client_socket, input_queue),
                daemon=True,
            )
            writer_thread.start()

            # Store queues for external access
            connection.input_queue = input_queue
            connection.output_queue = output_queue
            connection.client_socket = client_socket

            self._trigger_callbacks(
                "connection",
                connection_id,
                {
                    "remote_address": connection.remote_address,
                    "remote_port": connection.remote_port,
                },
            )

            # Wait for threads to complete
            reader_thread.join()
            writer_thread.join()

        except Exception as e:
            logger.error(f"Error handling connection {connection_id}: {e}")
            connection.status = ShellStatus.ERROR
            self._trigger_callbacks("error", connection_id, str(e))
        finally:
            try:
                client_socket.close()
            except Exception:
                pass

    def _read_from_shell(
        self, connection_id: str, client_socket: socket.socket, output_queue: queue.Queue
    ) -> None:
        """Read data from the reverse shell and add to console history."""
        connection = self.connections[connection_id]

        try:
            while connection.status == ShellStatus.CONNECTED:
                try:
                    data = client_socket.recv(4096)
                    if not data:
                        break

                    # Decode and add to console history
                    output_text = data.decode("utf-8", errors="replace")
                    connection.console_history.append(
                        f"[{datetime.now().isoformat()}] {output_text}"
                    )

                    # Trim history if it gets too long
                    if len(connection.console_history) > connection.max_history_size:
                        connection.console_history = connection.console_history[
                            -connection.max_history_size :
                        ]

                    connection.last_activity = datetime.now()
                    output_queue.put(output_text)

                    # Trigger data callback
                    self._trigger_callbacks("data", connection_id, output_text)

                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Error reading from shell {connection_id}: {e}")
                    break

        except Exception as e:
            logger.error(f"Error in shell reader thread {connection_id}: {e}")
        finally:
            connection.status = ShellStatus.DISCONNECTED
            self._trigger_callbacks("disconnect", connection_id, None)

    def _write_to_shell(
        self, connection_id: str, client_socket: socket.socket, input_queue: queue.Queue
    ) -> None:
        """Write data to the reverse shell."""
        connection = self.connections[connection_id]

        try:
            while connection.status == ShellStatus.CONNECTED:
                try:
                    # Get input from queue with timeout
                    input_text = input_queue.get(timeout=1.0)

                    # Add to console history
                    connection.console_history.append(
                        f"[{datetime.now().isoformat()}] > {input_text}"
                    )

                    # Send to shell
                    client_socket.send(input_text.encode("utf-8"))
                    connection.last_activity = datetime.now()

                except queue.Empty:
                    continue
                except Exception as e:
                    logger.error(f"Error writing to shell {connection_id}: {e}")
                    break

        except Exception as e:
            logger.error(f"Error in shell writer thread {connection_id}: {e}")

    def send_command(self, connection_id: str, command: str) -> bool:
        """
        Send a command to an active reverse shell connection.

        Args:
            connection_id: The connection ID
            command: Command to send

        Returns:
            True if command was sent successfully
        """
        with self.lock:
            if connection_id not in self.connections:
                return False

            connection = self.connections[connection_id]
            if connection.status != ShellStatus.CONNECTED:
                return False

            if hasattr(connection, "input_queue"):
                try:
                    connection.input_queue.put(command)
                    return True
                except Exception as e:
                    logger.error(f"Error sending command to {connection_id}: {e}")
                    return False

            return False

    def get_console_history(self, connection_id: str, limit: Optional[int] = None) -> List[str]:
        """
        Get console history for a connection.

        Args:
            connection_id: The connection ID
            limit: Maximum number of lines to return

        Returns:
            List of console history lines
        """
        with self.lock:
            if connection_id not in self.connections:
                return []

            connection = self.connections[connection_id]
            history = connection.console_history.copy()

            if limit:
                history = history[-limit:]

            return history

    def close_connection(self, connection_id: str) -> bool:
        """
        Close a reverse shell connection.

        Args:
            connection_id: The connection ID

        Returns:
            True if connection was closed successfully
        """
        with self.lock:
            if connection_id not in self.connections:
                return False

            connection = self.connections[connection_id]

            # Close socket if it exists
            if hasattr(connection, "client_socket"):
                try:
                    connection.client_socket.close()
                except Exception:
                    pass

            # Release port
            self.port_allocator.release_port(connection.port)

            # Update status
            connection.status = ShellStatus.CLOSED

            # Remove from connections dict
            del self.connections[connection_id]

            logger.info(f"Closed reverse shell connection {connection_id}")
            return True

    def get_connection_info(self, connection_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a reverse shell connection.

        Args:
            connection_id: The connection ID

        Returns:
            Connection information dictionary
        """
        with self.lock:
            if connection_id not in self.connections:
                return None

            connection = self.connections[connection_id]
            info = asdict(connection)
            # Convert enum to string for JSON serialization
            info["status"] = connection.status.value
            return info

    def get_all_connections(self) -> List[Dict[str, Any]]:
        """
        Get information about all reverse shell connections.

        Returns:
            List of connection information dictionaries
        """
        with self.lock:
            connections = []
            for conn in self.connections.values():
                info = asdict(conn)
                # Convert enum to string for JSON serialization
                info["status"] = conn.status.value
                connections.append(info)
            return connections

    def cleanup_inactive_connections(self, timeout_seconds: int = 300) -> int:
        """
        Clean up inactive connections.

        Args:
            timeout_seconds: Timeout in seconds for inactive connections

        Returns:
            Number of connections cleaned up
        """
        with self.lock:
            current_time = datetime.now()
            to_remove = []

            for connection_id, connection in self.connections.items():
                if connection.status == ShellStatus.CONNECTED:
                    time_diff = (current_time - connection.last_activity).total_seconds()
                    if time_diff > timeout_seconds and connection.auto_close:
                        to_remove.append(connection_id)

            for connection_id in to_remove:
                self.close_connection(connection_id)

            return len(to_remove)

    def register_callback(self, event_type: str, callback: Callable) -> None:
        """
        Register a callback for connection events.

        Args:
            event_type: Type of event ('connection', 'data', 'disconnect', 'error')
            callback: Callback function to register
        """
        if event_type in self.callbacks:
            self.callbacks[event_type].append(callback)

    def _trigger_callbacks(self, event_type: str, connection_id: str, data: Any) -> None:
        """Trigger callbacks for an event."""
        for callback in self.callbacks.get(event_type, []):
            try:
                callback(connection_id, data)
            except Exception as e:
                logger.error(f"Error in callback for {event_type}: {e}")


class PortAllocator:
    """Manages dynamic port allocation for reverse shell listeners."""

    def __init__(self, base_port: int, max_ports: int):
        """
        Initialize the port allocator.

        Args:
            base_port: Starting port number
            max_ports: Maximum number of ports to manage
        """
        self.base_port = base_port
        self.max_ports = max_ports
        self.allocated_ports: Set[int] = set()
        self.lock = threading.Lock()

        logger.info(f"PortAllocator initialized with base_port={base_port}, max_ports={max_ports}")

    def allocate_port(self) -> int:
        """
        Allocate an available port.

        Returns:
            Allocated port number
        """
        with self.lock:
            for port in range(self.base_port, self.base_port + self.max_ports):
                if port not in self.allocated_ports and self._is_port_available(port):
                    self.allocated_ports.add(port)
                    logger.info(f"Allocated port {port}")
                    return port

            raise RuntimeError("No available ports for allocation")

    def reserve_port(self, port: int) -> bool:
        """
        Reserve a specific port.

        Args:
            port: Port number to reserve

        Returns:
            True if port was reserved successfully
        """
        with self.lock:
            if port in self.allocated_ports:
                return False

            if not self._is_port_available(port):
                return False

            self.allocated_ports.add(port)
            logger.info(f"Reserved port {port}")
            return True

    def release_port(self, port: int) -> bool:
        """
        Release an allocated port.

        Args:
            port: Port number to release

        Returns:
            True if port was released successfully
        """
        with self.lock:
            if port in self.allocated_ports:
                self.allocated_ports.remove(port)
                logger.info(f"Released port {port}")
                return True
            return False

    def is_port_available(self, port: int) -> bool:
        """
        Check if a port is available for allocation.

        Args:
            port: Port number to check

        Returns:
            True if port is available
        """
        with self.lock:
            return port not in self.allocated_ports and self._is_port_available(port)

    def _is_port_available(self, port: int) -> bool:
        """Check if a port is actually available on the system."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("0.0.0.0", port))
                return True
        except OSError:
            return False

    def get_allocated_ports(self) -> Set[int]:
        """
        Get all currently allocated ports.

        Returns:
            Set of allocated port numbers
        """
        with self.lock:
            return self.allocated_ports.copy()
