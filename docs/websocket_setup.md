# WebSocket Support in DragonShard

DragonShard's API includes real-time WebSocket functionality for live attack monitoring, network visualization, and interactive features. This document explains the WebSocket setup and how to resolve common issues.

## Overview

DragonShard uses WebSockets for:
- **Real-time attack monitoring**: Live updates during vulnerability scanning and exploitation
- **Network visualization**: Interactive network topology updates
- **Genetic algorithm progress**: Real-time fuzzing progress visualization
- **Session management**: Live session state updates

## Dependencies

The following WebSocket dependencies are required:

```bash
# Core WebSocket support
websockets==15.0.1

# Enhanced uvicorn with WebSocket support
uvicorn[standard]==0.35.0

# Additional dependencies included with uvicorn[standard]
httptools==0.6.4
python-dotenv==1.1.1
uvloop==0.21.0
watchfiles==1.1.0
```

## Installation

### Automatic Setup

The WebSocket dependencies are automatically installed during setup:

```bash
# Standard setup (includes WebSocket support)
make setup

# NixOS setup (includes WebSocket support)
make setup-nixos
```

### Manual Installation

If you need to install WebSocket support manually:

```bash
# Install uvicorn with standard extras (includes WebSocket support)
uv pip install "uvicorn[standard]"

# Or install individual dependencies
uv pip install websockets httptools python-dotenv uvloop watchfiles
```

## Testing WebSocket Support

### Quick Test

```bash
# Test WebSocket functionality
make test-websocket
```

### Manual Verification

```bash
# Check if websockets library is available
uv run python -c "import websockets; print('✅ WebSocket support available')"

# Check uvicorn WebSocket support
uv run python -c "import uvicorn; print('✅ uvicorn WebSocket support available')"
```

## Common Issues and Solutions

### Issue: "No supported WebSocket library detected"

**Symptoms:**
```
WARNING:  No supported WebSocket library detected. Please use "pip install 'uvicorn[standard]'", or install 'websockets' or 'wsproto' manually.
```

**Solution:**
```bash
# Install uvicorn with standard extras
uv pip install "uvicorn[standard]"

# Or install websockets directly
uv pip install websockets
```

### Issue: "Unsupported upgrade request"

**Symptoms:**
```
WARNING:  Unsupported upgrade request.
```

**Solution:**
This warning appears when WebSocket libraries aren't properly installed. Install the standard extras:

```bash
uv pip install "uvicorn[standard]"
```

### Issue: WebSocket connections fail

**Symptoms:**
- WebSocket connections return 404 errors
- Real-time features don't work
- Browser console shows WebSocket connection errors

**Solution:**
1. Ensure WebSocket dependencies are installed
2. Check that the API server is running with WebSocket support
3. Verify the WebSocket endpoints are properly configured

## API WebSocket Endpoints

DragonShard provides several WebSocket endpoints:

### Attack Monitoring
```
ws://localhost:8000/ws/attacks
```

### Network Visualization
```
ws://localhost:8000/ws/network
```

### Fuzzing Progress
```
ws://localhost:8000/ws/fuzzing
```

### Session Management
```
ws://localhost:8000/ws/sessions
```

## Development

### Testing WebSocket Functionality

```bash
# Run WebSocket tests
make test-websocket

# Start API with WebSocket support
make start-api

# Test in browser
# Open http://localhost:8000/docs for API documentation
# WebSocket endpoints are available at /ws/* paths
```

### Debugging WebSocket Issues

1. **Check dependencies:**
   ```bash
   make test-websocket
   ```

2. **Verify API startup:**
   ```bash
   make start-api
   # Look for WebSocket warnings in startup logs
   ```

3. **Test WebSocket connection:**
   ```bash
   # Use curl to test WebSocket upgrade
   curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==" http://localhost:8000/ws/attacks
   ```

## Production Deployment

### Docker Deployment

The Docker setup includes WebSocket support:

```bash
# Build and run with WebSocket support
make docker-up

# Check logs for WebSocket warnings
make docker-logs
```

### Manual Deployment

Ensure WebSocket dependencies are installed in production:

```bash
# Install with WebSocket support
pip install "uvicorn[standard]"

# Or install requirements
pip install -r requirements.lock.txt
```

## Troubleshooting

### WebSocket Not Working

1. **Check dependencies:**
   ```bash
   make test-websocket
   ```

2. **Reinstall WebSocket support:**
   ```bash
   uv pip install "uvicorn[standard]"
   ```

3. **Check API logs:**
   ```bash
   make start-api
   # Look for WebSocket warnings
   ```

4. **Verify endpoints:**
   - Check that WebSocket endpoints are properly configured
   - Ensure the API server is running on the correct port
   - Verify firewall/proxy settings allow WebSocket connections

### Performance Issues

1. **Use uvloop for better performance:**
   ```bash
   uvicorn dragonshard.api.app:app --loop uvloop
   ```

2. **Monitor WebSocket connections:**
   - Check for memory leaks
   - Monitor connection counts
   - Verify proper cleanup

### Security Considerations

1. **WebSocket authentication:**
   - Implement proper authentication for WebSocket connections
   - Validate session tokens
   - Rate limit WebSocket connections

2. **CORS configuration:**
   - Configure CORS for WebSocket connections
   - Allow appropriate origins

## References

- [FastAPI WebSocket Documentation](https://fastapi.tiangolo.com/advanced/websockets/)
- [Uvicorn WebSocket Support](https://www.uvicorn.org/)
- [WebSockets Library Documentation](https://websockets.readthedocs.io/) 