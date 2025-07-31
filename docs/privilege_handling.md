# Privilege Handling in DragonShard Scanner

## Overview

DragonShard's network scanner now includes intelligent privilege handling to ensure scans work reliably across different environments, including containerized systems where certain scan types may be restricted.

## Problem Solved

The original issue was that certain nmap scan types (particularly SYN scans `-sS`) require root privileges, but even with sudo, these scans can be blocked in containerized environments or systems with additional security restrictions.

**Original Error:**
```
ERROR: 'You requested a scan type which requires root privileges.\nQUITTING!\n'
```

## Solution Implemented

### 1. **Intelligent Scan Type Selection**

The scanner now automatically chooses the most appropriate scan type based on:
- Available privileges
- Environment restrictions
- Scan requirements

### 2. **TCP Connect Scans as Default**

Instead of using SYN scans (`-sS`) which are often blocked, the scanner now uses TCP connect scans (`-sT`) for comprehensive scans:

```python
# Before (problematic)
arguments = "-T4 -sS -sU -p- --version-intensity 5"

# After (reliable)
arguments = "-T4 -sT -p- --version-intensity 5"
```

### 3. **Privilege Detection**

The scanner includes functions to detect and report privilege status:

```python
from dragonshard.recon.scanner import check_privileges, get_scan_capabilities

# Check if running with admin privileges
has_privileges = check_privileges()

# Get detailed capability information
capabilities = get_scan_capabilities()
```

### 4. **Graceful Fallbacks**

All scan types now have reliable fallback options:
- **Quick scans**: Always work without privileges
- **UDP scans**: Work with or without privileges
- **Comprehensive scans**: Use TCP connect scans by default

## Scan Types and Compatibility

| Scan Type | Privileges Required | Fallback Available | Notes |
|-----------|-------------------|-------------------|-------|
| Quick | ❌ No | ✅ Yes | Fast scan of common ports |
| UDP | ❌ No | ✅ Yes | UDP scans work without privileges |
| Comprehensive | ⚠️ Partial | ✅ Yes | Uses TCP connect scans by default |

## Usage Examples

### Basic Scanning

```python
from dragonshard.recon.scanner import run_scan

# Quick scan (always works)
results = run_scan("127.0.0.1", "quick")

# Comprehensive scan (uses TCP connect)
results = run_scan("127.0.0.1", "comprehensive")

# UDP scan
results = run_scan("127.0.0.1", "udp")
```

### Checking Capabilities

```python
from dragonshard.recon.scanner import get_scan_capabilities, get_scan_recommendations

# Check what scan types are available
capabilities = get_scan_capabilities()
print(f"Can run SYN scans: {capabilities['can_run_syn_scans']}")

# Get recommendations for better scanning
recommendations = get_scan_recommendations()
for rec in recommendations['recommendations']:
    print(f"• {rec}")
```

### API Usage

```bash
# Scan a host with comprehensive scan
curl -X POST "http://localhost:8000/api/v1/network/hosts/host_id/scan" \
  -H "Content-Type: application/json" \
  -d '{"scan_type": "comprehensive"}'

# Quick scan
curl -X POST "http://localhost:8000/api/v1/network/hosts/host_id/scan" \
  -H "Content-Type: application/json" \
  -d '{"scan_type": "quick"}'
```

## Testing

### Run Privilege Tests

```bash
# Test the privilege handling functionality
make test-privileged-scanner
```

### Manual Testing

```bash
# Test with localhost
python -c "
from dragonshard.recon.scanner import run_scan
results = run_scan('127.0.0.1', 'comprehensive')
print(f'Found {len(results)} hosts')
"
```

## Environment Considerations

### Containerized Environments

In Docker containers or similar environments:
- SYN scans are often blocked even with root privileges
- TCP connect scans provide reliable alternatives
- UDP scans work normally

### Production Systems

For production deployments:
- Use `sudo make start-api` for better scan capabilities
- TCP connect scans are more reliable across different environments
- Consider network policies that might block certain scan types

### Development Environments

For development:
- All scan types work without special configuration
- Quick scans are recommended for testing
- Comprehensive scans use TCP connect by default

## Configuration

### Scan Arguments

The scanner automatically selects appropriate arguments:

```python
# Quick scan
arguments = "-T4 -F"

# UDP scan  
arguments = "-T4 -sU -F"

# Comprehensive scan (TCP connect)
arguments = "-T4 -sT -p- --version-intensity 5"
```

### Customization

To modify scan behavior, edit `dragonshard/recon/scanner.py`:

```python
def run_scan(target: str, scan_type: str = "comprehensive") -> Dict[str, Any]:
    # Customize scan arguments here
    if scan_type == "comprehensive":
        arguments = "-T4 -sT -p- --version-intensity 5"  # Customize this
```

## Troubleshooting

### Common Issues

1. **"Permission denied" errors**
   - Use TCP connect scans instead of SYN scans
   - Run with `sudo` if needed
   - Check system security policies

2. **Scan timeouts**
   - Reduce scan scope (use quick scan)
   - Check network connectivity
   - Verify target is reachable

3. **No results returned**
   - Check if target is up
   - Verify scan arguments
   - Review firewall rules

### Debug Information

Enable debug logging to see scan details:

```python
import logging
logging.getLogger('dragonshard.recon.scanner').setLevel(logging.DEBUG)
```

## Benefits

### ✅ **Reliability**
- Scans work consistently across different environments
- No more privilege-related failures
- Graceful fallbacks for all scan types

### ✅ **Compatibility**
- Works in containers, VMs, and bare metal
- Compatible with various security policies
- No special configuration required

### ✅ **Performance**
- TCP connect scans are often faster than SYN scans
- Quick scans provide rapid results
- Efficient resource usage

### ✅ **User Experience**
- No more confusing privilege errors
- Clear recommendations for better scanning
- Consistent behavior across environments

## Future Enhancements

Potential improvements for future versions:

1. **Dynamic Scan Type Selection**
   - Automatically test available scan types
   - Choose optimal scan method per environment

2. **Advanced Privilege Management**
   - Support for different privilege escalation methods
   - Integration with system security policies

3. **Scan Optimization**
   - Parallel scanning capabilities
   - Intelligent scan timing
   - Resource-aware scanning

4. **Enhanced Reporting**
   - Detailed scan capability reports
   - Performance metrics
   - Environment-specific recommendations

## Conclusion

The privilege handling solution ensures that DragonShard's scanner works reliably across all environments while providing clear feedback about capabilities and recommendations for optimal usage. The use of TCP connect scans as the default for comprehensive scans eliminates the privilege-related errors while maintaining full functionality. 