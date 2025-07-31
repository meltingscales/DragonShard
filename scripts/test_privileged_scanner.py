#!/usr/bin/env python3
"""
Test script for privileged scanner functionality.
"""

import sys
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from dragonshard.recon.scanner import (
    check_privileges, 
    get_scan_capabilities, 
    get_scan_recommendations,
    run_scan
)


def test_privilege_check():
    """Test privilege checking functionality."""
    print("🔐 Testing privilege checking...")
    
    has_privileges = check_privileges()
    print(f"✅ Has admin privileges: {has_privileges}")
    
    capabilities = get_scan_capabilities()
    print("📊 Scan capabilities:")
    for capability, available in capabilities.items():
        status = "✅" if available else "❌"
        print(f"  {status} {capability}: {available}")
    
    return True


def test_scan_recommendations():
    """Test scan recommendations functionality."""
    print("\n💡 Testing scan recommendations...")
    
    recommendations = get_scan_recommendations()
    print(f"Current status: {recommendations['current_status']}")
    print("Recommendations:")
    for rec in recommendations['recommendations']:
        print(f"  • {rec}")
    
    return True


def test_scan_functionality():
    """Test scan functionality with localhost."""
    print("\n🎯 Testing scan functionality...")
    
    try:
        # Test with localhost
        target = "127.0.0.1"
        print(f"Scanning {target}...")
        
        # Test quick scan (should work without privileges)
        print("Running quick scan...")
        quick_results = run_scan(target, "quick")
        print(f"✅ Quick scan completed: {len(quick_results)} hosts found")
        
        # Test comprehensive scan (may require privileges)
        print("Running comprehensive scan...")
        comprehensive_results = run_scan(target, "comprehensive")
        print(f"✅ Comprehensive scan completed: {len(comprehensive_results)} hosts found")
        
        # Show some results
        for host, host_data in comprehensive_results.items():
            print(f"  Host: {host} - Status: {host_data.get('status', 'unknown')}")
            tcp_ports = len(host_data.get('tcp', {}))
            udp_ports = len(host_data.get('udp', {}))
            print(f"    TCP ports: {tcp_ports}, UDP ports: {udp_ports}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error during scan test: {e}")
        return False


def test_privilege_handling():
    """Test that privilege handling works correctly."""
    print("\n🛡️ Testing privilege handling...")
    
    try:
        # Test that scans work regardless of privileges
        target = "127.0.0.1"
        
        # Quick scan should always work
        quick_results = run_scan(target, "quick")
        if quick_results and len(quick_results) > 0:
            print("✅ Quick scan works without privileges")
        else:
            print("❌ Quick scan failed")
            return False
        
        # Comprehensive scan should work with fallback
        comprehensive_results = run_scan(target, "comprehensive")
        if comprehensive_results and len(comprehensive_results) > 0:
            print("✅ Comprehensive scan works (with fallback if needed)")
        else:
            print("❌ Comprehensive scan failed")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Error during privilege handling test: {e}")
        return False


def main():
    """Main test function."""
    print("🧪 Testing privileged scanner functionality...")
    
    success = True
    
    # Test privilege checking
    success &= test_privilege_check()
    
    # Test scan recommendations
    success &= test_scan_recommendations()
    
    # Test scan functionality
    success &= test_scan_functionality()
    
    # Test privilege handling
    success &= test_privilege_handling()
    
    if success:
        print("\n🎉 All privileged scanner tests passed!")
        print("✅ The scanner now handles admin privileges correctly")
        print("💡 Use 'sudo make start-api' for better scan capabilities")
        sys.exit(0)
    else:
        print("\n💥 Some privileged scanner tests failed!")
        print("⚠️  The scanner may not work correctly")
        sys.exit(1)


if __name__ == "__main__":
    main() 