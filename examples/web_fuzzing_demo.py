#!/usr/bin/env python3
"""
Web Fuzzing Visualization Demo

This script demonstrates how to use the web fuzzing visualization
to test websites for vulnerabilities with real-time mutation tree tracking.
"""

import sys
import os
import tkinter as tk
from tkinter import messagebox

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

def main():
    """Main demonstration function."""
    print("🌐 DragonShard Web Fuzzing Visualization Demo")
    print("=" * 60)
    print()
    print("This demo will show you how to use the web fuzzing visualization")
    print("to test websites for vulnerabilities with real-time mutation tree tracking.")
    print()
    print("Features:")
    print("✅ Real-time web fuzzing against vulnerable targets")
    print("✅ Mutation tree visualization showing payload evolution")
    print("✅ Vulnerability discovery tracking with confidence scores")
    print("✅ HTTP response analysis and anomaly detection")
    print("✅ Multi-payload type support (SQL Injection, XSS, etc.)")
    print("✅ Export capabilities for results and mutation tree data")
    print()
    print("Prerequisites:")
    print("1. Make sure you have tkinter installed")
    print("2. Optional: Start vulnerable test containers with 'make test-env-start'")
    print("3. Have a target URL ready for testing")
    print()
    
    # Check if tkinter is available
    try:
        import tkinter
        print("✅ Tkinter is available")
    except ImportError:
        print("❌ Tkinter is not available. Please install python3-tk")
        return 1
    
    # Check if test environment is available
    try:
        import requests
        response = requests.get("http://localhost:8082", timeout=2)
        print("✅ Test environment is available (vulnerable containers running)")
        print("   You can use http://localhost:8082 as your target URL")
    except:
        print("⚠️  Test environment not available")
        print("   Run 'make test-env-start' to start vulnerable containers")
        print("   Or use any other target URL for testing")
    
    print()
    print("Starting web fuzzing visualization...")
    print("In the GUI, you can:")
    print("- Set your target URL")
    print("- Choose payload type (SQL Injection, XSS, etc.)")
    print("- Select HTTP method (GET, POST, etc.)")
    print("- Watch real-time mutation tree evolution")
    print("- Monitor vulnerability discovery")
    print("- Export results when finished")
    print()
    
    try:
        from dragonshard.visualizer.web_fuzzing_viz import main as run_web_viz
        run_web_viz()
    except Exception as e:
        print(f"❌ Error starting web fuzzing visualization: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main()) 