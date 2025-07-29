#!/usr/bin/env python3
"""
Test script for DragonShard Web Fuzzing Visualization.

This script runs the web fuzzing visualizer to demonstrate
real-time mutation tree tracking and vulnerability discovery
against websites.
"""

import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

def main():
    """Main function to run the web fuzzing visualization test."""
    print("🌐 DragonShard Web Fuzzing Visualization Test")
    print("=" * 60)
    
    try:
        # Import and run the web fuzzing visualizer
        from dragonshard.visualizer.web_fuzzing_viz import main as run_web_viz
        run_web_viz()
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Make sure you're running this from the project root directory.")
        return 1
    except Exception as e:
        print(f"❌ Error running web fuzzing visualization: {e}")
        print("This might be due to missing test environment or GUI issues.")
        print("Try running: make test-env-start")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main()) 