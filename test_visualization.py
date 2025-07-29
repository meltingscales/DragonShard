#!/usr/bin/env python3
"""
Test script for DragonShard Genetic Algorithm Visualization.

This script runs the genetic algorithm visualizer to demonstrate
real-time mutation tracking and evolution visualization.
"""

import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.dirname(__file__))

def main():
    """Main function to run the visualization test."""
    print("🧬 DragonShard Genetic Algorithm Visualization Test")
    print("=" * 60)
    
    try:
        # Import and run the visualizer
        from dragonshard.tests.test_genetic_visualization import main as run_visualizer
        run_visualizer()
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Make sure you're running this from the project root directory.")
        return 1
    except Exception as e:
        print(f"❌ Error running visualization: {e}")
        print("This might be due to missing test environment or GUI issues.")
        print("Try running: make test-env-start")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main()) 