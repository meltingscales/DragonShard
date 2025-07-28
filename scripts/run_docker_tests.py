#!/usr/bin/env python3
"""
Script to run Docker-based integration tests for DragonShard.
"""

import subprocess
import sys
import time
import os
from pathlib import Path


def check_docker_available():
    """Check if Docker is available and running."""
    try:
        result = subprocess.run(['docker', 'version'], 
                              capture_output=True, timeout=10)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def start_test_containers():
    """Start test containers using Docker Compose."""
    print("🐳 Starting test containers...")
    
    try:
        # Start containers in background
        subprocess.run([
            'docker-compose', '-f', 'docker-compose.test.yml', 'up', '-d'
        ], check=True)
        
        print("✅ Test containers started")
        
        # Wait for containers to be ready
        print("⏳ Waiting for containers to be ready...")
        time.sleep(45)  # Give containers time to start
        
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to start containers: {e}")
        return False


def stop_test_containers():
    """Stop and clean up test containers."""
    print("🧹 Cleaning up test containers...")
    
    try:
        subprocess.run([
            'docker-compose', '-f', 'docker-compose.test.yml', 'down'
        ], check=True)
        
        print("✅ Test containers cleaned up")
        
    except subprocess.CalledProcessError as e:
        print(f"⚠️  Failed to clean up containers: {e}")


def run_docker_tests():
    """Run the Docker-based integration tests."""
    print("🧪 Running Docker-based integration tests...")
    
    try:
        # Run the Docker tests
        result = subprocess.run([
            'python', '-m', 'pytest', 
            'dragonshard/tests/test_docker_scanner.py',
            '-v', '-s'
        ], check=True)
        
        print("✅ Docker tests completed successfully")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Docker tests failed: {e}")
        return False


def main():
    """Main function to run Docker tests."""
    print("🐉 DragonShard Docker Integration Tests")
    print("=" * 50)
    
    # Check if Docker is available
    if not check_docker_available():
        print("❌ Docker is not available or not running")
        print("Please install Docker and ensure it's running")
        sys.exit(1)
    
    print("✅ Docker is available")
    
    # Change to project root
    project_root = Path(__file__).parent.parent
    os.chdir(project_root)
    
    try:
        # Start containers
        if not start_test_containers():
            sys.exit(1)
        
        # Run tests
        if not run_docker_tests():
            sys.exit(1)
        
        print("\n🎉 All Docker integration tests passed!")
        
    except KeyboardInterrupt:
        print("\n⚠️  Tests interrupted by user")
        sys.exit(1)
        
    finally:
        # Always clean up containers
        stop_test_containers()


if __name__ == '__main__':
    main() 