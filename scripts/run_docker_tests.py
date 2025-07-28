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


def wait_for_container_ready(container_name: str, max_wait: int = 60) -> bool:
    """
    Wait for a container to be ready by checking its status.
    
    Args:
        container_name: Name of the container to check
        max_wait: Maximum time to wait in seconds
    
    Returns:
        True if container is ready, False if timeout
    """
    print(f"⏳ Waiting for container {container_name} to be ready...")
    
    start_time = time.time()
    while time.time() - start_time < max_wait:
        try:
            # Check if container is running
            result = subprocess.run([
                'docker', 'inspect', '-f', '{{.State.Status}}', container_name
            ], capture_output=True, text=True, check=True)
            
            status = result.stdout.strip()
            if status == 'running':
                # Check if container is healthy (if health check is configured)
                try:
                    health_result = subprocess.run([
                        'docker', 'inspect', '-f', '{{.State.Health.Status}}', container_name
                    ], capture_output=True, text=True, check=True)
                    
                    health_status = health_result.stdout.strip()
                    if health_status == 'healthy' or health_status == '<nil>':
                        print(f"✅ Container {container_name} is ready!")
                        return True
                    elif health_status == 'unhealthy':
                        print(f"❌ Container {container_name} is unhealthy")
                        return False
                    else:
                        print(f"⏳ Container {container_name} starting up... ({health_status})")
                except subprocess.CalledProcessError:
                    # No health check configured, assume ready if running
                    print(f"✅ Container {container_name} is ready (no health check)")
                    return True
            else:
                print(f"⏳ Container {container_name} status: {status}")
                
        except subprocess.CalledProcessError:
            print(f"⏳ Container {container_name} not found yet...")
        
        time.sleep(2)
    
    print(f"❌ Container {container_name} failed to start within {max_wait} seconds")
    return False


def check_container_health(container_name: str) -> bool:
    """
    Check if a container is healthy and responding.
    
    Args:
        container_name: Name of the container to check
    
    Returns:
        True if container is healthy, False otherwise
    """
    try:
        # Get container IP
        ip_result = subprocess.run([
            'docker', 'inspect', '-f', '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', container_name
        ], capture_output=True, text=True, check=True)
        
        container_ip = ip_result.stdout.strip()
        if not container_ip:
            print(f"❌ Could not get IP for container {container_name}")
            return False
        
        # Try to connect to the container (basic health check)
        try:
            # Use curl to check if container is responding
            curl_result = subprocess.run([
                'curl', '-f', '-s', '-o', '/dev/null', '-w', '%{http_code}',
                f'http://{container_ip}:80'
            ], capture_output=True, text=True, timeout=10)
            
            if curl_result.returncode == 0:
                print(f"✅ Container {container_name} is responding on port 80")
                return True
            else:
                print(f"⚠️  Container {container_name} not responding on port 80 (HTTP {curl_result.stdout})")
                return False
                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # curl not available, try basic port check
            try:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((container_ip, 80))
                sock.close()
                
                if result == 0:
                    print(f"✅ Container {container_name} is responding on port 80")
                    return True
                else:
                    print(f"⚠️  Container {container_name} not responding on port 80")
                    return False
            except Exception as e:
                print(f"⚠️  Could not check container health: {e}")
                return False
                
    except subprocess.CalledProcessError as e:
        print(f"❌ Error checking container health: {e}")
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
        
        # Wait for containers to be ready with intelligent checking
        containers = ['dragonshard-dvwa-test', 'dragonshard-juice-shop-test', 
                     'dragonshard-vulhub-test']
        
        ready_containers = []
        for container in containers:
            if wait_for_container_ready(container, max_wait=45):
                if check_container_health(container):
                    ready_containers.append(container)
                else:
                    print(f"⚠️  Container {container} started but health check failed")
            else:
                print(f"❌ Container {container} failed to start")
        
        if ready_containers:
            print(f"✅ {len(ready_containers)} containers are ready: {ready_containers}")
            return True
        else:
            print("❌ No containers are ready")
            return False
        
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