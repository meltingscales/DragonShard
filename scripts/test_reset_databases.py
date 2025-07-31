#!/usr/bin/env python3
"""
Test script for database reset functionality.
"""

import subprocess
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from dragonshard.data.database import get_database_manager
from dragonshard.data.models import Session, Host, Service, Vulnerability


def test_sqlite_reset():
    """Test SQLite database reset functionality."""
    print("🧪 Testing SQLite database reset...")
    
    try:
        # Get database manager
        db_manager = get_database_manager()
        
        # Check initial state
        session_repo = db_manager.get_repository(Session)
        host_repo = db_manager.get_repository(Host)
        service_repo = db_manager.get_repository(Service)
        vuln_repo = db_manager.get_repository(Vulnerability)
        
        initial_counts = {
            'sessions': session_repo.count(),
            'hosts': host_repo.count(),
            'services': service_repo.count(),
            'vulnerabilities': vuln_repo.count()
        }
        
        print(f"Initial counts: {initial_counts}")
        
        # Run reset script
        result = subprocess.run(
            [sys.executable, "scripts/reset_databases.py", "--sqlite-only"],
            capture_output=True,
            text=True,
            cwd=project_root
        )
        
        if result.returncode != 0:
            print(f"❌ Reset failed: {result.stderr}")
            return False
        
        # Check final state
        final_counts = {
            'sessions': session_repo.count(),
            'hosts': host_repo.count(),
            'services': service_repo.count(),
            'vulnerabilities': vuln_repo.count()
        }
        
        print(f"Final counts: {final_counts}")
        
        # Verify all counts are 0 (fresh state)
        for table, count in final_counts.items():
            if count != 0:
                print(f"❌ {table} count is {count}, expected 0")
                return False
        
        print("✅ SQLite reset test passed!")
        return True
        
    except Exception as e:
        print(f"❌ SQLite reset test failed: {e}")
        return False


def test_mysql_reset():
    """Test MySQL database reset functionality."""
    print("🧪 Testing MySQL database reset...")
    
    try:
        # Check if Docker is available
        result = subprocess.run(
            ["docker", "--version"],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print("⚠️  Docker not available, skipping MySQL test")
            return True
        
        # Run MySQL reset
        result = subprocess.run(
            [sys.executable, "scripts/reset_databases.py", "--mysql-only"],
            capture_output=True,
            text=True,
            cwd=project_root
        )
        
        if result.returncode != 0:
            print(f"❌ MySQL reset failed: {result.stderr}")
            return False
        
        print("✅ MySQL reset test passed!")
        return True
        
    except Exception as e:
        print(f"❌ MySQL reset test failed: {e}")
        return False


def main():
    """Main test function."""
    print("🧪 Testing database reset functionality...")
    
    success = True
    
    # Test SQLite reset
    success &= test_sqlite_reset()
    
    # Test MySQL reset (if Docker available)
    success &= test_mysql_reset()
    
    if success:
        print("🎉 All database reset tests passed!")
        sys.exit(0)
    else:
        print("💥 Some database reset tests failed!")
        sys.exit(1)


if __name__ == "__main__":
    main() 