#!/usr/bin/env python3
"""
DragonShard Database Reset Script

Resets both DragonShard's SQLite database and the MySQL test database
to their original state for clean testing.
"""

import argparse
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from dragonshard.data.database import initialize_database, get_database_manager

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def reset_sqlite_database():
    """Reset DragonShard's SQLite database to original state."""
    try:
        logger.info("🗄️  Resetting DragonShard SQLite database...")
        
        # Get database manager
        db_manager = get_database_manager()
        
        # Drop all tables
        logger.info("Dropping all database tables...")
        db_manager.drop_tables()
        
        # Recreate tables
        logger.info("Recreating database tables...")
        db_manager.create_tables()
        
        # Verify reset
        if db_manager.check_connection():
            logger.info("✅ SQLite database reset successful")
            return True
        else:
            logger.error("❌ SQLite database reset failed - connection check failed")
            return False
            
    except Exception as e:
        logger.error(f"❌ SQLite database reset failed: {e}")
        return False


def reset_mysql_database():
    """Reset MySQL test database to original state."""
    try:
        logger.info("🐳 Resetting MySQL test database...")
        
        # Stop all test containers and remove volumes
        logger.info("Stopping test containers and removing volumes...")
        result = subprocess.run(
            ["docker-compose", "-f", "docker-compose.test.yml", "down", "-v"],
            capture_output=True,
            text=True,
            cwd=project_root
        )
        
        if result.returncode != 0:
            logger.warning(f"Warning: docker-compose down failed: {result.stderr}")
        
        # Start MySQL container
        logger.info("Starting MySQL container...")
        result = subprocess.run(
            ["docker-compose", "-f", "docker-compose.test.yml", "up", "-d", "mysql"],
            capture_output=True,
            text=True,
            cwd=project_root
        )
        
        if result.returncode != 0:
            logger.error(f"❌ Failed to start MySQL container: {result.stderr}")
            return False
        
        # Wait for MySQL to be ready
        logger.info("⏳ Waiting for MySQL to be ready...")
        max_attempts = 60  # 5 minutes max
        for attempt in range(max_attempts):
            try:
                result = subprocess.run(
                    ["docker-compose", "-f", "docker-compose.test.yml", "exec", "-T", "mysql", "mysqladmin", "ping", "-h", "localhost"],
                    capture_output=True,
                    text=True,
                    cwd=project_root,
                    timeout=10
                )
                
                if result.returncode == 0:
                    logger.info("✅ MySQL is ready")
                    break
                    
            except subprocess.TimeoutExpired:
                pass
            
            if attempt == max_attempts - 1:
                logger.error("❌ MySQL failed to start within timeout")
                return False
            
            time.sleep(5)
        
        # Verify MySQL is working by checking if init.sql was executed
        logger.info("Verifying MySQL database initialization...")
        result = subprocess.run(
            ["docker-compose", "-f", "docker-compose.test.yml", "exec", "-T", "mysql", "mysql", "-u", "testuser", "-ptestpass", "testdb", "-e", "SELECT COUNT(*) FROM users;"],
            capture_output=True,
            text=True,
            cwd=project_root,
            timeout=30
        )
        
        if result.returncode == 0 and "4" in result.stdout:
            logger.info("✅ MySQL database reset successful")
            return True
        else:
            logger.error(f"❌ MySQL database verification failed: {result.stderr}")
            return False
            
    except Exception as e:
        logger.error(f"❌ MySQL database reset failed: {e}")
        return False


def show_database_status():
    """Show current database status."""
    try:
        logger.info("📊 Checking DragonShard database status...")
        
        # Import models for status check
        from dragonshard.data.models import Session, Host, Service, Vulnerability
        
        db_manager = get_database_manager()
        
        if not db_manager.check_connection():
            logger.error("❌ Database connection failed")
            return False
        
        # Get repositories
        session_repo = db_manager.get_repository(Session)
        host_repo = db_manager.get_repository(Host)
        service_repo = db_manager.get_repository(Service)
        vuln_repo = db_manager.get_repository(Vulnerability)
        
        logger.info(f"📊 Database Status:")
        logger.info(f"  Sessions: {session_repo.count()}")
        logger.info(f"  Hosts: {host_repo.count()}")
        logger.info(f"  Services: {service_repo.count()}")
        logger.info(f"  Vulnerabilities: {vuln_repo.count()}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Database status check failed: {e}")
        return False


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="DragonShard Database Reset Tool")
    parser.add_argument(
        "--sqlite-only",
        action="store_true",
        help="Only reset SQLite database"
    )
    parser.add_argument(
        "--mysql-only",
        action="store_true",
        help="Only reset MySQL database"
    )
    parser.add_argument(
        "--status-only",
        action="store_true",
        help="Only show database status"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    success = True
    
    if args.status_only:
        success = show_database_status()
    else:
        if not args.mysql_only:
            success &= reset_sqlite_database()
        
        if not args.sqlite_only:
            success &= reset_mysql_database()
        
        if success:
            logger.info("✅ Database reset completed successfully!")
            show_database_status()
    
    if success:
        logger.info("🎉 All operations completed successfully!")
        sys.exit(0)
    else:
        logger.error("💥 Some operations failed!")
        sys.exit(1)


if __name__ == "__main__":
    main() 