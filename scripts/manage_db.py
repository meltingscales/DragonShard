#!/usr/bin/env python3
"""
DragonShard Database Management Script

Provides commands for initializing, migrating, and managing the database.
"""

import argparse
import logging
import os
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from dragonshard.data.database import initialize_database, get_database_manager
from dragonshard.data.models import Base

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def init_db(database_url: str = None):
    """Initialize the database and create tables."""
    try:
        logger.info("Initializing database...")
        db_manager = initialize_database(database_url)
        
        if db_manager.check_connection():
            logger.info("Database connection successful")
        else:
            logger.error("Database connection failed")
            return False
            
        logger.info("Database initialized successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        return False


def create_tables():
    """Create database tables."""
    try:
        logger.info("Creating database tables...")
        db_manager = get_database_manager()
        db_manager.create_tables()
        logger.info("Database tables created successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to create tables: {e}")
        return False


def drop_tables():
    """Drop all database tables."""
    try:
        logger.info("Dropping database tables...")
        db_manager = get_database_manager()
        db_manager.drop_tables()
        logger.info("Database tables dropped successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to drop tables: {e}")
        return False


def check_connection():
    """Check database connection."""
    try:
        logger.info("Checking database connection...")
        db_manager = get_database_manager()
        
        if db_manager.check_connection():
            logger.info("Database connection successful")
            return True
        else:
            logger.error("Database connection failed")
            return False
            
    except Exception as e:
        logger.error(f"Database connection check failed: {e}")
        return False


def run_migrations():
    """Run database migrations."""
    try:
        logger.info("Running database migrations...")
        
        # Import alembic here to avoid dependency issues
        from alembic import command
        from alembic.config import Config
        
        # Create Alembic configuration
        alembic_cfg = Config("alembic.ini")
        
        # Run migrations
        command.upgrade(alembic_cfg, "head")
        
        logger.info("Database migrations completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to run migrations: {e}")
        return False


def create_migration(message: str):
    """Create a new migration."""
    try:
        logger.info(f"Creating migration: {message}")
        
        # Import alembic here to avoid dependency issues
        from alembic import command
        from alembic.config import Config
        
        # Create Alembic configuration
        alembic_cfg = Config("alembic.ini")
        
        # Create migration
        command.revision(alembic_cfg, message=message, autogenerate=True)
        
        logger.info("Migration created successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to create migration: {e}")
        return False


def show_status():
    """Show database status."""
    try:
        logger.info("Checking database status...")
        db_manager = get_database_manager()
        
        # Check connection
        if db_manager.check_connection():
            logger.info("✓ Database connection: OK")
        else:
            logger.error("✗ Database connection: FAILED")
            return False
        
        # Check tables
        try:
            from dragonshard.data.models import Session, Host, Service, Vulnerability
            session_repo = db_manager.get_repository(Session)
            host_repo = db_manager.get_repository(Host)
            service_repo = db_manager.get_repository(Service)
            vuln_repo = db_manager.get_repository(Vulnerability)
            
            logger.info(f"✓ Sessions: {session_repo.count()}")
            logger.info(f"✓ Hosts: {host_repo.count()}")
            logger.info(f"✓ Services: {service_repo.count()}")
            logger.info(f"✓ Vulnerabilities: {vuln_repo.count()}")
            
        except Exception as e:
            logger.error(f"✗ Table status check failed: {e}")
            return False
        
        logger.info("Database status: OK")
        return True
        
    except Exception as e:
        logger.error(f"Database status check failed: {e}")
        return False


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="DragonShard Database Management")
    parser.add_argument(
        "command",
        choices=[
            "init", "create-tables", "drop-tables", "check", 
            "migrate", "create-migration", "status"
        ],
        help="Database command to execute"
    )
    parser.add_argument(
        "--database-url",
        help="Database URL (overrides environment variables)"
    )
    parser.add_argument(
        "--message",
        help="Migration message (for create-migration command)"
    )
    
    args = parser.parse_args()
    
    # Set database URL if provided
    if args.database_url:
        os.environ["DATABASE_URL"] = args.database_url
    
    success = False
    
    if args.command == "init":
        success = init_db(args.database_url)
    elif args.command == "create-tables":
        success = create_tables()
    elif args.command == "drop-tables":
        success = drop_tables()
    elif args.command == "check":
        success = check_connection()
    elif args.command == "migrate":
        success = run_migrations()
    elif args.command == "create-migration":
        if not args.message:
            logger.error("Migration message is required")
            sys.exit(1)
        success = create_migration(args.message)
    elif args.command == "status":
        success = show_status()
    
    if success:
        logger.info("Command completed successfully")
        sys.exit(0)
    else:
        logger.error("Command failed")
        sys.exit(1)


if __name__ == "__main__":
    main() 