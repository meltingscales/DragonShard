#!/usr/bin/env python3
"""
DragonShard Database Manager

Handles database connections, session management, and provides
repository classes for all DragonShard data models.
"""

import logging
import os
from contextlib import contextmanager
from typing import Any, Dict, List, Optional, Type, TypeVar

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session as DBSession, sessionmaker
from sqlalchemy.pool import StaticPool

from dragonshard.data.models import Base

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=Base)


class DatabaseManager:
    """Manages database connections and provides repository access."""

    def __init__(self, database_url: Optional[str] = None):
        """
        Initialize the database manager.

        Args:
            database_url: Database connection URL. If None, uses environment variable
                         or defaults to SQLite in-memory database.
        """
        self.database_url = database_url or self._get_database_url()
        self.engine: Optional[Engine] = None
        self.SessionLocal: Optional[sessionmaker] = None
        self._initialize_engine()

    def _get_database_url(self) -> str:
        """Get database URL from environment or use default."""
        # Check environment variables
        if os.getenv("DATABASE_URL"):
            return os.getenv("DATABASE_URL")
        
        # Check for PostgreSQL
        if all(os.getenv(var) for var in ["POSTGRES_HOST", "POSTGRES_PORT", "POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD"]):
            host = os.getenv("POSTGRES_HOST", "localhost")
            port = os.getenv("POSTGRES_PORT", "5432")
            db = os.getenv("POSTGRES_DB", "dragonshard")
            user = os.getenv("POSTGRES_USER", "dragonshard")
            password = os.getenv("POSTGRES_PASSWORD", "dragonshard")
            return f"postgresql://{user}:{password}@{host}:{port}/{db}"
        
        # Check for MySQL
        if all(os.getenv(var) for var in ["MYSQL_HOST", "MYSQL_PORT", "MYSQL_DATABASE", "MYSQL_USER", "MYSQL_PASSWORD"]):
            host = os.getenv("MYSQL_HOST", "localhost")
            port = os.getenv("MYSQL_PORT", "3306")
            db = os.getenv("MYSQL_DATABASE", "dragonshard")
            user = os.getenv("MYSQL_USER", "dragonshard")
            password = os.getenv("MYSQL_PASSWORD", "dragonshard")
            return f"mysql+pymysql://{user}:{password}@{host}:{port}/{db}"
        
        # Default to SQLite
        return "sqlite:///dragonshard.db"

    def _initialize_engine(self):
        """Initialize the database engine."""
        try:
            if self.database_url.startswith("sqlite"):
                # SQLite configuration
                self.engine = create_engine(
                    self.database_url,
                    connect_args={"check_same_thread": False},
                    poolclass=StaticPool,
                    echo=False,
                )
            else:
                # PostgreSQL/MySQL configuration
                self.engine = create_engine(
                    self.database_url,
                    pool_pre_ping=True,
                    pool_recycle=300,
                    echo=False,
                )

            self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
            logger.info(f"Database engine initialized with URL: {self.database_url}")

        except Exception as e:
            logger.error(f"Failed to initialize database engine: {e}")
            raise

    def create_tables(self):
        """Create all database tables."""
        try:
            Base.metadata.create_all(bind=self.engine)
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Failed to create database tables: {e}")
            raise

    def drop_tables(self):
        """Drop all database tables."""
        try:
            Base.metadata.drop_all(bind=self.engine)
            logger.info("Database tables dropped successfully")
        except Exception as e:
            logger.error(f"Failed to drop database tables: {e}")
            raise

    def check_connection(self) -> bool:
        """Check if database connection is working."""
        try:
            with self.get_session() as session:
                session.execute(text("SELECT 1"))
                return True
        except Exception as e:
            logger.error(f"Database connection check failed: {e}")
            return False

    @contextmanager
    def get_session(self):
        """Get a database session context manager."""
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            session.close()

    def get_repository(self, model_class: Type[T]) -> "Repository":
        """
        Get a repository for a specific model class.

        Args:
            model_class: The model class to create a repository for

        Returns:
            Repository instance for the model class
        """
        return Repository(self, model_class)


class Repository:
    """Generic repository for database operations."""

    def __init__(self, db_manager: DatabaseManager, model_class: Type[T]):
        """
        Initialize the repository.

        Args:
            db_manager: Database manager instance
            model_class: The model class this repository handles
        """
        self.db_manager = db_manager
        self.model_class = model_class

    def create(self, **kwargs) -> T:
        """
        Create a new record.

        Args:
            **kwargs: Model attributes

        Returns:
            Created model instance
        """
        with self.db_manager.get_session() as session:
            instance = self.model_class(**kwargs)
            session.add(instance)
            session.flush()
            session.refresh(instance)
            # Return a copy of the instance to avoid session binding issues
            return self.model_class(**{c.name: getattr(instance, c.name) for c in instance.__table__.columns})

    def get_by_id(self, id_value: str) -> Optional[T]:
        """
        Get a record by its primary key.

        Args:
            id_value: Primary key value

        Returns:
            Model instance or None
        """
        with self.db_manager.get_session() as session:
            instance = session.query(self.model_class).filter_by(
                **{self.model_class.__table__.primary_key.columns.keys()[0]: id_value}
            ).first()
            if instance:
                # Return a copy to avoid session binding issues
                return self.model_class(**{c.name: getattr(instance, c.name) for c in instance.__table__.columns})
            return None

    def get_all(self) -> List[T]:
        """
        Get all records.

        Returns:
            List of model instances
        """
        with self.db_manager.get_session() as session:
            instances = session.query(self.model_class).all()
            # Return copies to avoid session binding issues
            return [self.model_class(**{c.name: getattr(instance, c.name) for c in instance.__table__.columns}) for instance in instances]

    def update(self, id_value: str, **kwargs) -> Optional[T]:
        """
        Update a record.

        Args:
            id_value: Primary key value
            **kwargs: Attributes to update

        Returns:
            Updated model instance or None
        """
        with self.db_manager.get_session() as session:
            instance = session.query(self.model_class).filter_by(
                **{self.model_class.__table__.primary_key.columns.keys()[0]: id_value}
            ).first()
            
            if instance:
                for key, value in kwargs.items():
                    setattr(instance, key, value)
                session.flush()
                session.refresh(instance)
                # Return a copy to avoid session binding issues
                return self.model_class(**{c.name: getattr(instance, c.name) for c in instance.__table__.columns})
            
            return None

    def delete(self, id_value: str) -> bool:
        """
        Delete a record.

        Args:
            id_value: Primary key value

        Returns:
            True if deleted, False if not found
        """
        with self.db_manager.get_session() as session:
            instance = session.query(self.model_class).filter_by(
                **{self.model_class.__table__.primary_key.columns.keys()[0]: id_value}
            ).first()
            
            if instance:
                session.delete(instance)
                return True
            
            return False

    def filter_by(self, **kwargs) -> List[T]:
        """
        Filter records by attributes.

        Args:
            **kwargs: Filter criteria

        Returns:
            List of matching model instances
        """
        with self.db_manager.get_session() as session:
            instances = session.query(self.model_class).filter_by(**kwargs).all()
            # Return copies to avoid session binding issues
            return [self.model_class(**{c.name: getattr(instance, c.name) for c in instance.__table__.columns}) for instance in instances]

    def count(self) -> int:
        """
        Get total count of records.

        Returns:
            Total count
        """
        with self.db_manager.get_session() as session:
            return session.query(self.model_class).count()

    def exists(self, id_value: str) -> bool:
        """
        Check if a record exists.

        Args:
            id_value: Primary key value

        Returns:
            True if exists, False otherwise
        """
        return self.get_by_id(id_value) is not None


# Global database manager instance
_db_manager: Optional[DatabaseManager] = None


def get_database_manager() -> DatabaseManager:
    """Get the global database manager instance."""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
    return _db_manager


def initialize_database(database_url: Optional[str] = None) -> DatabaseManager:
    """
    Initialize the database and create tables.

    Args:
        database_url: Optional database URL

    Returns:
        Database manager instance
    """
    global _db_manager
    _db_manager = DatabaseManager(database_url)
    _db_manager.create_tables()
    return _db_manager


def get_repository(model_class: Type[T]) -> Repository:
    """
    Get a repository for a specific model class.

    Args:
        model_class: The model class to create a repository for

    Returns:
        Repository instance for the model class
    """
    db_manager = get_database_manager()
    return db_manager.get_repository(model_class) 