#!/usr/bin/env python3
"""
DragonShard Data Module

This module provides database models, session management, and state graph
functionality for persistent storage of DragonShard data.
"""

from dragonshard.data.database import (
    DatabaseManager,
    Repository,
    get_database_manager,
    get_repository,
    initialize_database,
)
from dragonshard.data.models import (
    AuthCredentials,
    AuthMethod,
    Base,
    Connection,
    Host,
    HostStatus,
    Session,
    SessionState,
    Service,
    ServiceType,
    Vulnerability,
    VulnerabilityLevel,
)
from dragonshard.data.session_manager_db import DatabaseSessionManager
from dragonshard.data.state_graph_db import DatabaseStateGraph

__all__ = [
    # Database management
    "DatabaseManager",
    "Repository",
    "get_database_manager",
    "get_repository",
    "initialize_database",
    
    # Models
    "Base",
    "Session",
    "SessionState",
    "AuthCredentials",
    "AuthMethod",
    "Host",
    "HostStatus",
    "Service",
    "ServiceType",
    "Vulnerability",
    "VulnerabilityLevel",
    "Connection",
    
    # Database-backed implementations
    "DatabaseSessionManager",
    "DatabaseStateGraph",
] 