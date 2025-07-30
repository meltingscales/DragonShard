#!/usr/bin/env python3
"""
DragonShard Database Models

SQLAlchemy models for persistent storage of session data, state graphs,
and other DragonShard data structures.
"""

import json
import time
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum as SQLEnum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    event,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.pool import StaticPool

# Create base class for declarative models
Base = declarative_base()


class SessionState(str, Enum):
    """Session states."""

    UNAUTHENTICATED = "unauthenticated"
    AUTHENTICATED = "authenticated"
    EXPIRED = "expired"
    LOCKED = "locked"
    ERROR = "error"


class AuthMethod(str, Enum):
    """Authentication methods."""

    NONE = "none"
    BASIC = "basic"
    FORM = "form"
    TOKEN = "token"
    COOKIE = "cookie"
    OAUTH = "oauth"


class ServiceType(str, Enum):
    """Types of services."""

    HTTP = "http"
    HTTPS = "https"
    FTP = "ftp"
    SSH = "ssh"
    SMTP = "smtp"
    DNS = "dns"
    DATABASE = "database"
    API = "api"
    WEBSOCKET = "websocket"
    UNKNOWN = "unknown"


class HostStatus(str, Enum):
    """Host status."""

    DISCOVERED = "discovered"
    SCANNED = "scanned"
    VULNERABLE = "vulnerable"
    COMPROMISED = "compromised"
    BLOCKED = "blocked"
    OFFLINE = "offline"


class VulnerabilityLevel(str, Enum):
    """Vulnerability severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Session(Base):
    """Session data and state."""

    __tablename__ = "sessions"

    session_id = Column(String(255), primary_key=True)
    target_host = Column(String(255), nullable=False)
    state = Column(SQLEnum(SessionState), nullable=False, default=SessionState.UNAUTHENTICATED)
    auth_method = Column(SQLEnum(AuthMethod), nullable=False, default=AuthMethod.NONE)
    cookies = Column(Text, default="{}")  # JSON string
    headers = Column(Text, default="{}")  # JSON string
    created_at = Column(Float, nullable=False, default=time.time)
    last_used = Column(Float, nullable=False, default=time.time)
    expires_at = Column(Float, nullable=True)
    login_url = Column(String(500), nullable=True)
    logout_url = Column(String(500), nullable=True)
    csrf_token = Column(String(255), nullable=True)
    user_agent = Column(String(255), default="DragonShard/1.0")
    proxy = Column(String(255), nullable=True)

    # Relationships
    credentials = relationship("AuthCredentials", back_populates="session", uselist=False)

    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary."""
        return {
            "session_id": self.session_id,
            "target_host": self.target_host,
            "state": self.state.value,
            "auth_method": self.auth_method.value,
            "cookies": json.loads(self.cookies),
            "headers": json.loads(self.headers),
            "created_at": self.created_at,
            "last_used": self.last_used,
            "expires_at": self.expires_at,
            "login_url": self.login_url,
            "logout_url": self.logout_url,
            "csrf_token": self.csrf_token,
            "user_agent": self.user_agent,
            "proxy": self.proxy,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Session":
        """Create session from dictionary."""
        return cls(
            session_id=data["session_id"],
            target_host=data["target_host"],
            state=SessionState(data["state"]),
            auth_method=AuthMethod(data["auth_method"]),
            cookies=json.dumps(data["cookies"]),
            headers=json.dumps(data["headers"]),
            created_at=data["created_at"],
            last_used=data["last_used"],
            expires_at=data.get("expires_at"),
            login_url=data.get("login_url"),
            logout_url=data.get("logout_url"),
            csrf_token=data.get("csrf_token"),
            user_agent=data.get("user_agent", "DragonShard/1.0"),
            proxy=data.get("proxy"),
        )


class AuthCredentials(Base):
    """Authentication credentials."""

    __tablename__ = "auth_credentials"

    id = Column(Integer, primary_key=True)
    session_id = Column(String(255), ForeignKey("sessions.session_id"), nullable=False)
    username = Column(String(255), nullable=False)
    password = Column(String(255), nullable=False)
    token = Column(String(500), nullable=True)
    api_key = Column(String(500), nullable=True)
    session_id_ref = Column(String(255), nullable=True)

    # Relationships
    session = relationship("Session", back_populates="credentials")

    def to_dict(self) -> Dict[str, Any]:
        """Convert credentials to dictionary."""
        return {
            "id": self.id,
            "session_id": self.session_id,
            "username": self.username,
            "password": self.password,
            "token": self.token,
            "api_key": self.api_key,
            "session_id_ref": self.session_id_ref,
        }


class Host(Base):
    """Information about a host."""

    __tablename__ = "hosts"

    host_id = Column(String(255), primary_key=True)
    hostname = Column(String(255), nullable=False)
    ip_address = Column(String(45), nullable=False)  # IPv6 compatible
    status = Column(SQLEnum(HostStatus), nullable=False, default=HostStatus.DISCOVERED)
    discovered_at = Column(Float, nullable=False, default=time.time)
    last_seen = Column(Float, nullable=False, default=time.time)
    os_info = Column(String(500), nullable=True)
    mac_address = Column(String(17), nullable=True)
    hostnames = Column(Text, default="[]")  # JSON array
    notes = Column(Text, default="")

    # Relationships
    services = relationship("Service", back_populates="host")
    vulnerabilities = relationship("Vulnerability", secondary="host_vulnerabilities")

    def to_dict(self) -> Dict[str, Any]:
        """Convert host to dictionary."""
        return {
            "host_id": self.host_id,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "status": self.status.value,
            "discovered_at": self.discovered_at,
            "last_seen": self.last_seen,
            "os_info": self.os_info,
            "mac_address": self.mac_address,
            "hostnames": json.loads(self.hostnames),
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Host":
        """Create host from dictionary."""
        return cls(
            host_id=data["host_id"],
            hostname=data["hostname"],
            ip_address=data["ip_address"],
            status=HostStatus(data["status"]),
            discovered_at=data["discovered_at"],
            last_seen=data["last_seen"],
            os_info=data.get("os_info"),
            mac_address=data.get("mac_address"),
            hostnames=json.dumps(data.get("hostnames", [])),
            notes=data.get("notes", ""),
        )


class Service(Base):
    """Information about a service."""

    __tablename__ = "services"

    service_id = Column(String(255), primary_key=True)
    host_id = Column(String(255), ForeignKey("hosts.host_id"), nullable=False)
    port = Column(Integer, nullable=False)
    service_type = Column(SQLEnum(ServiceType), nullable=False)
    protocol = Column(String(10), nullable=False, default="tcp")
    banner = Column(Text, nullable=True)
    version = Column(String(255), nullable=True)
    status = Column(String(50), default="open")
    discovered_at = Column(Float, nullable=False, default=time.time)
    last_seen = Column(Float, nullable=False, default=time.time)
    credentials = Column(Text, default="{}")  # JSON object

    # Relationships
    host = relationship("Host", back_populates="services")
    vulnerabilities = relationship("Vulnerability", back_populates="service")

    def to_dict(self) -> Dict[str, Any]:
        """Convert service to dictionary."""
        return {
            "service_id": self.service_id,
            "host_id": self.host_id,
            "port": self.port,
            "service_type": self.service_type.value,
            "protocol": self.protocol,
            "banner": self.banner,
            "version": self.version,
            "status": self.status,
            "discovered_at": self.discovered_at,
            "last_seen": self.last_seen,
            "credentials": json.loads(self.credentials),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Service":
        """Create service from dictionary."""
        return cls(
            service_id=data["service_id"],
            host_id=data["host_id"],
            port=data["port"],
            service_type=ServiceType(data["service_type"]),
            protocol=data.get("protocol", "tcp"),
            banner=data.get("banner"),
            version=data.get("version"),
            status=data.get("status", "open"),
            discovered_at=data["discovered_at"],
            last_seen=data["last_seen"],
            credentials=json.dumps(data.get("credentials", {})),
        )


class Vulnerability(Base):
    """Information about a vulnerability."""

    __tablename__ = "vulnerabilities"

    vuln_id = Column(String(255), primary_key=True)
    service_id = Column(String(255), ForeignKey("services.service_id"), nullable=False)
    vuln_type = Column(String(100), nullable=False)
    severity = Column(SQLEnum(VulnerabilityLevel), nullable=False)
    description = Column(Text, nullable=False)
    discovered_at = Column(Float, nullable=False, default=time.time)
    cve_id = Column(String(50), nullable=True)
    cvss_score = Column(Float, nullable=True)
    exploit_available = Column(Boolean, default=False)
    exploited = Column(Boolean, default=False)
    evidence = Column(Text, default="")
    remediation = Column(Text, default="")

    # Relationships
    service = relationship("Service", back_populates="vulnerabilities")

    def to_dict(self) -> Dict[str, Any]:
        """Convert vulnerability to dictionary."""
        return {
            "vuln_id": self.vuln_id,
            "service_id": self.service_id,
            "vuln_type": self.vuln_type,
            "severity": self.severity.value,
            "description": self.description,
            "discovered_at": self.discovered_at,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "exploit_available": self.exploit_available,
            "exploited": self.exploited,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Vulnerability":
        """Create vulnerability from dictionary."""
        return cls(
            vuln_id=data["vuln_id"],
            service_id=data["service_id"],
            vuln_type=data["vuln_type"],
            severity=VulnerabilityLevel(data["severity"]),
            description=data["description"],
            discovered_at=data["discovered_at"],
            cve_id=data.get("cve_id"),
            cvss_score=data.get("cvss_score"),
            exploit_available=data.get("exploit_available", False),
            exploited=data.get("exploited", False),
            evidence=data.get("evidence", ""),
            remediation=data.get("remediation", ""),
        )


class Connection(Base):
    """Information about a connection between hosts."""

    __tablename__ = "connections"

    connection_id = Column(String(255), primary_key=True)
    source_host = Column(String(255), ForeignKey("hosts.host_id"), nullable=False)
    target_host = Column(String(255), ForeignKey("hosts.host_id"), nullable=False)
    connection_type = Column(String(100), nullable=False)
    protocol = Column(String(10), nullable=False)
    port = Column(Integer, nullable=False)
    established_at = Column(Float, nullable=False, default=time.time)
    last_seen = Column(Float, nullable=False, default=time.time)
    data_transferred = Column(Integer, default=0)
    status = Column(String(50), default="active")

    def to_dict(self) -> Dict[str, Any]:
        """Convert connection to dictionary."""
        return {
            "connection_id": self.connection_id,
            "source_host": self.source_host,
            "target_host": self.target_host,
            "connection_type": self.connection_type,
            "protocol": self.protocol,
            "port": self.port,
            "established_at": self.established_at,
            "last_seen": self.last_seen,
            "data_transferred": self.data_transferred,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Connection":
        """Create connection from dictionary."""
        return cls(
            connection_id=data["connection_id"],
            source_host=data["source_host"],
            target_host=data["target_host"],
            connection_type=data["connection_type"],
            protocol=data["protocol"],
            port=data["port"],
            established_at=data["established_at"],
            last_seen=data["last_seen"],
            data_transferred=data.get("data_transferred", 0),
            status=data.get("status", "active"),
        )


# Association table for many-to-many relationship between hosts and vulnerabilities
class HostVulnerability(Base):
    """Association table for host-vulnerability relationship."""

    __tablename__ = "host_vulnerabilities"

    host_id = Column(String(255), ForeignKey("hosts.host_id"), primary_key=True)
    vuln_id = Column(String(255), ForeignKey("vulnerabilities.vuln_id"), primary_key=True)


# Event listeners for automatic timestamp updates
@event.listens_for(Session, "before_update")
def update_session_timestamp(mapper, connection, target):
    """Update last_used timestamp when session is modified."""
    target.last_used = time.time()


@event.listens_for(Host, "before_update")
def update_host_timestamp(mapper, connection, target):
    """Update last_seen timestamp when host is modified."""
    target.last_seen = time.time()


@event.listens_for(Service, "before_update")
def update_service_timestamp(mapper, connection, target):
    """Update last_seen timestamp when service is modified."""
    target.last_seen = time.time()


@event.listens_for(Connection, "before_update")
def update_connection_timestamp(mapper, connection, target):
    """Update last_seen timestamp when connection is modified."""
    target.last_seen = time.time() 