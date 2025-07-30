"""
Pydantic models for DragonShard Visualization API
"""

from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional, Union
from datetime import datetime
from enum import Enum

# Enums
class AttackStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class VulnerabilityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ServiceType(str, Enum):
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    FTP = "ftp"
    SMTP = "smtp"
    DNS = "dns"
    RDP = "rdp"
    SMB = "smb"
    MYSQL = "mysql"
    POSTGRES = "postgres"
    REDIS = "redis"
    MONGODB = "mongodb"

class FuzzingStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"

# Base Models
class BaseResponse(BaseModel):
    success: bool = True
    message: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)

# Attack Models
class AttackStep(BaseModel):
    id: str
    name: str
    description: str
    status: AttackStatus
    target: str
    payload: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration: Optional[float] = None

class AttackChain(BaseModel):
    id: str
    name: str
    description: str
    status: AttackStatus
    steps: List[AttackStep]
    total_steps: int
    completed_steps: int
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration: Optional[float] = None
    success_rate: float = 0.0

class AttackSummary(BaseModel):
    total_attacks: int
    running_attacks: int
    completed_attacks: int
    failed_attacks: int
    success_rate: float
    average_duration: float

# Vulnerability Models
class Vulnerability(BaseModel):
    id: str
    name: str
    description: str
    level: VulnerabilityLevel
    cve_id: Optional[str] = None
    target: str
    service: Optional[str] = None
    port: Optional[int] = None
    discovered_at: datetime
    details: Optional[Dict[str, Any]] = None

class VulnerabilitySummary(BaseModel):
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    by_service: Dict[str, int]
    by_level: Dict[str, int]

# Network Models
class Host(BaseModel):
    id: str
    ip_address: str
    hostname: Optional[str] = None
    os_info: Optional[str] = None
    discovered_at: datetime
    last_seen: datetime
    services: List["Service"]
    vulnerabilities: List[Vulnerability]

class Service(BaseModel):
    id: str
    name: str
    type: ServiceType
    port: int
    version: Optional[str] = None
    banner: Optional[str] = None
    discovered_at: datetime
    vulnerabilities: List[Vulnerability]

class NetworkTopology(BaseModel):
    hosts: List[Host]
    total_hosts: int
    total_services: int
    total_vulnerabilities: int
    network_range: Optional[str] = None

# Fuzzing Models
class FuzzingSession(BaseModel):
    id: str
    name: str
    status: FuzzingStatus
    target: str
    payload_type: str
    generation: int
    population_size: int
    best_fitness: float
    average_fitness: float
    mutations_count: int
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration: Optional[float] = None

class FuzzingProgress(BaseModel):
    session_id: str
    generation: int
    population_size: int
    best_fitness: float
    average_fitness: float
    diversity: float
    mutations_count: int
    successful_payloads: int
    timestamp: datetime

class GeneticAlgorithmStats(BaseModel):
    total_sessions: int
    active_sessions: int
    total_generations: int
    total_mutations: int
    average_fitness: float
    best_fitness: float

# Session Models
class Session(BaseModel):
    id: str
    target: str
    authenticated: bool
    auth_method: Optional[str] = None
    cookies: Dict[str, str] = {}
    headers: Dict[str, str] = {}
    created_at: datetime
    last_used: datetime
    requests_count: int

class SessionSummary(BaseModel):
    total_sessions: int
    authenticated_sessions: int
    active_sessions: int
    by_target: Dict[str, int]

# Export Models
class ExportRequest(BaseModel):
    data_type: str  # "attacks", "vulnerabilities", "network", "fuzzing", "sessions"
    format: str = "json"  # "json", "csv", "html"
    filters: Optional[Dict[str, Any]] = None
    include_details: bool = True

class ExportResponse(BaseModel):
    export_id: str
    data_type: str
    format: str
    file_size: int
    download_url: str
    expires_at: datetime

# WebSocket Models
class WebSocketMessage(BaseModel):
    type: str
    data: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.now)

class SubscriptionRequest(BaseModel):
    type: str = "subscribe"
    stream: str  # "attacks", "vulnerabilities", "network", "fuzzing", "sessions"

# Update references
Host.model_rebuild()
Service.model_rebuild() 