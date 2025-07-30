# DragonShard Database Implementation

This module provides a comprehensive database backend for DragonShard, replacing the in-memory storage with persistent database storage.

## Features

- **PostgreSQL Support**: Primary database with full SQLAlchemy ORM
- **SQLite Fallback**: Local development with SQLite
- **MySQL Support**: Alternative database option
- **Session Management**: Persistent session storage with authentication
- **State Graph**: Network topology and vulnerability tracking
- **Migration System**: Alembic-based database migrations
- **Docker Integration**: Complete Docker Compose setup

## Architecture

### Database Models

The database is organized around these core entities:

- **Session**: Authentication sessions and state
- **AuthCredentials**: Stored credentials for sessions
- **Host**: Network hosts and their status
- **Service**: Services running on hosts
- **Vulnerability**: Security vulnerabilities found
- **Connection**: Network connections between hosts

### Repository Pattern

All database operations use a generic repository pattern:

```python
from dragonshard.data.database import get_repository
from dragonshard.data.models import Host

# Get repository for Host model
host_repo = get_repository(Host)

# Create a host
host = host_repo.create(
    host_id="host_123",
    hostname="example.com",
    ip_address="192.168.1.1",
    status=HostStatus.DISCOVERED
)

# Query hosts
hosts = host_repo.get_all()
host = host_repo.get_by_id("host_123")
filtered_hosts = host_repo.filter_by(status=HostStatus.SCANNED)
```

## Setup

### 1. Database Initialization

```bash
# Initialize database and create tables
make db-init

# Check database status
make db-status

# Run migrations
make db-migrate
```

### 2. Docker Setup (Recommended)

```bash
# Start DragonShard with PostgreSQL
make docker-up

# Check logs
make docker-logs

# Stop containers
make docker-down
```

### 3. Manual Setup

```bash
# Install dependencies
pip install -r requirements.lock.txt

# Set environment variables
export DATABASE_URL="postgresql://dragonshard:dragonshard@localhost:5432/dragonshard"

# Initialize database
python scripts/manage_db.py init
```

## Usage

### Session Manager

```python
from dragonshard.data.session_manager_db import DatabaseSessionManager
from dragonshard.data.models import AuthMethod

# Initialize session manager
session_manager = DatabaseSessionManager()

# Create a session
session_id = session_manager.create_session("http://example.com", AuthMethod.FORM)

# Authenticate session
credentials = {"username": "admin", "password": "password123"}
success = session_manager.authenticate_session(session_id, credentials)

# Get session headers
headers = session_manager.get_session_headers(session_id)
```

### State Graph

```python
from dragonshard.data.state_graph_db import DatabaseStateGraph
from dragonshard.data.models import HostStatus, ServiceType, VulnerabilityLevel

# Initialize state graph
state_graph = DatabaseStateGraph()

# Add hosts
host_id = state_graph.add_host("web.example.com", "192.168.1.10", HostStatus.DISCOVERED)

# Add services
service_id = state_graph.add_service(host_id, 80, ServiceType.HTTP)

# Add vulnerabilities
vuln_id = state_graph.add_vulnerability(
    service_id, "sql_injection", VulnerabilityLevel.HIGH, "SQL injection found"
)

# Get summaries
vuln_summary = state_graph.get_vulnerability_summary()
topology = state_graph.get_network_topology()
```

## Database Management

### Commands

```bash
# Initialize database
make db-init

# Check status
make db-status

# Run migrations
make db-migrate

# Create new migration
make db-create-migration message="Add new table"

# Drop all tables
make db-drop

# Check connection
make db-check

# Run tests
make db-test
```

### Migration System

The project uses Alembic for database migrations:

```bash
# Create a new migration
alembic revision --autogenerate -m "Add new field"

# Run migrations
alembic upgrade head

# Rollback migration
alembic downgrade -1
```

## Configuration

### Environment Variables

- `DATABASE_URL`: Database connection string
- `POSTGRES_HOST`: PostgreSQL host (default: localhost)
- `POSTGRES_PORT`: PostgreSQL port (default: 5432)
- `POSTGRES_DB`: Database name (default: dragonshard)
- `POSTGRES_USER`: Database user (default: dragonshard)
- `POSTGRES_PASSWORD`: Database password (default: dragonshard)

### Docker Environment

The Docker Compose setup includes:

- **PostgreSQL**: Primary database
- **Redis**: Caching layer (optional)
- **Adminer**: Database management interface
- **Nginx**: Reverse proxy (optional)

## Testing

### Run Database Tests

```bash
# Run all database tests
make db-test

# Or run directly
python scripts/test_database.py
```

### Test Coverage

The database tests cover:

- Database connection and initialization
- Session manager operations
- State graph operations
- Repository pattern operations
- CRUD operations on all models

## Performance

### Optimizations

- **Connection Pooling**: SQLAlchemy connection pooling
- **Indexes**: Automatic index creation on primary keys
- **Lazy Loading**: Relationships loaded on demand
- **Batch Operations**: Bulk insert/update support

### Monitoring

```bash
# Check database status
make db-status

# View Docker logs
make docker-logs

# Monitor PostgreSQL
docker exec -it dragonshard-postgres psql -U dragonshard -d dragonshard
```

## Troubleshooting

### Common Issues

1. **Connection Refused**: Check if PostgreSQL is running
2. **Authentication Failed**: Verify database credentials
3. **Migration Errors**: Run `make db-drop` and `make db-init`
4. **Docker Issues**: Check container logs with `make docker-logs`

### Debug Mode

```bash
# Enable debug logging
export LOG_LEVEL=DEBUG

# Run with verbose output
python scripts/manage_db.py status
```

## Migration from In-Memory

To migrate existing in-memory data:

1. Export data from old system
2. Import using the new database-backed classes
3. Update code to use `DatabaseSessionManager` and `DatabaseStateGraph`

## Security

- **Encrypted Passwords**: Passwords are hashed before storage
- **Session Expiration**: Automatic session cleanup
- **SQL Injection Protection**: Parameterized queries
- **Connection Security**: TLS/SSL support for PostgreSQL

## Contributing

When adding new database features:

1. Create models in `dragonshard/data/models.py`
2. Add repository methods if needed
3. Create migration: `make db-create-migration message="Add feature"`
4. Update tests in `scripts/test_database.py`
5. Update documentation 