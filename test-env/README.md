# Genetic Fuzzer Test Environment

This directory contains vulnerable applications for testing the DragonShard genetic fuzzer.

## 🐳 Vulnerable Containers

### Available Applications

1. **DVWA (Damn Vulnerable Web Application)**
   - Port: 8080
   - URL: http://localhost:8080
   - Vulnerabilities: SQL Injection, XSS, File Upload, Command Injection

2. **OWASP Juice Shop**
   - Port: 3000
   - URL: http://localhost:3000
   - Vulnerabilities: Modern web app vulnerabilities, API security issues

3. **WebGoat**
   - Port: 8081
   - URL: http://localhost:8081
   - Vulnerabilities: OWASP Top 10 vulnerabilities, educational lessons

4. **Vulnerable PHP App**
   - Port: 8082
   - URL: http://localhost:8082
   - Vulnerabilities: SQL Injection, XSS, LFI, Command Injection, Path Traversal

5. **Vulnerable Node.js App**
   - Port: 8083
   - URL: http://localhost:8083
   - Vulnerabilities: SQL Injection, NoSQL Injection, Command Injection, SSRF, XXE

6. **Vulnerable Python App**
   - Port: 8084
   - URL: http://localhost:8084
   - Vulnerabilities: SQL Injection, Command Injection, Path Traversal, SSRF, XXE, Template Injection

## 🚀 Quick Start

### 1. Start the Environment
```bash
# Start all vulnerable containers
make test-env-start

# Or manually:
docker-compose -f ../docker-compose.test.yml up -d
```

### 2. Run Genetic Fuzzer Tests
```bash
# Run comprehensive test
make test-fuzzer-manual

# Or run integration tests
make test-fuzzer-integration
```

### 3. Stop the Environment
```bash
# Stop containers
make test-env-stop

# Clean up completely
make test-env-clean
```

## 🧬 Testing Different Vulnerability Types

### SQL Injection Testing

```python
# Test against PHP app
target_url = "http://localhost:8082"
test_endpoint = f"{target_url}/search"

# Base payloads
payloads = [
    "1' OR '1'='1",
    "1' UNION SELECT 1,2,3--",
    "admin'--"
]

# The genetic mutator will evolve these payloads
# and test them against the vulnerable endpoint
```

### XSS Testing

```python
# Test against PHP app
target_url = "http://localhost:8082"
test_endpoint = f"{target_url}/?input=PAYLOAD"

# Base payloads
payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)"
]
```

### Command Injection Testing

```python
# Test against Node.js app
target_url = "http://localhost:8083"
test_endpoint = f"{target_url}/command"

# Base payloads
payloads = [
    "127.0.0.1; ls",
    "127.0.0.1 && whoami",
    "127.0.0.1 | cat /etc/passwd"
]
```

## 📊 Response Analysis Features

The test environment supports the enhanced genetic fuzzer features:

### 1. Response Differential Analysis
- Compares responses against baselines
- Detects subtle differences indicating vulnerabilities
- Calculates reward scores based on response changes

### 2. Intelligent Search Strategies
- Breadth-first exploration
- Dead-end path detection
- Adaptive mutation selection

### 3. Vulnerability Pattern Detection
- SQL injection error messages
- XSS reflection in responses
- Command injection error messages
- Path traversal file access errors

## 🔧 Container Details

### Database
- MySQL 5.7
- Database: `testdb`
- User: `testuser`
- Password: `testpass`

### Vulnerable Applications

#### PHP App (`vuln-php/`)
- **SQL Injection**: `/search` endpoint
- **XSS**: `/?input=PAYLOAD`
- **LFI**: `/file` endpoint
- **Command Injection**: `/command` endpoint
- **Path Traversal**: `/path` endpoint

#### Node.js App (`vuln-node/`)
- **SQL Injection**: `/search` endpoint
- **Command Injection**: `/command` endpoint
- **SSRF**: `/fetch` endpoint
- **XXE**: `/xml` endpoint
- **XSS**: `/xss` endpoint

#### Python App (`vuln-python/`)
- **SQL Injection**: `/search` endpoint
- **Command Injection**: `/command` endpoint
- **Path Traversal**: `/file` endpoint
- **SSRF**: `/fetch` endpoint
- **XXE**: `/xml` endpoint
- **Template Injection**: `/template` endpoint

## 🧪 Test Scripts

### Run Comprehensive Test
```bash
python3 ../test_genetic_fuzzer.py
```

This script will:
1. Test target availability
2. Set baseline responses
3. Run genetic fuzzing for SQL injection, XSS, and command injection
4. Report results with payloads and scores

### Manual Testing
```bash
# Test SQL injection
curl -X POST http://localhost:8082/search -d "search=1' OR '1'='1"

# Test XSS
curl "http://localhost:8082/?input=<script>alert('XSS')</script>"

# Test command injection
curl -X POST http://localhost:8083/command -d "command=127.0.0.1; ls"
```

## 🛑 Stopping the Environment

```bash
# Stop all containers
docker-compose -f ../docker-compose.test.yml down

# Remove volumes (optional)
docker-compose -f ../docker-compose.test.yml down -v
```

## 🔍 Monitoring

### View Container Logs
```bash
# View all logs
docker-compose -f ../docker-compose.test.yml logs

# View specific container logs
docker-compose -f ../docker-compose.test.yml logs vuln-php
```

### Health Checks
```bash
# Check container health
docker-compose -f ../docker-compose.test.yml ps

# Test endpoints manually
curl http://localhost:8082
curl http://localhost:8083
curl http://localhost:8084
```

## ⚠️ Security Notice

⚠️ **WARNING**: These containers contain intentionally vulnerable applications for testing purposes only. 

- Do NOT deploy these containers in production environments
- Do NOT expose these containers to the internet
- Use only in isolated testing environments
- These applications are designed to be exploited for educational purposes

## 🎯 Expected Results

When running the genetic fuzzer against these containers, you should see:

1. **High-scoring payloads** that trigger vulnerabilities
2. **Response differentials** indicating successful exploitation
3. **Evolution of payloads** becoming more effective over generations
4. **Detection of various vulnerability types** through response analysis

The genetic fuzzer should successfully discover:
- SQL injection payloads that cause database errors
- XSS payloads that reflect in responses
- Command injection payloads that execute commands
- Path traversal payloads that access sensitive files 