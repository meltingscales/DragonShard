# ✅ TODO

MVP Milestones

## ✅ Phase 1 - Recon (COMPLETED)
- ✅ Implement scanner.py with Nmap support
- ✅ Output structured JSON of open ports and services
- ✅ Added UDP scanning capabilities
- ✅ Added service detection and version information
- ✅ Added comprehensive unit tests with mocking
- ✅ Added multiple scan types (quick, comprehensive, udp)
- ✅ Added common service scanning functionality
- ✅ Added utility functions for extracting open ports
- ✅ Added Docker-based integration tests

**Features implemented:**
- TCP and UDP port scanning
- Service detection with version information
- Multiple scan types (quick, comprehensive, udp)
- Common service scanning on well-known ports
- Comprehensive test coverage with mocking
- Utility functions for data processing
- Docker integration tests with vulnerable containers

## ✅ Phase 2 - API Inference (COMPLETED)
- ✅ Implement crawler.py with HTTP service crawling
- ✅ Implement js_crawler.py with JavaScript support (Playwright)
- ✅ Implement unified_crawler.py with smart crawler selection
- ✅ Added comprehensive unit tests for all crawler components
- ✅ Added dual crawler system (fast httpx + slow Playwright)
- ✅ Added context manager support for browser cleanup
- ✅ Added link extraction and URL resolution
- ✅ Added JavaScript-rendered content support
- ✅ Added crawler comparison and analysis tools

**Features implemented:**
- Fast crawler using httpx (no JavaScript support)
- JavaScript-enabled crawler using Playwright
- Unified crawler with automatic selection
- Smart crawling with force_js option
- Comprehensive test coverage with mocking
- Context manager for proper resource cleanup
- Link extraction from both static and dynamic content
- URL resolution and filtering (http/https only)
- Crawler comparison and analytics

## 🚧 Phase 3 - Fuzzing
- Implement fuzzer.py with basic payload testing (XSS, SQLi)
- Implement mutators.py for payload mutation strategies
- Build comprehensive payload library in payloads.json
- Add anomaly detection and crash logging
- Add tests for fuzzing components

## 🚧 Phase 4 - Planner
- Implement chain_planner.py with LLM integration for attack planning
- Create effective prompts in prompts/ directory for different attack scenarios
- Add tests for planner components

## 🚧 Phase 5 - Executor
- Implement executor.py for attack execution engine
- Implement session_manager.py for managing attack sessions
- Implement state_graph.py for building graph of hosts/services
- Add tests for executor components

## ✅ CI/CD Infrastructure (COMPLETED)
- ✅ Set up GitHub Actions for automated testing
- ✅ Configure Codecov.io for code coverage reporting
- ✅ Set up automated Docker image building
- ✅ Add security scanning with Bandit/Safety
- ✅ Add Playwright browser installation in CI
- ✅ Add test analytics with JUnit XML reports
- ✅ Remove Travis CI (migrated to GitHub Actions)
- ✅ Streamline workflow by removing redundant lint job
- ✅ Add comprehensive test coverage reporting

**Features implemented:**
- Multi-Python testing (3.10, 3.11, 3.12)
- Docker support for integration tests
- Coverage reporting with Codecov
- Security scanning with Bandit and Safety
- Playwright browser installation for JS crawler tests
- Test analytics and performance tracking
- Automated Docker image building
- Comprehensive linting and formatting checks

## ✅ Additional Infrastructure (COMPLETED)
- ✅ Add proper error handling throughout
- ✅ Add logging system
- ✅ Add configuration management
- ✅ Add comprehensive test coverage
- ✅ Add Makefile for development automation
- ✅ Add VS Code task integration
- ✅ Add documentation (README.md, API docs)
- ✅ Add ruff linting and formatting
- ✅ Add security scanning integration

**Features implemented:**
- Comprehensive error handling and logging
- Configuration management with pyproject.toml
- Extensive test coverage with mocking
- Development automation with Makefile
- VS Code task integration for common workflows
- Complete documentation with examples
- Code quality tools (ruff, bandit, safety)
- Security scanning and vulnerability detection

## 🚧 Next Steps - Phase 3: Fuzzing
The next major milestone is implementing the fuzzing module. This will include:

### Core Fuzzing Components
- **fuzzer.py**: Main fuzzing engine with payload testing
- **mutators.py**: Payload mutation strategies
- **payloads.json**: Comprehensive payload library
- **anomaly_detector.py**: Detection of unusual responses

### Planned Features
- XSS payload testing and detection
- SQL injection testing and detection
- Command injection testing
- Path traversal testing
- Custom payload mutation strategies
- Response analysis and anomaly detection
- Crash logging and reporting
- Comprehensive test coverage

### Implementation Priority
1. **Basic fuzzer.py** with simple payload testing
2. **payloads.json** with common attack vectors
3. **Response analysis** for detecting vulnerabilities
4. **Mutation strategies** for payload variation
5. **Integration with crawler** for automatic endpoint discovery
6. **Comprehensive testing** and documentation


# Extra ideas

- dynamic fuzz payload generator (AI? genetic algorithms? both?)