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

## 🚧 Phase 2 - API Inference
- Implement crawler.py with HTTP service crawling
- Implement schema_infer.py to extract endpoints and infer data schemas
- Implement auth_detector.py to identify common authentication patterns
- Add tests for API inference components

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

## 🚧 CI/CD Infrastructure
- Set up Travis CI for automated testing
- Configure Codecov.io for code coverage reporting
- Add GitHub Actions as alternative CI/CD
- Set up automated Docker image building
- Add security scanning with Bandit/Safety
- Configure automated dependency updates

## 🚧 Additional Infrastructure Needs
- Add proper error handling throughout
- Add logging system
- Add configuration management
- Add CLI interface
- Add documentation
- Add more comprehensive test coverage