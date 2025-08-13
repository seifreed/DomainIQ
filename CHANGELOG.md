# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-08-13

### Added
- Complete rewrite as a modern Python 3.10+ library
- Modular architecture with separate client, models, exceptions, and utility modules
- Type hints throughout the codebase for better IDE support
- Asynchronous client (`AsyncDomainIQClient`) with aiohttp support
- Comprehensive error handling with custom exception classes:
  - `DomainIQError` (base exception)
  - `DomainIQAPIError` (API-related errors)
  - `DomainIQAuthenticationError` (authentication failures)
  - `DomainIQRateLimitError` (rate limiting)
  - `DomainIQTimeoutError` (request timeouts)
- Configuration management with multiple API key sources:
  - Parameter-based configuration
  - Environment variables (`DOMAINIQ_API_KEY`)
  - Config file (`~/.domainiq`)
  - Interactive prompts
- Data models using dataclasses for structured response handling:
  - `WhoisResult`
  - `DNSResult`
  - `DomainCategory`
  - `DomainSnapshot`
  - `DomainReport`
  - `MonitorReport`
- Enhanced CLI with improved argument parsing and help text
- Concurrent operation support in async client
- Request retry logic with exponential backoff
- Comprehensive logging throughout the library
- Context manager support for both sync and async clients
- Input validation for domains, IPs, and email addresses
- CSV to JSON conversion utilities
- PyPI packaging with `pyproject.toml`
- Development tools configuration (pytest, black, isort, mypy, flake8)

### Changed
- **BREAKING**: Minimum Python version is now 3.10
- **BREAKING**: Client initialization now uses `Config` object
- **BREAKING**: Method names follow Python conventions (snake_case)
- **BREAKING**: Return types are now structured data models instead of raw dictionaries
- CLI arguments use hyphens instead of underscores for consistency
- Improved error messages and debugging information
- Better parameter validation and sanitization
- Modern packaging using `pyproject.toml` instead of `setup.py`

### Improved
- Performance through connection pooling and session reuse
- Security through proper parameter sanitization in logs
- Reliability through retry mechanisms and better error handling
- Developer experience through type hints and documentation
- Testing infrastructure with pytest and coverage reporting
- Code quality through linting and formatting tools

### Removed
- **BREAKING**: Removed support for Python < 3.10
- Monolithic script structure
- Hardcoded configuration options
- Basic print-based error handling

## [1.0.0] - 2024-XX-XX

### Added
- Initial implementation as single script (`domainIQ.py`)
- Support for all major DomainIQ API endpoints:
  - WHOIS lookups
  - DNS queries  
  - Domain categorization
  - Domain snapshots and history
  - Various reports (domain, name, organization, email, IP)
  - Domain and reverse searches
  - Bulk operations
  - Monitoring and alerting
- Command-line interface with extensive argument support
- Basic API key management via config file
- CSV response parsing for bulk operations
- MIT License