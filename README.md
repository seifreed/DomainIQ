# DomainIQ Python Library

A modern, feature-rich Python client for the DomainIQ API that provides comprehensive domain intelligence and security research capabilities.

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE.md)
[![PyPI Version](https://img.shields.io/badge/pypi-2.0.0-orange.svg)](https://pypi.org/project/domainiq/)

## Features

- 🚀 **Modern Python 3.10+ support** with full type hints
- ⚡ **Async/await support** for high-performance concurrent operations
- 🛡️ **Comprehensive error handling** with custom exception classes
- 📊 **Structured data models** using dataclasses for clean API responses
- 🔧 **Flexible configuration** supporting multiple API key sources
- 🧪 **Full test suite** with real API integration tests
- 📦 **PyPI ready** with proper packaging and dependencies
- 🔍 **Security research tools** with built-in analysis workflows
- 📝 **Extensive documentation** and examples

## Installation

### From PyPI (Recommended)

```bash
pip install domainiq
```

### With async support

```bash
pip install domainiq[async]
```

### Development installation

```bash
git clone https://github.com/seifreed/DomainIQ.git
cd DomainIQ
pip install -e .[dev]
```

## Requirements

- **Python 3.10+** (supports 3.10, 3.11, 3.12, 3.13)
- **requests** >= 2.28.0 (automatically installed)
- **aiohttp** >= 3.8.0 (optional, for async client)

## Quick Start

### API Key Configuration

The library supports multiple ways to provide your DomainIQ API key:

1. **Environment variable** (recommended):
   ```bash
   export DOMAINIQ_API_KEY="your_api_key_here"
   ```

2. **Configuration file**:
   ```bash
   echo "your_api_key_here" > ~/.domainiq
   ```

3. **Direct parameter**:
   ```python
   from domainiq import DomainIQClient
   client = DomainIQClient(api_key="your_api_key_here")
   ```

4. **Interactive prompt** (when available):
   The library will prompt for your API key if no other method is found.

### Basic Usage (Synchronous)

```python
from domainiq import DomainIQClient
from domainiq.models import DNSRecordType

# Create client (API key loaded automatically)
client = DomainIQClient()

# WHOIS lookup
whois_result = client.whois_lookup(domain="example.com")
if whois_result:
    print(f"Registrar: {whois_result.registrar}")
    print(f"Created: {whois_result.creation_date}")
    print(f"Expires: {whois_result.expiration_date}")

# DNS lookup
dns_result = client.dns_lookup("example.com", record_types=[DNSRecordType.A, DNSRecordType.MX])
if dns_result:
    for record in dns_result.records:
        print(f"{record.type}: {record.value}")

# Domain categorization
categories = client.domain_categorize(["example.com", "google.com"])
for category in categories:
    print(f"{category.domain}: {', '.join(category.categories)}")

# Bulk operations
bulk_results = client.bulk_dns(["example.com", "google.com"])
for result in bulk_results:
    print(f"{result['domain']}: {result.get('ip', 'N/A')}")

client.close()  # Clean up
```

### Async Usage (High Performance)

```python
import asyncio
from domainiq.async_client import AsyncDomainIQClient

async def main():
    async with AsyncDomainIQClient() as client:
        # Concurrent WHOIS lookups (much faster!)
        domains = ["example.com", "google.com", "github.com"]
        results = await client.concurrent_whois_lookup(
            targets=domains,
            max_concurrent=5
        )
        
        for domain, result in zip(domains, results):
            if result:
                print(f"{domain}: {result.registrar}")
        
        # Other async operations
        dns_result = await client.dns_lookup("example.com")
        categories = await client.domain_categorize(["example.com"])
        report = await client.domain_report("example.com")

asyncio.run(main())
```

### Context Manager Usage

```python
# Automatically handles connection cleanup
with DomainIQClient() as client:
    whois_data = client.whois_lookup(domain="example.com")
    dns_data = client.dns_lookup("example.com")
# Client is automatically closed
```

### Security Research Example

```python
from domainiq import DomainIQClient
from datetime import datetime, timedelta

client = DomainIQClient()

# Analyze suspicious domains
suspicious_domains = ["suspicious-site.com", "fake-bank.net"]
for domain in suspicious_domains:
    whois = client.whois_lookup(domain=domain)
    if whois and whois.creation_date:
        days_old = (datetime.now() - whois.creation_date.replace(tzinfo=None)).days
        if days_old < 30:
            print(f"⚠️  {domain} is newly registered ({days_old} days old)")
            print(f"   Registrar: {whois.registrar}")
            print(f"   Registrant: {whois.registrant_name}")
    
    # Check categories
    categories = client.domain_categorize([domain])
    if categories and categories[0].categories:
        for cat in categories[0].categories:
            if any(risk in cat.lower() for risk in ['malware', 'phishing', 'suspicious']):
                print(f"🚨 {domain} categorized as: {cat}")
```

## Command Line Interface

The library includes a comprehensive CLI tool:

```bash
# Basic usage
domainiq --whois-lookup example.com
domainiq --dns-lookup example.com --types A,MX
domainiq --domain-report example.com

# Bulk operations
domainiq --bulk-dns example.com google.com github.com
domainiq --bulk-whois example.com google.com

# Search operations
domainiq --domain-search keyword1 keyword2 --match any --limit 10
domainiq --reverse-search-type email --reverse-search admin@example.com

# Monitoring
domainiq --monitor-list
domainiq --create-monitor-report keyword "My Monitor" --email-alert

# Security research
domainiq --email-report suspicious@domain.com
domainiq --ip-report 192.168.1.1
```

## API Coverage

The library supports all major DomainIQ API endpoints:

### 🔍 **Lookup Services**
- ✅ WHOIS lookups (domains and IPs)
- ✅ DNS record queries (all record types)
- ✅ Domain categorization
- ✅ Domain snapshots and history
- ✅ Reverse DNS lookups

### 📊 **Report Services**
- ✅ Comprehensive domain reports
- ✅ Registrant name reports
- ✅ Organization reports
- ✅ Email address reports
- ✅ IP address reports

### 🔎 **Search Services**
- ✅ Domain search with keywords
- ✅ Reverse search (email, name, org)
- ✅ Reverse IP lookups
- ✅ Reverse MX lookups

### 📦 **Bulk Operations**
- ✅ Bulk DNS lookups
- ✅ Bulk WHOIS lookups
- ✅ Bulk domain IP lookups

### 🚨 **Monitoring Services**
- ✅ Monitor management
- ✅ Monitor reports and summaries
- ✅ Typosquatting monitoring
- ✅ Change tracking

## Data Models

The library provides structured data models for clean API responses:

```python
# WhoisResult model
whois = client.whois_lookup("example.com")
print(whois.domain)              # str
print(whois.registrar)           # str
print(whois.creation_date)       # datetime
print(whois.expiration_date)     # datetime
print(whois.registrant_name)     # str
print(whois.nameservers)         # List[str]

# DNSResult model  
dns = client.dns_lookup("example.com")
print(dns.domain)                # str
for record in dns.records:
    print(record.type)           # str (A, MX, CNAME, etc.)
    print(record.value)          # str
    print(record.ttl)            # int

# DomainReport model
report = client.domain_report("example.com")
print(report.domain)             # str
print(report.risk_score)         # float
print(report.categories)         # List[str]
print(report.related_domains)    # List[str]
```

## Error Handling

Comprehensive exception hierarchy for robust error handling:

```python
from domainiq import (
    DomainIQError,              # Base exception
    DomainIQAPIError,           # API-related errors
    DomainIQAuthenticationError, # Invalid API key
    DomainIQRateLimitError,     # Rate limiting
    DomainIQTimeoutError,       # Request timeouts
    DomainIQConfigurationError  # Configuration issues
)

try:
    result = client.whois_lookup("example.com")
except DomainIQAuthenticationError:
    print("Invalid API key")
except DomainIQRateLimitError as e:
    print(f"Rate limited. Retry after: {e.retry_after} seconds")
except DomainIQTimeoutError:
    print("Request timed out")
except DomainIQAPIError as e:
    print(f"API error: {e}")
```

## Configuration Options

Advanced configuration for specific needs:

```python
from domainiq import DomainIQClient
from domainiq.config import Config

# Custom configuration
config = Config(
    api_key="your_key",
    base_url="https://api.domainiq.com/custom",
    timeout=60,          # Request timeout in seconds
    max_retries=5,       # Maximum retry attempts
    retry_delay=2        # Initial delay between retries
)

client = DomainIQClient(config=config)
```

## Testing

The library includes comprehensive tests with real API integration:

```bash
# Install test dependencies
pip install domainiq[dev]

# Run all tests
pytest

# Run only unit tests (no API key required)
pytest -m "not integration"

# Run integration tests (requires API key)
pytest -m integration

# Run with coverage
pytest --cov=domainiq --cov-report=html
```

## Examples

Comprehensive examples are provided in the `examples/` directory:

- **`basic_usage.py`** - Fundamental operations and API usage
- **`async_usage.py`** - High-performance async operations
- **`security_research.py`** - Security analysis workflows

## Development

### Setting up development environment

```bash
git clone https://github.com/seifreed/DomainIQ.git
cd DomainIQ
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e .[dev]
```

### Code quality tools

```bash
# Format code
black domainiq/ tests/ examples/

# Sort imports
isort domainiq/ tests/ examples/

# Type checking
mypy domainiq/

# Linting
flake8 domainiq/ tests/
```

### Building and publishing

```bash
# Build package
python -m build

# Publish to PyPI
python -m twine upload dist/*
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for detailed version history.

## Migration from v1.x

If you're upgrading from the original script version:

**v1.x (script):**
```python
# Old monolithic script usage
python domainIQ.py --whois_lookup example.com
```

**v2.0+ (library):**
```python
# New library usage
from domainiq import DomainIQClient
client = DomainIQClient()
result = client.whois_lookup("example.com")
```

### Key changes:
- ✅ Method names use snake_case (`whois_lookup` not `whois_lookup`)
- ✅ Structured return objects instead of raw dictionaries
- ✅ Modern exception handling
- ✅ Type hints throughout
- ✅ Context manager support
- ✅ Async client available

## Security Research Use Cases

This library is particularly useful for:

- 🔍 **Threat Intelligence**: Analyze suspicious domains and infrastructure
- 🛡️ **Phishing Detection**: Identify lookalike domains and typosquats  
- 📊 **Brand Monitoring**: Track domain registrations related to your brand
- 🔎 **Infrastructure Analysis**: Map relationships between domains, IPs, and entities
- 🚨 **Incident Response**: Quickly gather domain intelligence during security incidents
- 📈 **Research & Development**: Build security tools and automated analysis workflows

## Contributing

We welcome contributions! Please feel free to submit issues, feature requests, and pull requests.

### Contributing Guidelines

1. **Fork the repository** and create your feature branch
2. **Write tests** for any new functionality
3. **Follow the code style** using black, isort, and flake8
4. **Add type hints** to all new code
5. **Update documentation** for any API changes
6. **Test thoroughly** including integration tests when possible

### Development Setup

```bash
git clone https://github.com/seifreed/DomainIQ.git
cd DomainIQ
python -m venv venv
source venv/bin/activate
pip install -e .[dev]
pre-commit install
```

### Running Tests

```bash
# Unit tests only
pytest -m "not integration"

# All tests (requires API key)
pytest

# With coverage
pytest --cov=domainiq
```

## License

This project is licensed under the MIT License - see the LICENSE.md file for details.
