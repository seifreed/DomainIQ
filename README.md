<p align="center">
  <img src="https://img.shields.io/badge/DomainIQ-Domain%20Intelligence-blue?style=for-the-badge" alt="DomainIQ">
</p>

<h1 align="center">DomainIQ</h1>

<p align="center">
  <strong>Python client for the DomainIQ API — Domain Intelligence and Security Research</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/domainiq/"><img src="https://img.shields.io/pypi/v/domainiq?style=flat-square&logo=pypi&logoColor=white" alt="PyPI Version"></a>
  <a href="https://pypi.org/project/domainiq/"><img src="https://img.shields.io/pypi/pyversions/domainiq?style=flat-square&logo=python&logoColor=white" alt="Python Versions"></a>
  <a href="https://github.com/seifreed/DomainIQ/blob/main/LICENSE.md"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"></a>
  <a href="https://github.com/seifreed/DomainIQ/actions"><img src="https://img.shields.io/github/actions/workflow/status/seifreed/DomainIQ/quality.yml?style=flat-square&logo=github&label=CI" alt="CI Status"></a>
  <a href="https://codecov.io/gh/seifreed/DomainIQ"><img src="https://img.shields.io/codecov/c/github/seifreed/DomainIQ?style=flat-square&logo=codecov&label=coverage" alt="Coverage"></a>
</p>

<p align="center">
  <a href="https://github.com/seifreed/DomainIQ/stargazers"><img src="https://img.shields.io/github/stars/seifreed/DomainIQ?style=flat-square" alt="GitHub Stars"></a>
  <a href="https://github.com/seifreed/DomainIQ/issues"><img src="https://img.shields.io/github/issues/seifreed/DomainIQ?style=flat-square" alt="GitHub Issues"></a>
  <a href="https://buymeacoffee.com/seifreed"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-yellow?style=flat-square&logo=buy-me-a-coffee&logoColor=white" alt="Buy Me a Coffee"></a>
</p>

---

## Overview

**DomainIQ** is a modern Python client for the DomainIQ API, providing comprehensive domain intelligence and security research capabilities. It supports both synchronous and asynchronous operations, making it ideal for threat intelligence analysts, security researchers, and incident responders.

### Key Features

| Feature | Description |
|---------|-------------|
| **Sync & Async Clients** | Full synchronous and asynchronous API support |
| **Structured Models** | Dataclass-based response models for clean API responses |
| **Flexible Config** | Multiple API key sources (env, file, parameter; CLI prompt when needed) |
| **CLI Tool** | Comprehensive command-line interface included |
| **Error Handling** | Custom exception hierarchy for robust error handling |
| **Type Hints** | Full type annotations throughout the codebase |
| **Retry Logic** | Exponential backoff with configurable retry settings |
| **Context Managers** | Automatic resource cleanup with `with` / `async with` |

### API Coverage

```
Lookups         WHOIS, DNS, Categorization, Snapshots, Reverse DNS
Reports         Domain, Name, Organization, Email, IP
Search          Domain Search, Reverse Search (Email/Name/Org/IP/MX)
Bulk            Bulk DNS, Bulk WHOIS, Bulk Domain IP
Monitoring      Create/List/Delete Reports, Typosquatting, Change Tracking
```

---

## Installation

### From PyPI (Recommended)

```bash
pip install domainiq
```

### With Async Support

```bash
pip install domainiq[async]
```

### From Source

```bash
git clone https://github.com/seifreed/DomainIQ.git
cd DomainIQ
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e .
```

---

## Quick Start

### API Key Configuration

The library supports multiple ways to provide your DomainIQ API key:

```bash
# Environment variable (recommended)
export DOMAINIQ_API_KEY="your_api_key_here"

# Configuration file
echo "your_api_key_here" > ~/.domainiq
```

Or pass it directly in code:

```python
from domainiq import DomainIQClient
client = DomainIQClient(api_key="your_api_key_here")
```

### Basic Usage

```python
from domainiq import DomainIQClient
from domainiq.models import DNSRecordType

# Create client (API key loaded automatically)
client = DomainIQClient()

# WHOIS lookup
whois = client.whois_lookup(domain="example.com")
if whois:
    print(f"Registrar: {whois.registrar}")
    print(f"Created: {whois.creation_date}")

# DNS lookup
dns = client.dns_lookup("example.com", record_types=[DNSRecordType.A, DNSRecordType.MX])
if dns:
    for record in dns.records:
        print(f"{record.type}: {record.value}")

client.close()
```

### Async Usage

```python
import asyncio
from domainiq.async_client import AsyncDomainIQClient

async def main():
    async with AsyncDomainIQClient() as client:
        domains = ["example.com", "google.com", "github.com"]
        results = await client.concurrent_whois_lookup(
            targets=domains, max_concurrent=5
        )
        for domain, result in zip(domains, results):
            if result:
                print(f"{domain}: {result.registrar}")

asyncio.run(main())
```

---

## Usage

### Command Line Interface

| Option | Description |
|--------|-------------|
| `--whois-lookup` | WHOIS lookup for a domain |
| `--dns-lookup` | DNS record query |
| `--domain-report` | Comprehensive domain report |
| `--bulk-dns` | Bulk DNS lookups |
| `--bulk-whois` | Bulk WHOIS lookups |
| `--domain-search` | Search domains by keywords |
| `--reverse-search-type` | Reverse search (email/name/org) |
| `--monitor-list` | List active monitors |
| `--create-monitor-report` | Create a new monitor |
| `--email-report` | Report for an email address |
| `--ip-report` | Report for an IP address |

```bash
# Basic usage
domainiq --whois-lookup example.com
domainiq --dns-lookup example.com --types A,MX
domainiq --domain-report example.com

# Bulk operations
domainiq --bulk-dns example.com google.com github.com
domainiq --bulk-whois example.com google.com

# Monitoring
domainiq --monitor-list
domainiq --create-monitor-report keyword "My Monitor" --email-alert
```

### Python Library

#### Public API Surface

Since 3.0.0, the package root exports clients, exceptions, model types, and
protocol contracts. Response parser helpers are intentionally not re-exported
from `domainiq`; endpoint methods own response parsing internally.

#### Context Manager

```python
with DomainIQClient() as client:
    whois = client.whois_lookup(domain="example.com")
    dns = client.dns_lookup("example.com")
# Client is automatically closed
```

#### Error Handling

```python
from domainiq import (
    DomainIQError,               # Base exception
    DomainIQAPIError,            # API-related errors
    DomainIQAuthenticationError, # Invalid API key
    DomainIQRateLimitError,      # Rate limiting
    DomainIQTimeoutError,        # Request timeouts
    DomainIQConfigurationError,  # Configuration issues
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

#### Custom Configuration

```python
from domainiq import DomainIQClient
from domainiq.config import Config

config = Config(
    api_key="your_key",
    base_url="https://api.domainiq.com/custom",
    timeout=60,
    max_retries=5,
    retry_delay=2,
)

client = DomainIQClient(config=config)
```

### Data Models

```python
# WhoisResult
whois = client.whois_lookup("example.com")
whois.domain             # str
whois.registrar          # str
whois.creation_date      # datetime
whois.expiration_date    # datetime
whois.registrant_name    # str
whois.nameservers        # List[str]

# DNSResult
dns = client.dns_lookup("example.com")
dns.domain               # str
for record in dns.records:
    record.type           # str (A, MX, CNAME, etc.)
    record.value          # str
    record.ttl            # int

# DomainReport
report = client.domain_report("example.com")
report.domain            # str
report.risk_score        # float
report.categories        # List[str]
report.related_domains   # List[str]
```

---

## Examples

### Security Research Workflow

```python
from domainiq import DomainIQClient
from datetime import datetime

client = DomainIQClient()

suspicious_domains = ["suspicious-site.com", "fake-bank.net"]
for domain in suspicious_domains:
    whois = client.whois_lookup(domain=domain)
    if whois and whois.creation_date:
        days_old = (datetime.now() - whois.creation_date.replace(tzinfo=None)).days
        if days_old < 30:
            print(f"{domain} is newly registered ({days_old} days old)")

    categories = client.domain_categorize([domain])
    if categories and categories[0].categories:
        for cat in categories[0].categories:
            if any(risk in cat.lower() for risk in ['malware', 'phishing', 'suspicious']):
                print(f"{domain} categorized as: {cat}")
```

### Process Multiple Domains

```python
from domainiq import DomainIQClient
from pathlib import Path

client = DomainIQClient()

domains = Path("domains.txt").read_text().splitlines()
for domain in domains:
    whois = client.whois_lookup(domain=domain.strip())
    if whois:
        print(f"{domain}: {whois.registrar}")
```

More examples in the `examples/` directory:
- **`basic_usage.py`** — Fundamental operations
- **`async_usage.py`** — High-performance async operations
- **`security_research.py`** — Security analysis workflows

---

## Requirements

- Python 3.13+
- See [pyproject.toml](pyproject.toml) for full dependency list

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## Support the Project

If you find DomainIQ useful, consider supporting its development:

<a href="https://buymeacoffee.com/seifreed" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50">
</a>

---

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

**Attribution Required:**
- Author: **Marc Rivero** | [@seifreed](https://github.com/seifreed)
- Repository: [github.com/seifreed/DomainIQ](https://github.com/seifreed/DomainIQ)

---

<p align="center">
  <sub>Made with dedication for the threat intelligence community</sub>
</p>
