"""Entry point for running domainiq as a module.

Usage:
    python -m domainiq --whois-lookup example.com
    python -m domainiq --help
"""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
