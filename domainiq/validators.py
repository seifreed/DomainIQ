"""Input validation functions for domains, IP addresses, and emails."""

import ipaddress
import logging
import re
from datetime import date
from decimal import Decimal

from .exceptions import DomainIQValidationError

logger = logging.getLogger(__name__)

MAX_DOMAIN_LENGTH = 255
MAX_LABEL_LENGTH = 63
MIN_DOMAIN_LABELS = 2
MAX_EMAIL_PARTS = 2
IPV4_VERSION = 4
IPV6_VERSION = 6
IPV4_OCTET_COUNT = 4

_LABEL_PATTERN = re.compile(r"^[a-zA-Z0-9-]+$")
_EMAIL_LOCAL_PATTERN = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$")


def _is_ip_like_domain(value: str) -> bool:
    """Return True when a domain-shaped value is actually an IP literal."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _validate_label(label: str) -> bool:
    """Validate a single DNS label (handles IDN and ASCII labels)."""
    try:
        # Intentional rebind: normalize IDN label before length/char validation.
        label = label.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    if not (0 < len(label) <= MAX_LABEL_LENGTH):
        return False
    if label.startswith("-") or label.endswith("-"):
        return False
    return bool(_LABEL_PATTERN.fullmatch(label))


def validate_domain(domain: str) -> bool:
    """Basic domain name validation.

    Args:
        domain: Domain name to validate

    Returns:
        True if domain appears valid, False otherwise
    """
    if (
        not domain
        or not isinstance(domain, str)
        or len(domain) > MAX_DOMAIN_LENGTH
        or _is_ip_like_domain(domain)
        or domain.startswith(".")
        or domain.endswith(".")
        or ".." in domain
    ):
        return False
    labels = domain.split(".")
    # Reject strings that look like IPv4 addresses (4 numeric octets).
    if len(labels) == IPV4_OCTET_COUNT and all(part.isdigit() for part in labels):
        return False
    if len(labels) < MIN_DOMAIN_LABELS:
        return False
    return all(_validate_label(label) for label in labels)


def validate_ipv4(ip: str) -> bool:
    """Validate an IPv4 address.

    Args:
        ip: IP address to validate

    Returns:
        True if IP appears valid, False otherwise
    """
    if not ip or not isinstance(ip, str):
        return False
    try:
        return ipaddress.ip_address(ip).version == IPV4_VERSION
    except ValueError:
        return False


def validate_ipv6(ip: str) -> bool:
    """Validate an IPv6 address.

    Args:
        ip: IP address string to validate

    Returns:
        True if ip is a valid IPv6 address, False otherwise
    """
    if not ip or not isinstance(ip, str):
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    else:
        return addr.version == IPV6_VERSION


def is_ip_address(value: str) -> bool:
    """Check if a string is any valid IP address (IPv4 or IPv6).

    Args:
        value: String to check

    Returns:
        True if value is a valid IPv4 or IPv6 address
    """
    return validate_ipv4(value) or validate_ipv6(value)


def validate_email(email: str) -> bool:
    """Basic email address validation.

    Args:
        email: Email address to validate

    Returns:
        True if email appears valid, False otherwise
    """
    if not email or not isinstance(email, str):
        return False

    if "@" not in email:
        return False

    parts = email.split("@")
    if len(parts) != MAX_EMAIL_PARTS:
        return False

    local, domain = parts
    if not local or not domain:
        return False
    if (
        not _EMAIL_LOCAL_PATTERN.fullmatch(local)
        or local.startswith(".")
        or local.endswith(".")
        or ".." in local
    ):
        return False

    return validate_domain(domain)


def validate_whois_target(
    domain: str | None, ip: str | None
) -> tuple[str | None, str | None]:
    """Validate and normalize domain/IP args for a WHOIS lookup.

    Returns (domain, ip) stripped of whitespace. Raises ValueError on invalid input.
    """
    domain_provided = domain is not None
    ip_provided = ip is not None

    if domain is not None and not isinstance(domain, str):
        msg = f"domain must be a string, got {type(domain).__name__}"
        raise DomainIQValidationError(msg, param_name="domain")
    if ip is not None and not isinstance(ip, str):
        msg = f"ip must be a string, got {type(ip).__name__}"
        raise DomainIQValidationError(msg, param_name="ip")

    if domain is not None:
        domain = domain.strip() or None
    if ip is not None:
        ip = ip.strip() or None

    if domain_provided and not domain:
        msg = "domain cannot be empty or whitespace-only"
        raise DomainIQValidationError(msg, param_name="domain")
    if ip_provided and not ip:
        msg = "ip cannot be empty or whitespace-only"
        raise DomainIQValidationError(msg, param_name="ip")
    if not domain and not ip:
        msg = "Either domain or ip must be provided"
        raise DomainIQValidationError(msg, param_name="domain")
    if domain and ip:
        msg = "Cannot specify both domain and ip"
        raise DomainIQValidationError(msg, param_name="domain")
    if domain and not validate_domain(domain):
        msg = f"Invalid domain: {domain}"
        raise DomainIQValidationError(msg, param_name="domain")
    if ip and not is_ip_address(ip):
        msg = f"Invalid IP address: {ip}"
        raise DomainIQValidationError(msg, param_name="ip")

    return domain, ip


def ensure_positive_int(field_name: str, value: object) -> int:
    """Raise DomainIQValidationError if value is not a positive integer."""
    if (
        (isinstance(value, int) and not isinstance(value, bool))
        or (isinstance(value, float) and value.is_integer())
        or (
            isinstance(value, Decimal)
            and not value.is_nan()
            and not value.is_infinite()
            and value == int(value)
        )
    ):
        int_value = int(value)
    else:
        msg = f"{field_name} must be a positive integer, got {value!r}"
        raise DomainIQValidationError(msg, param_name=field_name)

    if int_value <= 0:
        msg = f"{field_name} must be positive, got {value!r}"
        raise DomainIQValidationError(msg, param_name=field_name)
    return int_value


def validate_date_string(date_str: str) -> str:
    """Parse and validate date string for API usage.

    Only accepts unambiguous ISO format YYYY-MM-DD.

    Args:
        date_str: Date string in YYYY-MM-DD format

    Returns:
        Validated date string (YYYY-MM-DD)

    Raises:
        DomainIQValidationError: If the date string is invalid.
    """
    if not isinstance(date_str, str) or not date_str:
        msg = f"Invalid date format: {date_str!r} (expected YYYY-MM-DD)"
        raise DomainIQValidationError(msg, param_name="date")

    date_str = date_str.strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_str):
        try:
            date.fromisoformat(date_str)
        except ValueError:
            pass
        else:
            return date_str

    msg = f"Invalid date format: {date_str} (expected YYYY-MM-DD)"
    raise DomainIQValidationError(msg, param_name="date")
