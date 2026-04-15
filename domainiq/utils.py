"""Utility functions for the DomainIQ library."""

import csv
import logging
import time
from functools import wraps
from io import StringIO
from typing import Any

from .exceptions import DomainIQError

logger = logging.getLogger(__name__)

# Domain validation constants
MAX_DOMAIN_LENGTH = 255
MAX_LABEL_LENGTH = 63
MIN_DOMAIN_LABELS = 2
IPV4_OCTETS = 4
MAX_OCTET_VALUE = 255
MAX_EMAIL_PARTS = 2
MAX_FILENAME_LENGTH = 200


def csv_to_dict_list(csv_content: str) -> list[dict[str, Any]]:
    """Convert CSV content to a list of dictionaries.

    Args:
        csv_content: CSV content as string

    Returns:
        List of dictionaries representing CSV rows

    Raises:
        DomainIQError: If CSV parsing fails
    """
    try:
        f = StringIO(csv_content)
        reader = csv.DictReader(f, delimiter=",")
        return list(reader)
    except Exception as e:
        msg = f"Failed to parse CSV content: {e}"
        raise DomainIQError(msg) from e


def validate_domain(domain: str) -> bool:
    """Basic domain name validation.

    Args:
        domain: Domain name to validate

    Returns:
        True if domain appears valid, False otherwise
    """
    if not domain or not isinstance(domain, str):
        return False

    # Basic checks
    if len(domain) > MAX_DOMAIN_LENGTH:
        return False

    if domain.startswith(".") or domain.endswith("."):
        return False

    if ".." in domain:
        return False

    # Split into labels and check each
    labels = domain.split(".")
    if len(labels) < MIN_DOMAIN_LABELS:  # Must have at least one dot
        return False

    for label in labels:
        if not label:  # Empty label
            return False
        if len(label) > MAX_LABEL_LENGTH:  # Label too long
            return False
        if label.startswith("-") or label.endswith("-"):  # Invalid hyphens
            return False

    return True


def validate_ip(ip: str) -> bool:
    """Basic IP address validation (IPv4).

    Args:
        ip: IP address to validate

    Returns:
        True if IP appears valid, False otherwise
    """
    if not ip or not isinstance(ip, str):
        return False

    parts = ip.split(".")
    if len(parts) != IPV4_OCTETS:
        return False

    try:
        for part in parts:
            num = int(part)
            if num < 0 or num > MAX_OCTET_VALUE:
                return False
    except ValueError:
        return False

    return True


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

    # Validate domain part
    return validate_domain(domain)


def sanitize_filename(filename: str) -> str:
    """Sanitize a filename by removing/replacing invalid characters.

    Args:
        filename: Original filename

    Returns:
        Sanitized filename safe for filesystem use
    """
    if not filename:
        return "unnamed"

    # Replace invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, "_")

    # Remove leading/trailing whitespace and dots
    filename = filename.strip(" .")

    # Ensure not empty
    if not filename:
        return "unnamed"

    # Truncate if too long
    if len(filename) > MAX_FILENAME_LENGTH:
        filename = filename[:MAX_FILENAME_LENGTH]

    return filename


def retry_on_exception(
    exceptions: Exception | tuple = Exception,
    max_retries: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
):
    """Decorator to retry function on specified exceptions.

    Args:
        exceptions: Exception or tuple of exceptions to catch
        max_retries: Maximum number of retry attempts
        delay: Initial delay between retries in seconds
        backoff: Multiplier for delay on each retry

    Returns:
        Decorated function
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            current_delay = delay

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    if attempt == max_retries:
                        logger.exception(
                            "Function %s failed after %s retries: %s",
                            func.__name__,
                            max_retries,
                            e,
                        )
                        raise

                    logger.warning(
                        "Function %s failed on attempt %s, retrying in %ss: %s",
                        func.__name__,
                        attempt + 1,
                        current_delay,
                        e,
                    )
                    time.sleep(current_delay)
                    current_delay *= backoff

            return None  # Should never reach here

        return wrapper

    return decorator


def format_api_params(params: dict[str, Any]) -> dict[str, str]:
    """Format parameters for API requests.

    Args:
        params: Dictionary of parameters

    Returns:
        Dictionary with properly formatted string values
    """
    formatted = {}

    for key, value in params.items():
        if value is None:
            continue

        if isinstance(value, bool):
            # Convert boolean to '1' or '0' for API
            formatted[key] = "1" if value else "0"
        elif isinstance(value, list | tuple):
            # Join lists with appropriate separator
            if key in ("domains", "items"):
                formatted[key] = ">>".join(str(v) for v in value)
            else:
                formatted[key] = ",".join(str(v) for v in value)
        else:
            formatted[key] = str(value)

    return formatted


def parse_date_range(date_str: str) -> str | None:
    """Parse and validate date string for API usage.

    Args:
        date_str: Date string in various formats

    Returns:
        Standardized date string (YYYY-MM-DD) or None if invalid
    """
    if not date_str:
        return None

    # Try different date formats
    import re
    from datetime import datetime

    # YYYY-MM-DD format
    if re.match(r"^\d{4}-\d{2}-\d{2}$", date_str):
        try:
            datetime.strptime(date_str, "%Y-%m-%d")
            return date_str
        except ValueError:
            pass

    # MM/DD/YYYY format
    if re.match(r"^\d{1,2}/\d{1,2}/\d{4}$", date_str):
        try:
            dt = datetime.strptime(date_str, "%m/%d/%Y")
            return dt.strftime("%Y-%m-%d")
        except ValueError:
            pass

    # DD/MM/YYYY format
    if re.match(r"^\d{1,2}/\d{1,2}/\d{4}$", date_str):
        try:
            dt = datetime.strptime(date_str, "%d/%m/%Y")
            return dt.strftime("%Y-%m-%d")
        except ValueError:
            pass

    logger.warning("Invalid date format: %s", date_str)
    return None


def chunk_list(lst: list[Any], chunk_size: int) -> list[list[Any]]:
    """Split a list into chunks of specified size.

    Args:
        lst: List to split
        chunk_size: Size of each chunk

    Returns:
        List of chunks
    """
    if chunk_size <= 0:
        msg = "Chunk size must be positive"
        raise ValueError(msg)

    return [lst[i : i + chunk_size] for i in range(0, len(lst), chunk_size)]


def setup_logging(
    level: str = "INFO", format_string: str | None = None, filename: str | None = None
) -> None:
    """Setup logging configuration for the library.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format_string: Custom format string for log messages
        filename: Optional filename to write logs to
    """
    if format_string is None:
        format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    logging_config = {
        "level": getattr(logging, level.upper()),
        "format": format_string,
        "datefmt": "%Y-%m-%d %H:%M:%S",
    }

    if filename:
        logging_config["filename"] = filename

    logging.basicConfig(**logging_config)
