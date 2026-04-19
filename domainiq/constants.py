"""Domain-level constants for the DomainIQ API wire format."""

# API response format tokens (wire values)
API_FORMAT_JSON = "json"
API_FORMAT_CSV = "csv"

# Integer flag value to enable an optional API feature
API_FLAG_ENABLED = 1
API_FLAG_DISABLED = 0

# String-encoded booleans used by the monitor endpoint
API_BOOL_TRUE = "1"
API_BOOL_FALSE = "0"

RETRY_EXHAUSTED_MSG = "API request failed after all retries"

# Default screenshot dimensions (DomainIQ API recommendation for thumbnail display)
SNAPSHOT_DEFAULT_WIDTH = 250
SNAPSHOT_DEFAULT_HEIGHT = 125
SNAPSHOT_DEFAULT_LIMIT = 10

# Typo-monitoring strength bounds enforced by the DomainIQ monitor API
TYPO_STRENGTH_MIN = 5
TYPO_STRENGTH_MAX = 41

# Network and timeout defaults (overridable via environment variables)
INTERACTIVE_PROMPT_TIMEOUT: int = 30
DEFAULT_TIMEOUT: float = 30.0
DEFAULT_CONNECTOR_LIMIT: int = 100
DEFAULT_CONNECTOR_LIMIT_PER_HOST: int = 30
