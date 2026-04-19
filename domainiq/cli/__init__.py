"""Command-line interface for the DomainIQ library."""

import sys
import traceback

from ..config import Config
from ..exceptions import DomainIQError
from ..utils import setup_logging
from ._args import create_parser
from ._dispatch import (
    _dispatch_command,
    _dispatch_dns,
    _dispatch_whois,
    _EXIT_NO_COMMAND,
    _EXIT_SUCCESS,
)

__all__ = ["main", "create_parser"]


def main() -> int:
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()

    if args.debug:
        log_level = "DEBUG"
    elif args.verbose:
        log_level = "INFO"
    else:
        log_level = "WARNING"

    setup_logging(level=log_level)

    try:
        config = Config(
            api_key=args.api_key,
            timeout=args.timeout,
            config_file=args.config_file,
        )

        from ..client import DomainIQClient
        with DomainIQClient(config) as client:
            exit_code = _dispatch_command(client, args)
            if exit_code == _EXIT_NO_COMMAND:
                parser.print_help()
                return exit_code
            if exit_code != _EXIT_SUCCESS:
                return exit_code

    except DomainIQError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    except ValueError as e:
        # User-provided argument values failed validation
        print(f"Invalid argument: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        # File system or network setup error (e.g. config file unreadable)
        print(f"I/O error: {e}", file=sys.stderr)
        if args.debug:
            traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
