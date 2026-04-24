"""Command-line interface for the DomainIQ library."""

import argparse
import sys
import traceback

from ..config import Config
from ..constants import EXIT_NO_COMMAND
from ..exceptions import DomainIQConfigurationError, DomainIQError
from ..utils import setup_logging
from ._args import create_parser
from ._credentials import prompt_for_api_key

__all__ = ["create_parser", "main"]


def _build_config(args: argparse.Namespace) -> Config:
    """Build Config from parsed CLI arguments."""
    try:
        return Config(
            api_key=args.api_key,
            timeout=args.timeout,
            config_file=args.config_file,
        )
    except DomainIQConfigurationError:
        api_key = prompt_for_api_key(args.config_file)
        return Config(
            api_key=api_key,
            timeout=args.timeout,
            config_file=args.config_file,
        )


def _handle_cli_error(exc: Exception, debug: bool) -> int:
    """Map a caught exception to a CLI exit code, printing to stderr."""
    if isinstance(exc, DomainIQError):
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    if isinstance(exc, KeyboardInterrupt):
        return 130
    if isinstance(exc, ValueError):
        print(f"Invalid argument: {exc}", file=sys.stderr)
        return 1
    if isinstance(exc, OSError):
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        if debug:
            traceback.print_exc()
        return 1
    raise exc


def main() -> int:
    """Main CLI entry point."""
    from ._dispatch import _dispatch_command

    parser = create_parser()
    args = parser.parse_args()

    log_level = "DEBUG" if args.debug else "INFO" if args.verbose else "WARNING"
    setup_logging(level=log_level)

    try:
        config = _build_config(args)
        from ..client import DomainIQClient
        with DomainIQClient(config) as client:
            exit_code = _dispatch_command(client, args)
            if exit_code == EXIT_NO_COMMAND:
                parser.print_help()
            return exit_code
    except (DomainIQError, KeyboardInterrupt, ValueError, OSError) as e:
        return _handle_cli_error(e, args.debug)


if __name__ == "__main__":
    sys.exit(main())
