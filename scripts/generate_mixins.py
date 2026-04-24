# ruff: noqa: INP001
"""Generate async mixin classes from their sync counterparts.

Usage:
    python scripts/generate_mixins.py           # rewrite files in-place
    python scripts/generate_mixins.py --dry-run # print diffs, no writes

For each mixin file containing a sync class (e.g. _WhoisMixin), this script
generates the async counterpart (_AsyncXxxMixin) by:
  - Renaming the sync class to its async counterpart
  - Changing 'def ' to 'async def ' in method definitions
  - Inserting 'await ' before all _make_*_request() transport calls
  - Appending " asynchronously" to single-line method docstrings

The generated async class is written between these markers in each file:
    # --- BEGIN GENERATED ---
    # --- END GENERATED ---

Workflow: edit the SYNC class body, then run this script to regenerate
the async counterpart.  The file header (module docstring + imports) and
the sync class are never touched by the script.
"""

from __future__ import annotations

import difflib
import re
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PACKAGE = Path(__file__).parent.parent / "domainiq"

MIXIN_FILES = [
    "_whois_mixin.py",
    "_dns_mixin.py",
    "_domain_analysis_mixin.py",
    "_report_mixin.py",
    "_search_mixin.py",
    "_bulk_mixin.py",
    "_monitor_mixin.py",
]

_BEGIN_MARKER = "# --- BEGIN GENERATED ---\n"
_END_MARKER = "# --- END GENERATED ---\n"

# ---------------------------------------------------------------------------
# Transformation helpers
# ---------------------------------------------------------------------------

_TRANSPORT_RE = re.compile(
    r"\b(self\._make_(?:json_request|json_request_maybe_list|csv_request))\("
)
_CLASS_DECL_RE = re.compile(r"^(class _)(\w+)(Mixin\()(_SyncRequestable)(\):)")
_DEF_RE = re.compile(r"^(\s+)def (\w+)\(")
# Single-line docstring ending with '."""' or '."""' with trailing spaces
_SINGLE_DOCSTRING_RE = re.compile(r'^(\s+""")(.*?)(\.?""")(\s*)$')


def _transform_to_async(sync_source: str) -> str:
    """Return the async version of a sync mixin class source."""
    lines = sync_source.splitlines(keepends=True)
    out: list[str] = []

    for raw_line in lines:
        # 1. Class declaration
        line = _CLASS_DECL_RE.sub(
            lambda m: (
                f"{m.group(1)}Async{m.group(2)}"
                f"{m.group(3)}_AsyncRequestable{m.group(5)}"
            ),
            raw_line,
        )

        # 2. Method definitions: 'def ' → 'async def '
        #    Only indent + 'def ', not e.g. 'defaultdict'
        line = re.sub(r"^(\s+)def (\w)", r"\1async def \2", line)

        # 3. Transport calls: add 'await '
        line = _TRANSPORT_RE.sub(r"await \1(", line)

        # 4. Single-line docstrings: append " asynchronously" before closing """
        m = _SINGLE_DOCSTRING_RE.match(line)
        if m:
            prefix, body = m.group(1), m.group(2)
            closing, trail = m.group(3), m.group(4)
            trail = trail.rstrip("\r\n")
            if body and "asynchronously" not in body:
                # Normalise period: strip trailing period, add ", asynchronously."
                body_stripped = body.rstrip(".")
                line = f"{prefix}{body_stripped} asynchronously.{closing[1:]}{trail}\n"

        out.append(line)

    return "".join(out)


def _format_class_fragment(source: str, path: Path) -> str:
    """Format generated class source with Ruff before comparing or writing."""
    result = subprocess.run(  # noqa: S603 - fixed local tool invocation.
        [sys.executable, "-m", "ruff", "format", "--stdin-filename", str(path), "-"],
        input=source,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        msg = f"ruff format failed for generated {path.name}:\n{result.stderr}"
        raise RuntimeError(msg)
    return result.stdout


def _write_stdout(message: str) -> None:
    sys.stdout.write(f"{message}\n")


def _write_stderr(message: str) -> None:
    sys.stderr.write(f"{message}\n")


# ---------------------------------------------------------------------------
# File processing
# ---------------------------------------------------------------------------


def _extract_last_class(source: str) -> str:
    """Return the source of the last top-level class definition in source."""
    # Find all 'class ' declarations at column 0
    starts = [m.start() for m in re.finditer(r"^class ", source, re.MULTILINE)]
    if not starts:
        msg = "No class definition found in source"
        raise ValueError(msg)
    # The last class runs from its start to end of source
    return source[starts[-1] :]


def process_file(path: Path, dry_run: bool = False) -> bool:
    """Regenerate the async class in path.  Return True if file was changed."""
    text = path.read_text(encoding="utf-8")

    if _BEGIN_MARKER not in text or _END_MARKER not in text:
        _write_stderr(f"  SKIP {path.name}: no generated markers found")
        return False

    begin_idx = text.index(_BEGIN_MARKER)
    end_idx = text.index(_END_MARKER) + len(_END_MARKER)

    # Everything before the BEGIN marker contains the sync class
    before_marker = text[:begin_idx]
    sync_class_src = _extract_last_class(before_marker)

    async_class_src = _format_class_fragment(_transform_to_async(sync_class_src), path)

    new_generated = (
        _BEGIN_MARKER
        + "# Async counterpart of the sync class above — generated by "
        + "scripts/generate_mixins.py\n"
        + "# Edit the sync class, then run `make gen-mixins` to regenerate.\n"
        + async_class_src.rstrip("\n")
        + "\n\n\n"
        + _END_MARKER
    )

    new_text = before_marker + new_generated + text[end_idx:]

    if new_text == text:
        _write_stdout(f"  OK  {path.name}: no changes")
        return False

    if dry_run:
        # Show a simple diff
        diff = difflib.unified_diff(
            text.splitlines(keepends=True),
            new_text.splitlines(keepends=True),
            fromfile=f"a/{path.name}",
            tofile=f"b/{path.name}",
        )
        sys.stdout.writelines(diff)
        return True

    path.write_text(new_text, encoding="utf-8")
    _write_stdout(f"  WROTE {path.name}")
    return True


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    dry_run = "--dry-run" in sys.argv

    if dry_run:
        _write_stdout("DRY RUN — no files will be written\n")

    changed = 0
    for name in MIXIN_FILES:
        path = PACKAGE / name
        if not path.exists():
            _write_stderr(f"  MISSING {path}")
            continue
        if process_file(path, dry_run=dry_run):
            changed += 1

    total = len(MIXIN_FILES)

    _write_stdout(
        f"\n{changed}/{total} file(s) {'would be ' if dry_run else ''}updated."
    )
    if dry_run and changed:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
