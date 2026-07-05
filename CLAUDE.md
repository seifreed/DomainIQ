# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Non-negotiables

These are hard constraints. Do not work around them, do not ask to relax them.

- **Clean Code and Clean Architecture are mandatory**, not aspirational. Every change must comply (see sections below).
- **Quality gate must exist and stay green.** The project must run a quality gate covering `bandit`, `ruff`, `mypy`, `black`, and `pip-audit`. It must pass with **zero errors and zero warnings**.
- **Suppressing any error, warning, or policy is forbidden** — no `# noqa`, `# type: ignore`, `# nosec`, `--ignore`, `--exit-zero`, `fmt: off`, per-file ignore additions, or lowering any tool's severity to make the gate pass. Fix the underlying cause instead.
- **No legacy support.** No compatibility shims, deprecated-path fallbacks, or "old behavior" branches. Target the current version only and delete what it replaces.
- **No code duplication.** Duplicated logic must be factored out; three similar lines is fine, a copied block is not.
- **No mocks.** Tests exercise real code paths. Use real objects, in-memory implementations, or local test doubles that run the actual logic — never `unittest.mock`/`MagicMock`/patching to fake behavior.
- **Python 3.14.** Target and require Python 3.14; use its features freely and do not gate on older interpreters.

## Commands

All workflows are driven through the `Makefile` (`make help` lists them):

- `make test-unit` — unit tests only, no API key needed (this is what CI runs). Integration tests are excluded by default via `pytest.ini`.
- `make test-integration` — integration tests; requires `DOMAINIQ_API_KEY`.
- `make coverage` — full suite with coverage (HTML + XML). Coverage gate is **95%**.
- Single test: `pytest tests/test_client.py::TestLogicBugRegressions::test_<name>` (or `pytest -k "<expr>"`). `pytest -x` stops on first failure.
- `make quality` — runs `lint` (Ruff) + `format` (Ruff) + `type-check` (MyPy `strict`) + `security` (Bandit).
- `make ci-checks` — the exact gate CI enforces: `gen-mixins-check format-check lint type-check security test-unit`.
- `make build` — build sdist/wheel via hatchling.

Target Python is **3.14** (MyPy `strict`). CLI entry point: `domainiq = "domainiq.cli:main"`.

## Sync/async mixin generation — read before editing any `_*_mixin.py`

The async client is **generated from the sync client**, not hand-written. Each `domainiq/_*_mixin.py` file contains a hand-written sync class (e.g. `_WhoisMixin`) and a generated async counterpart (`_AsyncWhoisMixin`) sitting between `# --- BEGIN GENERATED ---` / `# --- END GENERATED ---` markers.

- **Edit only the sync class body**, then run `make gen-mixins` to regenerate the async version.
- Never hand-edit code between the generated markers — it will be overwritten.
- `make gen-mixins-check` (in CI) fails if the generated async code is stale relative to the sync source.
- The generator (`scripts/generate_mixins.py`) mechanically renames the class, turns `def`→`async def`, inserts `await` before `_make_*_request()` calls, and appends "asynchronously" to one-line docstrings.

## Architecture

Layers, dependencies pointing inward (CLI/transport → domain logic, never the reverse):

- **Clients** — `client.py` (`DomainIQClient`) and `async_client.py` (`AsyncDomainIQClient`) are thin composition roots. Each subclasses the domain mixins plus `_BaseDomainIQClient`. All API surface lives in the mixins (`_whois_mixin`, `_dns_mixin`, `_domain_analysis_mixin`, `_report_mixin`, `_search_mixin`, `_bulk_mixin`, `_monitor_mixin`), re-exported through `_mixins.py`.
- **Request pipeline** — `_request_pipeline.py` holds the single retry/error-handling flow shared by both clients (`execute_sync_request` / async variant), driven by `request_policy.py` (retry classification, HTTP-response classification, body parsing). `_sync_sleep`/`_async_sleep` are indirection points so tests stub retries without patching stdlib.
- **Transport** — `http/` defines transport protocols (`SyncTransport`/`AsyncTransport`) with `RequestsTransport` and the optional aiohttp transport as implementations. This is the I/O boundary; business logic is I/O-free.
- **Config & key resolution** — `config.py` + `_key_sources.py`. API keys resolve **only** from explicit, non-interactive sources, in order: explicit param → `DOMAINIQ_API_KEY` env var → `~/.domainiq` file. Each source is a `KeySource` protocol implementation.
- **Params / (de)serialization** — `_params/` builds typed request params per domain; `parsers.py`/`deserializers.py` turn raw responses into `models.py` dataclasses; `formatters.py` renders output.
- **Protocols** — `protocols.py` exposes narrow per-capability interfaces (`WhoisProtocol`, `DNSProtocol`, …, `DomainIQClientProtocol`). **Annotate function args with the narrowest protocol that covers what's needed, not the concrete client class.**
- **CLI** — `cli/` parses args (`_args.py`), validates (`_validation.py`), and dispatches (`_dispatch*.py`, one dispatcher per domain) into the client. Parsing/validation happen before domain logic touches user data.

## Regression Contracts

Every bug fix must include a regression test that fails before the fix and passes after.
- Regression tests live in `tests/test_client.py` under `TestLogicBugRegressions` or in the appropriate module-specific test file.
- Name regression tests descriptively: `test_<bug_description>_regression`.
- Regression tests must exercise the exact edge case that caused the bug, not just the happy path.
- Before submitting a fix, run the regression test against the unfixed code to confirm it fails.

## Conventions

- `from __future__ import annotations` at the top of modules; group stdlib / third-party / local imports (isort first-party = `domainiq`).
- Extract magic numbers/strings to module-level constants (`constants.py`, `_http_constants.py`).
- Prefer early returns over deeply nested `if` blocks. Booleans named `is_`/`has_`; functions are verbs.
- Comments explain *why*, not *what*. Ruff docstring convention is Google-style.
