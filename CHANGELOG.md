# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-10-23

### Fixed

- The package failed to import on Python 3.10, which it declares as supported,
  because it used `datetime.UTC` (added in Python 3.11).
- Malformed target URLs, such as an out-of-range or non-numeric port, now fail
  with a clear error before any request instead of crashing mid-run.
- Transport errors outside `httpx.RequestError` (for example invalid URLs) are
  recorded as availability findings instead of aborting the whole run.
- Headers passed with `-H` now replace the default `Content-Type` and `Accept`
  headers case-insensitively instead of being sent twice.
- `TestCase` no longer triggers pytest collection warnings in test suites that
  import it.

### Added

- `a2afuzz --version` and `python -m a2afuzz`.
- Documented exit codes: `--only` selectors that match nothing, unwritable
  report directories, and invalid settings exit with code 2; Ctrl-C exits with
  130 without a traceback.
- Public Python API exported from `a2afuzz` (`FuzzRunner`, `write_reports`,
  `generate_cases`, and the data models) with a `py.typed` marker.
- End-to-end tests that fuzz the bundled demo agent over real HTTP in both
  modes, plus CLI, transport, and runner regression tests.
- CI on Python 3.10 to 3.14, macOS, and Windows; format checking; a packaging
  job that builds the wheel, installs it in a clean environment, and runs the
  CLI against the demo agent.
- SARIF output now includes the tool's `informationUri`.

### Changed

- The version is defined once in `a2afuzz/_version.py` and used by packaging
  and all report formats.
- Removed the unused `pytest-asyncio` development dependency.
- README rewritten with installation, usage, exit codes, check reference,
  report formats, CI and Python API examples, and known limitations.

## [0.1.0] - 2026-10-22

- Initial release: deterministic A2A, MCP, and JSON-RPC probe sets, six
  response oracles, JSON/HTML/SARIF reports, loopback-only target guard, and a
  demo agent with vulnerable and hardened modes.
