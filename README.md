# a2a-fuzzer

[![CI](https://github.com/kirtanbhatt10/a2a-fuzzer/actions/workflows/ci.yml/badge.svg)](https://github.com/kirtanbhatt10/a2a-fuzzer/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Bounded conformance and robustness fuzzing for agent-to-agent protocols.

Point `a2afuzz` at an **A2A**, **MCP**, or plain **JSON-RPC 2.0** HTTP endpoint you own. It sends a small, deterministic set of malformed and edge-case requests and tells you where the server crashes, leaks internals, accepts input it should reject, or trusts data a client should never control. Every run produces JSON, HTML, and SARIF reports, so it drops straight into CI and GitHub code scanning.

> [!IMPORTANT]
> Use this tool only on systems you own or have explicit written permission to test. It refuses any non-loopback target unless you pass `--i-am-authorized`. Requests and captured responses are capped at 256 KiB each; this is robustness testing, not load testing.

## Contents

- [Features](#features)
- [Install](#install)
- [Quick start](#quick-start)
- [Usage](#usage)
- [What it checks](#what-it-checks)
- [Reports](#reports)
- [Using it in CI](#using-it-in-ci)
- [Python API](#python-api)
- [Limitations](#limitations)
- [Development](#development)
- [Responsible use](#responsible-use)
- [License](#license)

## Features

- **Deterministic and finite.** 26 generic JSON-RPC cases, plus 6 A2A or 5 MCP trust-boundary cases. The same input set every run, so results are reproducible and diffable. List them with `a2afuzz list` without sending anything.
- **Six response oracles**: crash, availability, info-leak, trust-boundary, validation, and conformance, each mapped to a severity.
- **Safe by default.** Loopback-only unless explicitly authorized, URL validation before any network I/O, no redirects followed, bounded payloads and response captures, configurable rate limit and concurrency.
- **CI-ready.** `--fail-on <severity>` sets the exit code; SARIF output uploads to GitHub code scanning.
- **Small footprint.** Two runtime dependencies (`httpx`, `typer`). Python 3.10+ on Linux, macOS, and Windows.

## Install

The package is not published to PyPI yet. Install it from GitHub:

```bash
pip install "git+https://github.com/kirtanbhatt10/a2a-fuzzer.git"
```

Or from a clone, with the development tools:

```bash
git clone https://github.com/kirtanbhatt10/a2a-fuzzer.git
cd a2a-fuzzer
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Check the install:

```bash
a2afuzz --version
```

## Quick start

The repository ships a small demo agent (standard library only) with a deliberately vulnerable default mode and a hardened `--secure` mode.

```bash
# Terminal 1: the vulnerable target
python examples/demo_agent.py

# Terminal 2: fuzz it
a2afuzz run http://127.0.0.1:9999/ -p a2a
```

You will see something like:

```text
Completed 32 cases: 35 findings (high=12, medium=22, low=1, info=0).
Reports: reports/a2afuzz.report.json, reports/a2afuzz.report.html, reports/a2afuzz.sarif
```

Open `reports/a2afuzz.report.html` in a browser for the full breakdown. Exact counts can vary slightly by Python version, because the demo relies on the standard-library JSON parser.

Now run the hardened mode and watch every finding disappear:

```bash
python examples/demo_agent.py --secure --port 9998
a2afuzz run http://127.0.0.1:9998/ -p a2a
# Completed 32 cases: 0 findings (high=0, medium=0, low=0, info=0).
```

The `--secure` code path in [`examples/demo_agent.py`](examples/demo_agent.py) is a compact reference for the controls each check expects: strict parsing, envelope and ID validation, size and depth limits, and trust-boundary rejection.

## Usage

```text
a2afuzz run URL [OPTIONS]      Run the probes and write reports
a2afuzz list [-p PROTOCOL]     Print the case set without sending anything
a2afuzz --version              Print the version
python -m a2afuzz ...          Same CLI, without the console script
```

`URL` is the JSON-RPC HTTP endpoint. Each case is sent as one `POST` with `Content-Type: application/json`.

| Option | Default | Description |
| --- | --- | --- |
| `-p, --protocol` | `a2a` | `a2a`, `mcp`, or `jsonrpc` |
| `-o, --out` | `reports/` | Directory for the JSON, HTML, and SARIF reports (created if missing) |
| `--concurrency` | `4` | Maximum requests in flight |
| `--rate` | `10` | Maximum requests per second; `0` means unlimited |
| `--timeout` | `10` | Per-request timeout in seconds; responses slower than 80% of it are flagged |
| `-H, --header` | none | Extra request header as `'Name: value'`; repeatable (for example an auth token) |
| `--only` | all | Case-ID prefix or category; repeatable or comma-separated |
| `--fail-on` | none | Exit `1` if any finding is at or above `info`, `low`, `medium`, or `high` |
| `--i-am-authorized` | off | Required before probing any non-loopback host |

Examples:

```bash
# Only the trust-boundary and parsing cases
a2afuzz run http://127.0.0.1:8080/rpc --only trust-boundary,parsing

# An authenticated staging endpoint you are authorized to test
a2afuzz run https://agent.staging.example.com/a2a -p a2a \
  -H "Authorization: Bearer $TOKEN" --i-am-authorized --rate 2

# An MCP server that answers JSON-RPC over plain HTTP
a2afuzz run http://127.0.0.1:3000/mcp -p mcp --fail-on medium
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The run completed and no finding met the `--fail-on` threshold (or no threshold was set) |
| `1` | At least one finding met the `--fail-on` threshold |
| `2` | Usage error: bad option, malformed or unauthorized target, `--only` matched nothing, or the report directory is not writable |
| `130` | Interrupted with Ctrl-C; no reports were written |

## What it checks

Run `a2afuzz list -p <protocol>` to see every case. The suite covers:

| Category | Cases | Examples |
| --- | --- | --- |
| `parsing` | 6 | Truncated or empty body, UTF-8 BOM, invalid UTF-8, `NaN`, duplicate keys |
| `envelope` | 6 | Missing or wrong `jsonrpc` version, missing or non-string `method`, scalar `params` |
| `ids` | 4 | Object IDs, 40-digit integers, 10 KiB strings, bidi and zero-width characters |
| `methods` | 4 | Unknown, reserved `rpc.*`, path-like, and dunder method names |
| `notifications` | 1 | A notification must not get a response |
| `batches` | 2 | Empty batch, batch with a malformed member |
| `resource-limits` | 3 | 2,000-level nesting, 240 KiB string, 20,000-key object |
| `trust-boundary` (A2A) | 6 | Client claiming the `agent` or `system` role, `file://` and `../` URIs, foreign or wildcard task IDs |
| `trust-boundary`, `validation` (MCP) | 5 | Unsupported protocol version, traversal and sensitive `resources/read` URIs, malformed `tools/call` and `initialize` |

Each response is evaluated by these oracles:

| Oracle | Severity | Detects |
| --- | --- | --- |
| `crash` | high | HTTP 5xx in response to malformed input |
| `availability` | high / low | Timeouts (high); dropped connections, slow responses, oversized responses (low) |
| `info-leak` | high / medium | Credential-like tokens or stack traces (high); server file paths (medium) |
| `trust-boundary` | medium | A success `result` for a role, URI, or task-ownership probe |
| `validation` | medium | A success `result` for malformed or unsupported input |
| `conformance` | low | Replies to notifications, non-JSON success bodies, wrong `jsonrpc` version, mismatched response IDs |

A JSON-RPC error object, an HTTP 4xx, or a clean refusal is always a pass. For the `ids` category a `null` response ID is accepted, because the specification allows it when the request ID cannot be read.

## Reports

Every run writes three files to `--out`:

| File | Purpose |
| --- | --- |
| `a2afuzz.report.json` | Complete machine-readable record: every request, response status, headers, body, timing, and finding. Bodies that are not valid UTF-8 are stored as base64. |
| `a2afuzz.report.html` | Self-contained report for humans, with light and dark themes. All endpoint content is HTML-escaped. |
| `a2afuzz.sarif` | SARIF 2.1.0, ready for GitHub code scanning or any SARIF viewer |

Reports can contain whatever the target sent back, including leaked secrets that triggered an `info-leak` finding. Treat them as sensitive. Request headers you pass with `-H` are never written to the reports.

## Using it in CI

A GitHub Actions job that starts your agent, fuzzes it, fails the build on medium or worse, and uploads the results to code scanning:

```yaml
jobs:
  fuzz:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # required for the SARIF upload
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-python@v6
        with:
          python-version: "3.12"
      - run: pip install "git+https://github.com/kirtanbhatt10/a2a-fuzzer.git"
      - name: Start the agent under test
        run: |
          python -m my_agent --port 8080 &
          sleep 2
      - name: Fuzz
        run: a2afuzz run http://127.0.0.1:8080/ -p a2a --fail-on medium
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: reports/a2afuzz.sarif
```

Pin the install to a tag or commit (`...a2a-fuzzer.git@<sha>`) so the case set only changes when you choose to upgrade.

## Python API

The CLI is a thin wrapper around a small async API:

```python
import asyncio

from a2afuzz import FuzzRunner, write_reports


async def main() -> None:
    runner = FuzzRunner(protocol="a2a", concurrency=4, rate=10, timeout=10)
    result = await runner.run("http://127.0.0.1:9999/", only=["a2a-trust"])
    for case in result.cases:
        for finding in case.findings:
            print(case.case.id, finding.severity, finding.message)
    write_reports(result, "reports")


asyncio.run(main())
```

`FuzzRunner.run()` raises `TargetAuthorizationError` before any network I/O if the URL is malformed or non-local without `authorized=True`. You can pass your own `transport` object (anything with `async send(url, body) -> TransportResponse`) to test non-HTTP transports or to unit-test your own oracles.

## Limitations

- Supports JSON-RPC over HTTP `POST` with a JSON response. Server-sent-event streams (for example A2A `message/stream`), WebSockets, and MCP stdio servers are not exercised.
- MCP Streamable HTTP servers that require an `initialize` handshake, an `Mcp-Session-Id`, or `Accept: text/event-stream` will reject most probes with HTTP 4xx, which counts as a pass. Supply what the server needs with `-H` (user headers replace the defaults) and check the status codes in the JSON report before trusting a clean result.
- Authentication is limited to static headers passed with `-H`.
- The suite is a fixed, reviewable set of probes, not a coverage-guided or mutation fuzzer. A clean run means none of these known mistakes were found, not that the server is bug-free.
- Trust-boundary checks are heuristics. If your server legitimately accepts one of those inputs (for example an operator-only endpoint), triage the finding instead of suppressing the whole category; use `--only` to scope runs.

## Development

```bash
pip install -e ".[dev]"
python -m pytest            # unit, CLI, and end-to-end tests against the demo agent
python -m ruff check .
python -m ruff format --check .
```

Project layout:

```text
a2afuzz/
  cli.py          Typer CLI (run, list, --version)
  generators.py   Deterministic case sets for jsonrpc, a2a, and mcp
  runner.py       Target validation, concurrency, rate limiting
  transport.py    httpx transport with timeouts and capped capture
  checks.py       Response oracles and severity thresholds
  report.py       JSON, HTML, and SARIF writers
  models.py       Dataclasses shared across modules
examples/demo_agent.py   Vulnerable and hardened demo target
tests/                   Unit, CLI, and end-to-end tests
```

CI runs lint and the full test suite on Python 3.10 to 3.14 (plus macOS and Windows), then builds the wheel, installs it into a clean environment, and checks that the hardened demo passes and the vulnerable demo is caught. See [CHANGELOG.md](CHANGELOG.md) for release notes.

## Responsible use

This tool is for builders testing their own services, local and staging deployments, or targets covered by explicit written permission. Do not use it against third-party agents you do not control. Keep the default rate limit unless you own the infrastructure.

## License

MIT © Kirtan Bhatt. See [LICENSE](LICENSE).
