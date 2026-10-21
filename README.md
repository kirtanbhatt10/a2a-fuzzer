# a2a-fuzzer

**Conformance and robustness fuzzing for agent-to-agent protocols.**
Point it at your own A2A, MCP or JSON-RPC agent endpoint. It sends a set of bounded, malformed and edge-case requests and reports where your server crashes, leaks internals, skips validation or trusts input it shouldn't.

[![CI](https://github.com/kirtanbhatt10/a2a-fuzzer/actions/workflows/ci.yml/badge.svg)](https://github.com/kirtanbhatt10/a2a-fuzzer/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

> ⚠️ **Use only on systems you own or have written permission to test.** By default the CLI refuses non-local targets unless you pass `--i-am-authorized`.

---

## Why

Agents now talk to other agents through Google's **A2A** protocol and to tools through **MCP**. Both use JSON-RPC 2.0. Most agent servers are written quickly, and the protocol layer is rarely tested against hostile input. Common bugs:

- a malformed request gives a **500 with a full stack trace**
- a client message claiming `role: "agent"` is **accepted as if it came from the agent**
- `tasks/get` with `"*"` **returns other users' tasks**
- a `file://` URI or `../../etc/passwd` is **accepted without question**
- a 2,000-level nested object **hangs or kills the process**

`a2a-fuzzer` finds these before someone else does.

## Install

```bash
pip install git+https://github.com/kirtanbhatt10/a2a-fuzzer
# or, for development
git clone https://github.com/kirtanbhatt10/a2a-fuzzer && cd a2a-fuzzer
pip install -e ".[dev]"
```

## Try it in 30 seconds

The repo ships a small demo agent with deliberate bugs, so you can see real findings straight away.

```bash
python examples/demo_agent.py &            # buggy demo agent on :9999
a2afuzz run http://127.0.0.1:9999/ -p a2a  # fuzz it
open reports/a2afuzz.report.html           # read the report
```

Then run the hardened version and watch the findings disappear:

```bash
python examples/demo_agent.py --secure --port 9998 &
a2afuzz run http://127.0.0.1:9998/ -p a2a
```

## Usage

```bash
a2afuzz run URL [options]
a2afuzz list -p a2a          # show every test case
```

| Option | Default | Meaning |
|---|---|---|
| `-p, --protocol` | `a2a` | `a2a`, `mcp` or `jsonrpc` |
| `-o, --out` | `reports/` | Where to write JSON, HTML and SARIF reports |
| `--concurrency` | `4` | Parallel requests |
| `--rate` | `10` | Max requests per second (`0` = unlimited) |
| `--timeout` | `10` | Per-request timeout, seconds |
| `-H, --header` | – | Extra header, e.g. `-H "Authorization: Bearer $TOKEN"` |
| `--only` | – | Run only case-id prefixes or categories, e.g. `--only a2a-trust` |
| `--fail-on` | – | Exit `1` if any finding is ≥ this severity (for CI) |
| `--i-am-authorized` | off | Required for any non-local target |

## What it checks

**~40 cases per protocol** in these groups:

| Group | Examples |
|---|---|
| Parsing | truncated JSON, empty body, BOM, invalid UTF-8, `NaN`, duplicate keys |
| Envelope | missing/wrong `jsonrpc`, non-string `method`, scalar `params` |
| IDs | object ids, 40-digit ints, 10 KiB strings, RTL/zero-width characters |
| Methods | unknown, reserved `rpc.*`, path-like, `__class__` |
| Notifications & batches | reply to a notification, empty, mixed, 500-item batch |
| Resource limits | 2,000-level nesting, 256 KiB strings, 20,000-key objects |
| **A2A trust** | role spoofing, `system` role, `file://` URIs, foreign `taskId`, wildcard task id |
| **MCP trust** | bad `protocolVersion`, path-traversal `resources/read`, wrong arg types |

Each response is checked by these oracles:

| Oracle | Severity | Flags |
|---|---|---|
| `crash` | high | HTTP 5xx on bad input |
| `availability` | high / low | timeouts, dropped connections, slow responses |
| `info-leak` | medium / high | Python/Node/Java/Go traces, file paths, API-key-like tokens |
| `trust-boundary` | medium | trust-violating input accepted with a success result |
| `validation` | medium | invalid input accepted instead of rejected |
| `conformance` | low / info | wrong error codes, id mismatch, replies to notifications |

All payloads are size-capped (max 256 KiB), so a run tests robustness. It is not a load test.

## Reports

Each run writes three files:

- `a2afuzz.report.json`: every case, its response and its findings
- `a2afuzz.report.html`: a readable, single-file report (supports dark mode)
- `a2afuzz.sarif`: upload to GitHub Code Scanning

## Use in CI

```yaml
- run: pip install git+https://github.com/kirtanbhatt10/a2a-fuzzer
- run: |
    python -m my_agent --port 8080 &
    sleep 2
    a2afuzz run http://127.0.0.1:8080/ -p a2a --fail-on medium
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: reports/a2afuzz.sarif
```

## Architecture

```
a2afuzz/
├── generators.py  # bounded test cases: JSON-RPC envelope + A2A + MCP
├── transport.py   # async HTTP JSON-RPC client (httpx), capped response capture
├── checks.py      # oracles that turn responses into findings
├── runner.py      # concurrency, rate limiting, local-target guard
├── report.py      # JSON / HTML / SARIF writers
└── cli.py         # Typer CLI
examples/demo_agent.py  # stdlib-only target with a buggy and a --secure mode
```

## Roadmap

- [ ] SSE / streaming (`message/stream`, MCP Streamable HTTP)
- [ ] Agent Card (`/.well-known/agent-card.json`) schema and signature checks
- [ ] MCP stdio transport
- [ ] Stateful sequences (create task → hijack from second client)
- [ ] Coverage-guided mutation mode
- [ ] Plugin API for custom cases and oracles

Contributions welcome. Please open an issue first for larger changes.

## Responsible use

This is a testing tool for builders. Run it against your own services, local and staging environments, or targets where you have explicit written permission. Do not use it against third-party agents you don't control.

## License

MIT © Kirtan Bhatt
