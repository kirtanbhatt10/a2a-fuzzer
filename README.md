# a2a-fuzzer

Bounded conformance and robustness fuzzing for agent-to-agent protocols. Point it at an A2A, MCP, or JSON-RPC endpoint you own and it sends a finite set of malformed and edge-case requests. The report highlights crashes, information leaks, validation failures, and trust-boundary mistakes.

> Use only on systems you own or have explicit permission to test. The CLI refuses non-local targets unless `--i-am-authorized` is supplied. Payloads and response captures are capped at 256 KiB; this is robustness testing, not load testing.

## Install

```bash
pip install -e ".[dev]"
```

## Try it locally

```bash
python examples/demo_agent.py &
a2afuzz run http://127.0.0.1:9999/ -p a2a
open reports/a2afuzz.report.html
```

The included target is deliberately vulnerable. Try its hardened mode to see the crash, leak, trust, and validation findings disappear:

```bash
python examples/demo_agent.py --secure --port 9998 &
a2afuzz run http://127.0.0.1:9998/ -p a2a
```

## Usage

```text
a2afuzz run URL [options]
a2afuzz list -p a2a
```

| Option | Default | Description |
| --- | --- | --- |
| `-p, --protocol` | `a2a` | `a2a`, `mcp`, or `jsonrpc` |
| `-o, --out` | `reports/` | Directory for JSON, HTML, and SARIF reports |
| `--concurrency` | `4` | Parallel requests |
| `--rate` | `10` | Maximum requests/second (`0` is unlimited) |
| `--timeout` | `10` | Per-request timeout in seconds |
| `-H, --header` | — | Extra request header; may be repeated |
| `--only` | — | Case-id prefix or category; may be repeated or comma-separated |
| `--fail-on` | — | Exit `1` for findings at or above `info`, `low`, `medium`, or `high` |
| `--i-am-authorized` | off | Required before probing any non-loopback target |

## Checks

The deterministic case suite covers malformed JSON, JSON-RPC envelope and ID errors, reserved/path-like methods, notifications and batches, nesting/string/object limits, and A2A/MCP-specific trust inputs such as role spoofing and unsafe resource URIs.

Responses are evaluated by these oracles:

| Oracle | Typical severity | Detects |
| --- | --- | --- |
| `crash` | high | HTTP 5xx for malformed input |
| `availability` | high / low | Timeouts, dropped connections, slow or oversized responses |
| `info-leak` | medium / high | Stack traces, server paths, credential-like tokens |
| `trust-boundary` | medium | Success results for role, URI, or task-ownership probes |
| `validation` | medium | Success results for malformed input |
| `conformance` | low | Notification responses, non-JSON success bodies, version or ID mismatches |

Each run writes `a2afuzz.report.json`, `a2afuzz.report.html`, and `a2afuzz.sarif` to the output directory. The JSON report preserves non-UTF-8 captures as base64; the HTML report escapes endpoint content before display.

## CI

```yaml
- run: pip install -e ".[dev]"
- run: |
    python -m my_agent --port 8080 &
    sleep 2
    a2afuzz run http://127.0.0.1:8080/ -p a2a --fail-on medium
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: reports/a2afuzz.sarif
```

## Development

```bash
python -m pytest
python -m ruff check .
```

## Responsible use

This tool is for builders testing their own services, local and staging deployments, or targets covered by explicit written permission. Do not use it against third-party agents you do not control.

## License

MIT © Kirtan Bhatt
