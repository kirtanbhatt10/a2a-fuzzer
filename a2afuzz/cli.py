"""Typer command line interface for a2afuzz."""

from __future__ import annotations

import asyncio
from collections import Counter
from pathlib import Path
from typing import Annotated

import typer

from ._version import __version__
from .checks import meets_severity
from .generators import generate_cases, select_cases
from .report import write_reports
from .runner import FuzzRunner, TargetAuthorizationError

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Bounded conformance and robustness fuzzing for agent JSON-RPC endpoints.",
)

# Exit codes are part of the CLI contract (see README).
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_INTERRUPTED = 130


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"a2afuzz {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    """Bounded conformance and robustness fuzzing for agent JSON-RPC endpoints."""


def _headers(values: list[str] | None) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for value in values or []:
        if ":" not in value:
            raise typer.BadParameter("headers must use 'Name: value' syntax")
        name, header_value = value.split(":", 1)
        if not name.strip():
            raise typer.BadParameter("header name cannot be empty")
        parsed[name.strip()] = header_value.strip()
    return parsed


def _selectors(values: list[str] | None) -> list[str]:
    return [part.strip() for value in values or [] for part in value.split(",") if part.strip()]


@app.command("list")
def list_cases(
    protocol: Annotated[str, typer.Option("--protocol", "-p", help="a2a, mcp, or jsonrpc")] = "a2a",
) -> None:
    """List the finite probe set without making any network request."""

    if protocol not in {"a2a", "mcp", "jsonrpc"}:
        raise typer.BadParameter("protocol must be a2a, mcp, or jsonrpc")
    for case in generate_cases(protocol):
        typer.echo(f"{case.id:32} {case.category:16} {case.title}")


@app.command()
def run(
    url: Annotated[str, typer.Argument(help="JSON-RPC HTTP endpoint to test")],
    protocol: Annotated[str, typer.Option("--protocol", "-p", help="a2a, mcp, or jsonrpc")] = "a2a",
    out: Annotated[Path, typer.Option("--out", "-o", help="Report directory")] = Path("reports"),
    concurrency: Annotated[int, typer.Option("--concurrency", min=1, help="Parallel requests")] = 4,
    rate: Annotated[
        float, typer.Option("--rate", min=0, help="Requests/second; 0 is unlimited")
    ] = 10.0,
    timeout: Annotated[
        float, typer.Option("--timeout", min=0.1, help="Per-request timeout in seconds")
    ] = 10.0,
    header: Annotated[
        list[str] | None, typer.Option("--header", "-H", help="Extra header: 'Name: value'")
    ] = None,
    only: Annotated[
        list[str] | None,
        typer.Option("--only", help="Case-id prefix or category; repeat or comma-separate"),
    ] = None,
    fail_on: Annotated[
        str | None, typer.Option("--fail-on", help="Exit 1 for info, low, medium, or high findings")
    ] = None,
    i_am_authorized: Annotated[
        bool, typer.Option("--i-am-authorized", help="Confirm authorization for a non-local target")
    ] = False,
) -> None:
    """Run bounded probes and write JSON, HTML, and SARIF reports."""

    if protocol not in {"a2a", "mcp", "jsonrpc"}:
        raise typer.BadParameter("protocol must be a2a, mcp, or jsonrpc")
    if fail_on is not None and fail_on not in {"info", "low", "medium", "high"}:
        raise typer.BadParameter("--fail-on must be info, low, medium, or high")
    selectors = _selectors(only)
    if selectors and not select_cases(generate_cases(protocol), selectors):
        # A typo in --only must not turn into a silently "clean" CI run.
        raise typer.BadParameter(
            f"no {protocol} case matches {', '.join(selectors)}; see 'a2afuzz list -p {protocol}'",
            param_hint="'--only'",
        )
    try:
        runner = FuzzRunner(
            protocol=protocol,
            concurrency=concurrency,
            rate=rate,
            timeout=timeout,
            headers=_headers(header),
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    try:
        result = asyncio.run(runner.run(url, authorized=i_am_authorized, only=selectors))
    except TargetAuthorizationError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=EXIT_USAGE) from exc
    except KeyboardInterrupt as exc:
        typer.echo("Interrupted; no reports were written.", err=True)
        raise typer.Exit(code=EXIT_INTERRUPTED) from exc

    try:
        paths = write_reports(result, out)
    except OSError as exc:
        typer.echo(f"Error: could not write reports to {out}: {exc}", err=True)
        raise typer.Exit(code=EXIT_USAGE) from exc
    counts = Counter(finding.severity for finding in result.findings)
    severity_summary = (
        f"high={counts['high']}, medium={counts['medium']}, "
        f"low={counts['low']}, info={counts['info']}"
    )
    typer.echo(
        f"Completed {len(result.cases)} cases: {len(result.findings)} findings "
        f"({severity_summary})."
    )
    typer.echo("Reports: " + ", ".join(str(path) for path in paths.values()))
    if any(meets_severity(finding, fail_on) for finding in result.findings):
        raise typer.Exit(code=EXIT_FINDINGS)


if __name__ == "__main__":
    app()
