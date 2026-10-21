"""Command-line interface."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .generators import PROTOCOL_GENERATORS, build_cases
from .models import Severity
from .report import write_html, write_json, write_sarif
from .runner import is_local, run

app = typer.Typer(add_completion=False, help="Conformance & robustness fuzzing for A2A / MCP "
                  "JSON-RPC endpoints you own or are authorised to test.")
console = Console()

SEV_STYLE = {"high": "bold red", "medium": "yellow", "low": "cyan", "info": "dim"}


def _parse_headers(values: List[str]) -> dict:
    out = {}
    for v in values:
        if ":" not in v:
            raise typer.BadParameter(f"header must be 'Name: value', got {v!r}")
        k, val = v.split(":", 1)
        out[k.strip()] = val.strip()
    return out


@app.command("run")
def run_cmd(
    url: str = typer.Argument(..., help="JSON-RPC endpoint URL, e.g. http://localhost:9999/"),
    protocol: str = typer.Option("a2a", "--protocol", "-p",
                                 help=f"One of: {', '.join(sorted(PROTOCOL_GENERATORS))}"),
    out: Path = typer.Option(Path("reports"), "--out", "-o", help="Report output directory"),
    concurrency: int = typer.Option(4, help="Parallel requests"),
    rate: float = typer.Option(10.0, help="Max requests per second (0 = unlimited)"),
    timeout: float = typer.Option(10.0, help="Per-request timeout in seconds"),
    header: List[str] = typer.Option([], "--header", "-H", help="Extra header 'Name: value'"),
    only: List[str] = typer.Option([], "--only", help="Run only case-id prefixes or categories"),
    fail_on: Optional[Severity] = typer.Option(
        None, "--fail-on", help="Exit 1 if any finding is at or above this severity (CI)"),
    authorized: bool = typer.Option(
        False, "--i-am-authorized",
        help="Required for non-local targets: confirms you own or may test this endpoint"),
) -> None:
    """Fuzz an endpoint and write JSON, HTML and SARIF reports."""
    if not is_local(url) and not authorized:
        console.print("[bold red]Refusing to run against a non-local target.[/]\n"
                      "Only test endpoints you own or have written permission to test. "
                      "Re-run with [bold]--i-am-authorized[/] to confirm.")
        raise typer.Exit(2)

    console.print(f"[bold]a2a-fuzzer {__version__}[/] → {url} ([cyan]{protocol}[/])")

    def on_result(res):
        mark = "[red]✗[/]" if res.findings else "[green]✓[/]"
        console.print(f"  {mark} {res.case.id}", highlight=False)

    report = asyncio.run(run(url, protocol=protocol, concurrency=concurrency, rate=rate,
                             timeout=timeout, headers=_parse_headers(header),
                             only=only or None, on_result=on_result))

    out.mkdir(parents=True, exist_ok=True)
    write_json(report, out / "a2afuzz.report.json")
    write_html(report, out / "a2afuzz.report.html")
    write_sarif(report, out / "a2afuzz.sarif")

    counts = report.counts()
    t = Table(title="Findings")
    for s in ["high", "medium", "low", "info"]:
        t.add_column(s.upper(), style=SEV_STYLE[s], justify="center")
    t.add_row(*(str(counts[s]) for s in ["high", "medium", "low", "info"]))
    console.print(t)
    console.print(f"Reports written to [bold]{out}/[/]")

    worst = report.max_severity()
    if fail_on and worst and worst.rank >= fail_on.rank:
        raise typer.Exit(1)


@app.command("list")
def list_cmd(protocol: str = typer.Option("a2a", "--protocol", "-p")) -> None:
    """List the test cases for a protocol."""
    t = Table(title=f"{protocol} test cases")
    t.add_column("id")
    t.add_column("category")
    t.add_column("description")
    for c in build_cases(protocol):
        t.add_row(c.id, c.category, c.description)
    console.print(t)


@app.command("version")
def version_cmd() -> None:
    """Print the version."""
    console.print(__version__)


if __name__ == "__main__":
    app()
