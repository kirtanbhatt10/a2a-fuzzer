from __future__ import annotations

import json
import subprocess
import sys

from typer.testing import CliRunner

from a2afuzz import __version__
from a2afuzz.cli import app

runner = CliRunner()


def test_list_command_prints_cases() -> None:
    result = runner.invoke(app, ["list", "-p", "mcp"])
    assert result.exit_code == 0
    assert "mcp-trust-resource-traversal" in result.output


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip() == f"a2afuzz {__version__}"


def test_module_entry_point() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "a2afuzz", "--version"],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == f"a2afuzz {__version__}"


def test_run_refuses_remote_target_without_authorization(tmp_path) -> None:
    result = runner.invoke(app, ["run", "https://example.test/", "-o", str(tmp_path)])
    assert result.exit_code == 2
    assert "Refusing a non-local target" in result.output
    assert not any(tmp_path.iterdir())


def test_run_rejects_only_selector_that_matches_nothing(tmp_path) -> None:
    result = runner.invoke(
        app, ["run", "http://127.0.0.1:9/", "--only", "no-such-case", "-o", str(tmp_path)]
    )
    assert result.exit_code == 2
    assert "no-such-case" in result.output


def test_run_rejects_unknown_protocol_and_threshold(tmp_path) -> None:
    bad_protocol = runner.invoke(app, ["run", "http://127.0.0.1:9/", "-p", "grpc"])
    assert bad_protocol.exit_code == 2
    bad_threshold = runner.invoke(app, ["run", "http://127.0.0.1:9/", "--fail-on", "critical"])
    assert bad_threshold.exit_code == 2


def test_run_against_hardened_agent_passes_fail_on(demo_agent, tmp_path) -> None:
    url = demo_agent(True)
    result = runner.invoke(
        app, ["run", url, "-p", "a2a", "--rate", "0", "--fail-on", "low", "-o", str(tmp_path)]
    )
    assert result.exit_code == 0, result.output
    assert "0 findings" in result.output
    document = json.loads((tmp_path / "a2afuzz.report.json").read_text(encoding="utf-8"))
    assert document["summary"]["findings"] == 0
    assert (tmp_path / "a2afuzz.report.html").is_file()
    assert (tmp_path / "a2afuzz.sarif").is_file()


def test_run_against_vulnerable_agent_fails_fail_on(demo_agent, tmp_path) -> None:
    url = demo_agent(False)
    result = runner.invoke(
        app, ["run", url, "-p", "a2a", "--rate", "0", "--fail-on", "high", "-o", str(tmp_path)]
    )
    assert result.exit_code == 1, result.output
    assert "high=" in result.output


def test_run_without_fail_on_exits_zero_even_with_findings(demo_agent, tmp_path) -> None:
    url = demo_agent(False)
    result = runner.invoke(
        app, ["run", url, "--rate", "0", "--only", "a2a-trust", "-o", str(tmp_path)]
    )
    assert result.exit_code == 0, result.output
    assert "Completed 6 cases" in result.output
