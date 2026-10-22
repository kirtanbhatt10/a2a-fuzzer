from __future__ import annotations

from typer.testing import CliRunner

from a2afuzz.cli import app


def test_list_command_prints_cases() -> None:
    result = CliRunner().invoke(app, ["list", "-p", "mcp"])
    assert result.exit_code == 0
    assert "mcp-trust-resource-traversal" in result.output


def test_run_refuses_remote_target_without_authorization(tmp_path) -> None:
    result = CliRunner().invoke(app, ["run", "https://example.test/", "-o", str(tmp_path)])
    assert result.exit_code == 2
    assert "Refusing a non-local target" in result.output
