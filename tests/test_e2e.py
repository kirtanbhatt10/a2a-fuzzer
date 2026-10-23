"""End-to-end: real HTTP runs against the bundled demo agent in both modes."""

from __future__ import annotations

import asyncio
import json

import pytest

from a2afuzz.generators import generate_cases
from a2afuzz.report import write_reports
from a2afuzz.runner import FuzzRunner


@pytest.mark.parametrize("protocol", ["a2a", "mcp", "jsonrpc"])
def test_hardened_agent_produces_no_findings(demo_agent, protocol: str) -> None:
    url = demo_agent(True)
    result = asyncio.run(FuzzRunner(protocol=protocol, rate=0, concurrency=8).run(url))
    assert result.cases
    assert all(case.response.status_code in (200, 204) for case in result.cases)
    assert result.findings == [], [
        f"{case.case.id}: {finding.message}" for case in result.cases for finding in case.findings
    ]


def test_vulnerable_agent_is_caught_and_reported(demo_agent, tmp_path) -> None:
    url = demo_agent(False)
    result = asyncio.run(FuzzRunner(protocol="a2a", rate=0, concurrency=8).run(url))

    oracles = {finding.oracle for finding in result.findings}
    assert {"crash", "info-leak", "validation", "trust-boundary", "conformance"} <= oracles
    flagged = {case.case.id for case in result.cases if case.findings}
    # limits-nesting-2000 is deliberately not asserted: whether the demo's stdlib
    # json parser crashes on deep nesting depends on the Python version.
    assert {
        "json-parse-truncated",
        "batch-mixed",
        "a2a-trust-agent-role",
        "a2a-trust-file-uri",
        "notification-replied",
    } <= flagged

    paths = write_reports(result, tmp_path)
    document = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert document["target"] == url
    assert document["summary"]["cases"] == len(result.cases)
    assert document["summary"]["bySeverity"]["high"] > 0
    sarif = json.loads(paths["sarif"].read_text(encoding="utf-8"))
    assert sarif["runs"][0]["results"]
    html_report = paths["html"].read_text(encoding="utf-8")
    assert "a2a-trust-agent-role" in html_report
    # Endpoint content is escaped, never injected into the report markup.
    assert "<script" not in html_report.lower()


def test_results_keep_generator_order_under_concurrency(demo_agent) -> None:
    url = demo_agent(True)
    result = asyncio.run(FuzzRunner(protocol="a2a", rate=0, concurrency=16).run(url))
    assert [case.case.id for case in result.cases] == [case.id for case in generate_cases("a2a")]
