"""Writers for complete JSON, human-readable HTML, and SARIF run reports."""

from __future__ import annotations

import base64
import html
import json
from collections import Counter
from pathlib import Path
from typing import Any

from .models import CaseResult, Finding, RunResult


def _binary_record(data: bytes) -> dict[str, str]:
    """Keep report captures exact while offering UTF-8 text when available."""

    try:
        return {"encoding": "utf-8", "text": data.decode("utf-8")}
    except UnicodeDecodeError:
        return {"encoding": "base64", "text": base64.b64encode(data).decode("ascii")}


def _finding_record(finding: Finding) -> dict[str, str]:
    return {
        "oracle": finding.oracle,
        "severity": finding.severity,
        "message": finding.message,
        "evidence": finding.evidence,
    }


def _case_record(result: CaseResult) -> dict[str, Any]:
    return {
        "id": result.case.id,
        "category": result.case.category,
        "title": result.case.title,
        "expectation": result.case.expectation,
        "notes": result.case.notes,
        "request": _binary_record(result.case.body),
        "response": {
            "statusCode": result.response.status_code,
            "headers": result.response.headers,
            "body": _binary_record(result.response.body),
            "elapsedMs": round(result.response.elapsed_ms, 2),
            "error": result.response.error,
            "timedOut": result.response.timed_out,
            "bodyTruncated": result.response.body_truncated,
        },
        "findings": [_finding_record(finding) for finding in result.findings],
    }


def to_json_document(run: RunResult) -> dict[str, Any]:
    counts = Counter(finding.severity for finding in run.findings)
    return {
        "schemaVersion": "1.0",
        "tool": {"name": "a2afuzz", "version": "0.1.0"},
        "target": run.target,
        "protocol": run.protocol,
        "startedAt": run.started_at,
        "finishedAt": run.finished_at,
        "summary": {
            "cases": len(run.cases),
            "findings": len(run.findings),
            "bySeverity": {
                severity: counts[severity] for severity in ("high", "medium", "low", "info")
            },
        },
        "cases": [_case_record(case) for case in run.cases],
    }


def _html_case(result: CaseResult) -> str:
    findings = result.findings
    status = (
        "pass"
        if not findings
        else max(
            findings, key=lambda item: {"info": 0, "low": 1, "medium": 2, "high": 3}[item.severity]
        ).severity
    )
    finding_html = '<p class="none">No findings</p>'
    if findings:
        finding_html = "".join(
            '<li><span class="badge {severity}">{severity}</span> <b>{oracle}</b>: {message}'
            "{evidence}</li>".format(
                severity=html.escape(finding.severity),
                oracle=html.escape(finding.oracle),
                message=html.escape(finding.message),
                evidence=(
                    f"<pre>{html.escape(finding.evidence)}</pre>" if finding.evidence else ""
                ),
            )
            for finding in findings
        )
        finding_html = f"<ul>{finding_html}</ul>"
    response_label = result.response.error or (
        f"HTTP {result.response.status_code}"
        if result.response.status_code is not None
        else "No response"
    )
    return (
        f'<article class="case {html.escape(status)}">'
        f'<div class="case-title"><code>{html.escape(result.case.id)}</code>'
        f"<span>{html.escape(result.case.category)} · {html.escape(result.case.title)}</span></div>"
        f'<div class="meta">{html.escape(response_label)} · {result.response.elapsed_ms:.0f} ms · '
        f"{result.case.payload_size:,} byte request</div>{finding_html}</article>"
    )


def to_html_document(run: RunResult) -> str:
    counts = Counter(finding.severity for finding in run.findings)
    cards = "".join(
        f'<div class="summary-card {severity}">'
        f"<b>{counts[severity]}</b><span>{severity}</span></div>"
        for severity in ("high", "medium", "low", "info")
    )
    cases = "".join(_html_case(result) for result in run.cases)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>a2afuzz report</title>
  <style>
    :root{{
      color-scheme:light dark;
      --bg:#f6f8fa;--card:#fff;--fg:#1f2328;--muted:#57606a;--line:#d0d7de
    }}
    @media (prefers-color-scheme:dark){{
      :root{{--bg:#0d1117;--card:#161b22;--fg:#e6edf3;--muted:#8b949e;--line:#30363d}}
    }}
    *{{box-sizing:border-box}}
    body{{
      margin:0;background:var(--bg);color:var(--fg);
      font:15px/1.5 ui-sans-serif,system-ui,sans-serif
    }}
    main{{max-width:1050px;margin:auto;padding:32px 20px 60px}}
    h1{{margin:0 0 4px}}
    .muted,.meta{{color:var(--muted)}}
    .summary{{display:flex;gap:12px;flex-wrap:wrap;margin:24px 0}}
    .summary-card{{
      background:var(--card);border:1px solid var(--line);border-radius:8px;
      padding:12px 24px;min-width:105px
    }}
    .summary-card b{{display:block;font-size:28px}}
    .summary-card span{{text-transform:capitalize;color:var(--muted)}}
    .case{{
      background:var(--card);border:1px solid var(--line);border-left:5px solid var(--line);
      border-radius:8px;margin:10px 0;padding:16px
    }}
    .case.high{{border-left-color:#cf222e}}
    .case.medium{{border-left-color:#bf8700}}
    .case.low{{border-left-color:#0969da}}
    .case-title{{display:flex;gap:12px;align-items:baseline;flex-wrap:wrap}}
    code{{font-weight:650}}
    .meta{{margin-top:5px;font-size:13px}}
    ul{{padding-left:20px;margin-bottom:0}}
    li{{margin:7px 0}}
    pre{{
      white-space:pre-wrap;word-break:break-word;
      background:color-mix(in srgb,var(--bg) 85%,transparent);
      padding:8px;border-radius:4px;margin:5px 0 0
    }}
    .badge{{border-radius:99px;padding:2px 7px;font-size:12px;color:white;background:#57606a}}
    .badge.high{{background:#cf222e}}
    .badge.medium{{background:#9a6700}}
    .badge.low{{background:#0969da}}
    .none{{margin:10px 0 0;color:var(--muted)}}
  </style>
</head>
<body><main><h1>a2afuzz report</h1>
<p class="muted">
  {html.escape(run.protocol.upper())} · {html.escape(run.target)} · {html.escape(run.started_at)}
</p>
<p>{len(run.cases)} cases · <b>{len(run.findings)} findings</b></p>
<section class="summary">{cards}</section>
<section>{cases}</section>
</main></body></html>"""


def to_sarif_document(run: RunResult) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    levels = {"high": "error", "medium": "warning", "low": "note", "info": "note"}
    for case in run.cases:
        for finding in case.findings:
            rule_id = f"a2afuzz/{finding.oracle}"
            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "shortDescription": {"text": finding.oracle.replace("-", " ").title()},
                    "helpUri": "https://github.com/kirtanbhatt10/a2a-fuzzer",
                },
            )
            results.append(
                {
                    "ruleId": rule_id,
                    "level": levels[finding.severity],
                    "message": {"text": f"{case.case.id}: {finding.message}"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": run.target}}}],
                    "properties": {
                        "severity": finding.severity,
                        "caseId": case.case.id,
                        "category": case.case.category,
                        "evidence": finding.evidence,
                    },
                }
            )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {"name": "a2afuzz", "version": "0.1.0", "rules": list(rules.values())}
                },
                "results": results,
            }
        ],
    }


def write_reports(run: RunResult, out_dir: str | Path) -> dict[str, Path]:
    """Write all report formats and return their paths."""

    output = Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": output / "a2afuzz.report.json",
        "html": output / "a2afuzz.report.html",
        "sarif": output / "a2afuzz.sarif",
    }
    paths["json"].write_text(
        json.dumps(to_json_document(run), indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    paths["html"].write_text(to_html_document(run), encoding="utf-8")
    paths["sarif"].write_text(json.dumps(to_sarif_document(run), indent=2) + "\n", encoding="utf-8")
    return paths
