"""JSON, HTML and SARIF report writers."""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, select_autoescape

from .models import Report, Severity

HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>a2a-fuzzer report</title>
<style>
:root{--bg:#fff;--fg:#1a1a1a;--muted:#666;--card:#f5f5f4;--b:#e5e5e5;
--high:#c0392b;--medium:#d68910;--low:#2e86c1;--info:#7f8c8d}
@media (prefers-color-scheme:dark){:root{--bg:#141414;--fg:#eee;--muted:#999;--card:#1f1f1f;--b:#333}}
body{font:14px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:24px 16px;max-width:1100px;margin:auto}
h1{font-size:22px;margin:0 0 4px}.muted{color:var(--muted)}
.stats{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}
.stat{background:var(--card);border:1px solid var(--b);border-radius:8px;padding:10px 14px;min-width:90px}
.stat b{display:block;font-size:20px}
table{width:100%;border-collapse:collapse;margin-top:12px}
th,td{text-align:left;padding:8px;border-bottom:1px solid var(--b);vertical-align:top}
.sev{font-weight:600;text-transform:uppercase;font-size:12px}
.high{color:var(--high)}.medium{color:var(--medium)}.low{color:var(--low)}.info{color:var(--info)}
code,pre{font-family:ui-monospace,monospace;font-size:12px}
pre{white-space:pre-wrap;word-break:break-all;background:var(--card);padding:6px;border-radius:4px;margin:4px 0 0}
.wrap{overflow-x:auto}
</style></head><body>
<h1>a2a-fuzzer report</h1>
<div class="muted">Target <code>{{ r.target }}</code> · protocol <b>{{ r.protocol }}</b> ·
{{ r.total_cases }} cases · v{{ r.tool_version }} · {{ r.finished_at }}</div>
<div class="stats">
{% for s in ["high","medium","low","info"] %}
<div class="stat"><span class="sev {{s}}">{{s}}</span><b>{{ counts[s] }}</b></div>
{% endfor %}
</div>
{% if findings %}
<div class="wrap"><table><thead><tr><th>Severity</th><th>Finding</th><th>Case</th></tr></thead><tbody>
{% for f in findings %}
<tr><td class="sev {{ f.severity.value }}">{{ f.severity.value }}</td>
<td><b>{{ f.title }}</b><div class="muted">{{ f.detail }}</div>
{% if f.evidence %}<pre>{{ f.evidence }}</pre>{% endif %}</td>
<td><code>{{ f.case_id }}</code></td></tr>
{% endfor %}
</tbody></table></div>
{% else %}<p>No findings. The endpoint handled every case gracefully.</p>{% endif %}
</body></html>"""


def write_json(report: Report, path: Path) -> None:
    data = report.model_dump(mode="json")
    data["summary"] = report.counts()
    path.write_text(json.dumps(data, indent=2, default=str))


def write_html(report: Report, path: Path) -> None:
    env = Environment(autoescape=select_autoescape(default=True))
    findings = sorted(report.findings, key=lambda f: -f.severity.rank)
    html = env.from_string(HTML_TEMPLATE).render(r=report, counts=report.counts(),
                                                 findings=findings)
    path.write_text(html)


_SARIF_LEVEL = {Severity.HIGH: "error", Severity.MEDIUM: "warning",
                Severity.LOW: "note", Severity.INFO: "note"}


def write_sarif(report: Report, path: Path) -> None:
    rules = {}
    results = []
    for f in report.findings:
        rid = f"{f.check}/{f.title.lower().replace(' ', '-')}"
        rules.setdefault(rid, {"id": rid, "name": f.title,
                               "shortDescription": {"text": f.title},
                               "fullDescription": {"text": f.detail}})
        results.append({
            "ruleId": rid,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f"[{f.case_id}] {f.detail}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": report.target}}}],
        })
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "a2a-fuzzer", "version": report.tool_version,
                                      "informationUri": "https://github.com/kirtanbhatt10/a2a-fuzzer",
                                      "rules": list(rules.values())}},
                  "results": results}],
    }
    path.write_text(json.dumps(sarif, indent=2))
