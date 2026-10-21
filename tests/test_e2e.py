"""End-to-end: run the fuzzer against the bundled demo agent in both modes."""

import json
import socket
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

import examples.demo_agent as demo
from a2afuzz.report import write_html, write_json, write_sarif
from a2afuzz.runner import run


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def server(request):
    demo.SECURE = request.param
    demo.TASKS.clear()
    port = _free_port()
    srv = ThreadingHTTPServer(("127.0.0.1", port), demo.Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}/"
    srv.shutdown()
    demo.SECURE = False


@pytest.mark.parametrize("server", [False], indirect=True)
async def test_buggy_agent_has_findings(server, tmp_path: Path):
    report = await run(server, protocol="a2a", rate=0, concurrency=8)
    checks = {f.check for f in report.findings}
    assert "crash" in checks
    assert "info-leak" in checks
    assert "trust-boundary" in checks
    assert report.counts()["high"] > 0

    write_json(report, tmp_path / "r.json")
    write_html(report, tmp_path / "r.html")
    write_sarif(report, tmp_path / "r.sarif")
    assert json.loads((tmp_path / "r.json").read_text())["summary"]["high"] > 0
    assert "a2a-fuzzer report" in (tmp_path / "r.html").read_text()
    assert json.loads((tmp_path / "r.sarif").read_text())["version"] == "2.1.0"


@pytest.mark.parametrize("server", [True], indirect=True)
async def test_secure_agent_has_no_high_or_medium(server):
    report = await run(server, protocol="a2a", rate=0, concurrency=8)
    bad = [f for f in report.findings if f.severity.value in ("high", "medium")]
    assert bad == [], [f"{f.case_id}: {f.title}" for f in bad]
