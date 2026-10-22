from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass

from a2afuzz.models import TransportResponse
from a2afuzz.report import write_reports
from a2afuzz.runner import FuzzRunner


@dataclass
class ErrorTransport:
    async def send(self, _url: str, _body: bytes) -> TransportResponse:
        return TransportResponse(status_code=500, body=b"Traceback (most recent call last): secret")


def test_reports_are_written_in_all_formats(tmp_path) -> None:
    runner = FuzzRunner(protocol="jsonrpc", transport=ErrorTransport(), rate=0)
    result = asyncio.run(runner.run("http://127.0.0.1:9000/", only=["json-parse-empty"]))
    paths = write_reports(result, tmp_path)
    assert all(path.is_file() for path in paths.values())
    document = json.loads(paths["json"].read_text())
    assert document["summary"]["findings"] >= 2
    sarif = json.loads(paths["sarif"].read_text())
    assert sarif["version"] == "2.1.0"
    assert "Traceback" in paths["html"].read_text()
