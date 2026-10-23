from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import pytest

from a2afuzz.models import TransportResponse
from a2afuzz.runner import FuzzRunner, TargetAuthorizationError, is_local_target, validate_target


@dataclass
class SuccessTransport:
    calls: list[bytes] = field(default_factory=list)

    async def send(self, _url: str, body: bytes) -> TransportResponse:
        self.calls.append(body)
        return TransportResponse(status_code=200, body=b'{"jsonrpc":"2.0","id":1,"result":{}}')


def test_target_guard_only_allows_loopback_without_opt_in() -> None:
    assert is_local_target("http://127.0.0.1:8080/")
    assert is_local_target("https://localhost/service")
    assert is_local_target("http://[::1]:9000/")
    assert not is_local_target("https://example.test/")
    with pytest.raises(TargetAuthorizationError):
        validate_target("https://example.test/", authorized=False)
    validate_target("https://example.test/", authorized=True)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:99999/",
        "http://127.0.0.1:port/",
        "ftp://127.0.0.1/",
        "127.0.0.1:8080",
        "http:///no-host",
    ],
)
def test_malformed_targets_are_rejected_before_any_request(url: str) -> None:
    transport = SuccessTransport()
    runner = FuzzRunner(transport=transport, rate=0)
    with pytest.raises(TargetAuthorizationError):
        asyncio.run(runner.run(url, authorized=True))
    assert transport.calls == []


def test_runner_rejects_invalid_settings() -> None:
    for kwargs in ({"concurrency": 0}, {"rate": -1}, {"timeout": 0}):
        with pytest.raises(ValueError):
            FuzzRunner(**kwargs)


def test_run_timestamps_are_timezone_aware() -> None:
    runner = FuzzRunner(protocol="jsonrpc", transport=SuccessTransport(), rate=0)
    result = asyncio.run(runner.run("http://127.0.0.1:9000/", only=["method-unknown"]))
    assert result.started_at.endswith("+00:00")
    assert result.finished_at.endswith("+00:00")


def test_runner_filters_cases_and_runs_with_injected_transport() -> None:
    transport = SuccessTransport()
    runner = FuzzRunner(protocol="a2a", transport=transport, concurrency=2, rate=0)
    result = asyncio.run(runner.run("http://127.0.0.1:9000/", only=["a2a-trust-agent-role"]))
    assert len(result.cases) == 1
    assert len(transport.calls) == 1
    assert any(finding.oracle == "trust-boundary" for finding in result.findings)
