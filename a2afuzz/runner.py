"""Concurrent execution, rate limiting, and target authorization guard."""

from __future__ import annotations

import asyncio
import ipaddress
import time
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import urlparse

from .checks import evaluate_response
from .generators import Protocol as FuzzProtocol
from .generators import generate_cases, select_cases
from .models import CaseResult, RunResult, TransportResponse
from .transport import AsyncHttpTransport


class TargetAuthorizationError(ValueError):
    """Raised before network I/O when a target needs explicit authorization."""


class Transport(Protocol):
    async def send(self, url: str, body: bytes) -> TransportResponse: ...


def is_local_target(url: str) -> bool:
    """Return true only for loopback hostnames and IP addresses."""

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    host = parsed.hostname.lower().rstrip(".")
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_target(url: str, *, authorized: bool) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise TargetAuthorizationError("Target must be an absolute http:// or https:// URL.")
    if not is_local_target(url) and not authorized:
        raise TargetAuthorizationError(
            "Refusing a non-local target. Confirm authorization with --i-am-authorized."
        )


class _RateLimiter:
    def __init__(self, rate: float) -> None:
        self.interval = 0.0 if rate <= 0 else 1.0 / rate
        self._next_allowed = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if not self.interval:
            return
        async with self._lock:
            now = time.monotonic()
            delay = max(0.0, self._next_allowed - now)
            self._next_allowed = max(now, self._next_allowed) + self.interval
        if delay:
            await asyncio.sleep(delay)


class FuzzRunner:
    """Run a protocol's finite test set against one JSON-RPC HTTP endpoint."""

    def __init__(
        self,
        *,
        protocol: FuzzProtocol = "a2a",
        concurrency: int = 4,
        rate: float = 10.0,
        timeout: float = 10.0,
        headers: Mapping[str, str] | None = None,
        transport: Transport | None = None,
    ) -> None:
        if concurrency < 1:
            raise ValueError("concurrency must be at least 1")
        if rate < 0:
            raise ValueError("rate must be 0 (unlimited) or positive")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.protocol = protocol
        self.concurrency = concurrency
        self.rate = rate
        self.timeout = timeout
        self.headers = dict(headers or {})
        self.transport = transport

    async def run(
        self,
        target: str,
        *,
        authorized: bool = False,
        only: Iterable[str] | None = None,
    ) -> RunResult:
        validate_target(target, authorized=authorized)
        cases = select_cases(generate_cases(self.protocol), only)
        started = datetime.now(UTC)
        semaphore = asyncio.Semaphore(self.concurrency)
        limiter = _RateLimiter(self.rate)
        transport = self.transport or AsyncHttpTransport(timeout=self.timeout, headers=self.headers)
        owns_transport = self.transport is None

        async def execute(case_index: int):
            case = cases[case_index]
            async with semaphore:
                await limiter.acquire()
                response = await transport.send(target, case.body)
            return case_index, CaseResult(
                case=case,
                response=response,
                findings=evaluate_response(
                    case, response, slow_after_ms=self.timeout * 1_000 * 0.8
                ),
            )

        try:
            completed = await asyncio.gather(*(execute(index) for index in range(len(cases))))
        finally:
            if owns_transport:
                await transport.aclose()  # type: ignore[union-attr]
        completed.sort(key=lambda item: item[0])
        finished = datetime.now(UTC)
        return RunResult(
            target=target,
            protocol=self.protocol,
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            cases=[result for _, result in completed],
        )
