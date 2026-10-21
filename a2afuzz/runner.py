"""Runs a fuzzing session against a single endpoint."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Callable, List, Optional
from urllib.parse import urlparse

from . import __version__
from .checks import evaluate
from .generators import build_cases
from .models import CaseResult, Report, TestCase
from .transport import Transport

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def is_local(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host in LOCAL_HOSTS or host.endswith(".localhost") or host.endswith(".test")


async def run(
    url: str,
    protocol: str = "a2a",
    concurrency: int = 4,
    rate: float = 10.0,
    timeout: float = 10.0,
    headers: Optional[dict] = None,
    only: Optional[List[str]] = None,
    on_result: Optional[Callable[[CaseResult], None]] = None,
) -> Report:
    cases: List[TestCase] = build_cases(protocol)
    if only:
        cases = [c for c in cases if any(c.id.startswith(p) or c.category == p for p in only)]

    transport = Transport(url, timeout=timeout, headers=headers)
    sem = asyncio.Semaphore(max(1, concurrency))
    interval = 1.0 / rate if rate > 0 else 0.0
    lock = asyncio.Lock()
    results: List[CaseResult] = []
    started = datetime.now(timezone.utc).isoformat()

    async def one(case: TestCase) -> None:
        async with sem:
            if interval:
                async with lock:  # global rate limit
                    await asyncio.sleep(interval)
            resp = await transport.send(case)
            res = CaseResult(case=case, response=resp, findings=evaluate(case, resp))
            results.append(res)
            if on_result:
                on_result(res)

    try:
        await asyncio.gather(*(one(c) for c in cases))
    finally:
        await transport.aclose()

    order = {c.id: i for i, c in enumerate(cases)}
    results.sort(key=lambda r: order[r.case.id])
    return Report(
        tool_version=__version__,
        target=url,
        protocol=protocol,
        started_at=started,
        finished_at=datetime.now(timezone.utc).isoformat(),
        total_cases=len(cases),
        results=results,
    )
