"""HTTP transport for JSON-RPC style agent endpoints."""

from __future__ import annotations

import json
import time
from typing import Dict, Optional

import httpx

from .models import Response, TestCase

MAX_BODY_CAPTURE = 64 * 1024  # never keep more than 64 KiB of any response


class Transport:
    def __init__(
        self,
        url: str,
        timeout: float = 10.0,
        headers: Optional[Dict[str, str]] = None,
        verify_tls: bool = True,
    ) -> None:
        self.url = url
        self.timeout = timeout
        self.base_headers = {"Content-Type": "application/json", **(headers or {})}
        self._client = httpx.AsyncClient(timeout=timeout, verify=verify_tls)

    async def send(self, case: TestCase) -> Response:
        headers = {**self.base_headers, **case.headers}
        content = case.raw if case.raw is not None else json.dumps(case.body).encode()
        start = time.perf_counter()
        try:
            r = await self._client.post(self.url, content=content, headers=headers)
        except httpx.TimeoutException:
            return Response(
                elapsed_ms=(time.perf_counter() - start) * 1000,
                transport_error="timeout",
            )
        except httpx.HTTPError as e:
            return Response(
                elapsed_ms=(time.perf_counter() - start) * 1000,
                transport_error=f"{type(e).__name__}: {e}",
            )
        elapsed = (time.perf_counter() - start) * 1000
        text = r.text[:MAX_BODY_CAPTURE]
        try:
            body = r.json() if r.content else None
        except ValueError:
            body = None
        return Response(
            status=r.status_code,
            headers={k.lower(): v for k, v in r.headers.items()},
            text=text,
            json_body=body,
            elapsed_ms=elapsed,
        )

    async def get(self, url: str) -> Response:
        start = time.perf_counter()
        try:
            r = await self._client.get(url)
        except httpx.HTTPError as e:
            return Response(transport_error=f"{type(e).__name__}: {e}")
        try:
            body = r.json()
        except ValueError:
            body = None
        return Response(
            status=r.status_code,
            text=r.text[:MAX_BODY_CAPTURE],
            json_body=body,
            elapsed_ms=(time.perf_counter() - start) * 1000,
        )

    async def aclose(self) -> None:
        await self._client.aclose()
