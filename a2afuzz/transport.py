"""Async HTTP transport with request timeouts and bounded response capture."""

from __future__ import annotations

import time
from collections.abc import Mapping

import httpx

from .models import TransportResponse

MAX_RESPONSE_BYTES = 256 * 1024


class AsyncHttpTransport:
    """A reusable HTTP POST transport for JSON-RPC over HTTP endpoints."""

    def __init__(
        self,
        *,
        timeout: float = 10.0,
        headers: Mapping[str, str] | None = None,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
        http_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.timeout = timeout
        self.headers = dict(headers or {})
        self.max_response_bytes = max_response_bytes
        self.http_transport = http_transport
        self._client: httpx.AsyncClient | None = None

    async def open(self) -> None:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                follow_redirects=False,
                transport=self.http_transport,
            )

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def send(self, url: str, body: bytes) -> TransportResponse:
        """POST *body* and return a response record even for connection failures."""

        await self.open()
        assert self._client is not None  # narrows for type checkers
        # httpx.Headers merges case-insensitively, so ``-H "Accept: ..."`` replaces
        # the default instead of sending two Accept headers.
        headers = httpx.Headers({"content-type": "application/json", "accept": "application/json"})
        headers.update(self.headers)
        started = time.perf_counter()
        try:
            async with self._client.stream("POST", url, content=body, headers=headers) as response:
                captured = bytearray()
                truncated = False
                async for chunk in response.aiter_bytes():
                    remaining = self.max_response_bytes - len(captured)
                    if remaining <= 0:
                        truncated = True
                        break
                    captured.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        truncated = True
                        break
                return TransportResponse(
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    body=bytes(captured),
                    elapsed_ms=(time.perf_counter() - started) * 1_000,
                    body_truncated=truncated,
                )
        except httpx.TimeoutException as exc:
            return TransportResponse(
                elapsed_ms=(time.perf_counter() - started) * 1_000,
                error=f"timeout: {exc}",
                timed_out=True,
            )
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            # Connection refused/reset, protocol violations, decoding failures and
            # similar problems are findings about the target, not tool crashes.
            return TransportResponse(
                elapsed_ms=(time.perf_counter() - started) * 1_000,
                error=f"network error: {type(exc).__name__}: {exc}",
            )
