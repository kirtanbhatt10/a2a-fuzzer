from __future__ import annotations

import asyncio

import httpx

from a2afuzz.transport import AsyncHttpTransport


def test_http_transport_posts_and_captures_response() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": True})

    transport = AsyncHttpTransport(timeout=2, http_transport=httpx.MockTransport(handler))
    try:
        response = asyncio.run(transport.send("http://127.0.0.1:9999/", b"{}"))
    finally:
        asyncio.run(transport.aclose())
    assert response.status_code == 200
    assert response.error is None
    assert b'"result":true' in response.body
    assert seen[0].method == "POST"
    assert seen[0].content == b"{}"
