from __future__ import annotations

import asyncio
import socket

import httpx

from a2afuzz.transport import AsyncHttpTransport


async def _send_once(transport: AsyncHttpTransport, url: str, body: bytes):
    try:
        return await transport.send(url, body)
    finally:
        await transport.aclose()


def test_http_transport_posts_and_captures_response() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": True})

    transport = AsyncHttpTransport(
        timeout=2, headers={"X-Test": "1"}, http_transport=httpx.MockTransport(handler)
    )
    response = asyncio.run(_send_once(transport, "http://127.0.0.1:9999/", b"{}"))
    assert response.status_code == 200
    assert response.error is None
    assert b'"result":true' in response.body
    assert seen[0].method == "POST"
    assert seen[0].content == b"{}"
    assert seen[0].headers["content-type"] == "application/json"
    assert seen[0].headers["x-test"] == "1"


def test_user_headers_replace_defaults_case_insensitively() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": True})

    transport = AsyncHttpTransport(
        headers={"Accept": "application/json, text/event-stream"},
        http_transport=httpx.MockTransport(handler),
    )
    asyncio.run(_send_once(transport, "http://127.0.0.1:9999/", b"{}"))
    assert seen[0].headers.get_list("accept") == ["application/json, text/event-stream"]


def test_response_capture_is_capped() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 5_000)

    transport = AsyncHttpTransport(
        max_response_bytes=1_024, http_transport=httpx.MockTransport(handler)
    )
    response = asyncio.run(_send_once(transport, "http://127.0.0.1:9999/", b"{}"))
    assert len(response.body) == 1_024
    assert response.body_truncated


def test_protocol_errors_are_recorded_not_raised() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.RemoteProtocolError("peer closed connection", request=request)

    transport = AsyncHttpTransport(http_transport=httpx.MockTransport(handler))
    response = asyncio.run(_send_once(transport, "http://127.0.0.1:9999/", b"{}"))
    assert response.status_code is None
    assert response.error is not None and "RemoteProtocolError" in response.error
    assert not response.timed_out


def test_timeouts_are_flagged() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("too slow", request=request)

    transport = AsyncHttpTransport(http_transport=httpx.MockTransport(handler))
    response = asyncio.run(_send_once(transport, "http://127.0.0.1:9999/", b"{}"))
    assert response.timed_out


def test_connection_refused_is_recorded_not_raised() -> None:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    # The port is now closed, so the connection is refused.
    transport = AsyncHttpTransport(timeout=2)
    response = asyncio.run(_send_once(transport, f"http://127.0.0.1:{port}/", b"{}"))
    assert response.status_code is None
    assert response.error is not None
