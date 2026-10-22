#!/usr/bin/env python3
"""A stdlib-only A2A-like demo endpoint for trying a2afuzz locally.

The default mode deliberately contains flaws. ``--secure`` demonstrates the
kind of parser, envelope, size, and trust-boundary controls a service needs.
It is a teaching target, not a production A2A implementation.
"""

from __future__ import annotations

import argparse
import json
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class ProtocolError(ValueError):
    pass


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError(f"duplicate member: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ProtocolError(f"non-standard JSON constant: {value}")


def _strict_json(raw: bytes) -> Any:
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ProtocolError("body is not UTF-8") from exc
    if not text:
        raise ProtocolError("empty body")
    try:
        return json.loads(
            text, object_pairs_hook=_no_duplicate_keys, parse_constant=_reject_constant
        )
    except (json.JSONDecodeError, RecursionError, ProtocolError) as exc:
        raise ProtocolError("invalid JSON") from exc


def _within_limits(value: Any) -> bool:
    """Iteratively enforce conservative limits without recursive walking."""

    pending: list[tuple[Any, int]] = [(value, 1)]
    seen = 0
    while pending:
        current, depth = pending.pop()
        seen += 1
        if seen > 25_000 or depth > 64:
            return False
        if isinstance(current, str) and len(current) > 8_192:
            return False
        if isinstance(current, dict):
            if len(current) > 1_000:
                return False
            pending.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            if len(current) > 1_000:
                return False
            pending.extend((item, depth + 1) for item in current)
    return True


def _is_valid_id(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return False
    if isinstance(value, str):
        return len(value) <= 128 and value.isascii() and value.isprintable()
    return abs(value) <= (2**53 - 1)


def _unsafe_trust_input(params: dict[str, Any]) -> bool:
    pending: list[Any] = [params]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            role = current.get("role")
            if role in {"agent", "system"}:
                return True
            task_id = current.get("taskId")
            if isinstance(task_id, str) and (task_id == "*" or task_id.startswith("other-")):
                return True
            for key in ("uri", "fileUri"):
                uri = current.get(key)
                if isinstance(uri, str) and (uri.lower().startswith("file:") or ".." in uri):
                    return True
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)
    return False


class DemoHandler(BaseHTTPRequestHandler):
    server: DemoServer
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _write_json(self, status: int, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _write_plain(self, status: int, text: str) -> None:
        encoded = text.encode("utf-8", errors="replace")
        self.send_response(status)
        self.send_header("content-type", "text/plain; charset=utf-8")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _no_content(self) -> None:
        self.send_response(204)
        self.send_header("content-length", "0")
        self.end_headers()

    def _error(
        self, identifier: str | int | float | None, message: str, code: int = -32600
    ) -> None:
        self._write_json(
            200, {"jsonrpc": "2.0", "id": identifier, "error": {"code": code, "message": message}}
        )

    def do_POST(self) -> None:  # noqa: N802 - mandated by BaseHTTPRequestHandler
        try:
            length = int(self.headers.get("content-length", "0"))
        except ValueError:
            length = 0
        raw = self.rfile.read(min(max(length, 0), 300 * 1024 + 1))
        if self.server.secure:
            self._secure(raw)
        else:
            self._insecure(raw)

    def _insecure(self, raw: bytes) -> None:
        """Intentionally buggy: leaks traces and treats every parsed input as trusted."""

        try:
            request = json.loads(raw)
            identifier = request.get("id")
            self._write_json(
                200,
                {"jsonrpc": "2.0", "id": identifier, "result": {"accepted": True, "echo": request}},
            )
        except Exception:
            self._write_plain(500, traceback.format_exc())

    def _secure(self, raw: bytes) -> None:
        if len(raw) > 256 * 1024:
            self._error(None, "request exceeds size limit", -32600)
            return
        try:
            request = _strict_json(raw)
        except ProtocolError:
            self._error(None, "parse error", -32700)
            return
        if not isinstance(request, dict):
            self._error(None, "request must be an object")
            return
        is_notification = "id" not in request
        raw_id = request.get("id")
        identifier = raw_id if _is_valid_id(raw_id) else None
        if request.get("jsonrpc") != "2.0":
            self._error(identifier, "jsonrpc must be 2.0")
            return
        method = request.get("method")
        params = request.get("params", {})
        if (
            not isinstance(method, str)
            or not isinstance(params, dict)
            or not _within_limits(request)
        ):
            self._error(identifier, "invalid request")
            return
        if "id" in request and not _is_valid_id(raw_id):
            self._error(None, "invalid request id")
            return
        if method.startswith("rpc.") or method.startswith("__") or "/" in method or ".." in method:
            self._error(identifier, "method not found", -32601)
            return
        if _unsafe_trust_input(params):
            self._error(identifier, "unsafe client-controlled input")
            return
        if method == "initialize":
            if params.get("protocolVersion") != "2024-11-05" or not isinstance(
                params.get("capabilities"), dict
            ):
                self._error(identifier, "unsupported MCP initialize request")
                return
        elif method == "tools/call":
            if not isinstance(params.get("name"), str) or not isinstance(
                params.get("arguments"), dict
            ):
                self._error(identifier, "invalid tool call")
                return
        elif method == "resources/read":
            if not isinstance(params.get("uri"), str):
                self._error(identifier, "invalid resource request")
                return
        elif method != "ping":
            self._error(identifier, "method not found", -32601)
            return
        if is_notification:
            self._no_content()
            return
        self._write_json(200, {"jsonrpc": "2.0", "id": identifier, "result": {"ok": True}})


class DemoServer(ThreadingHTTPServer):
    secure: bool


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument(
        "--secure", action="store_true", help="enable validation and trust-boundary controls"
    )
    args = parser.parse_args()
    server = DemoServer((args.host, args.port), DemoHandler)
    server.secure = args.secure
    mode = "secure" if args.secure else "insecure"
    print(f"Demo agent listening on http://{args.host}:{args.port}/ ({mode})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
