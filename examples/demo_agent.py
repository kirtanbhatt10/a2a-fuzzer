"""A tiny local A2A-style JSON-RPC agent for trying a2a-fuzzer.

Run it in two modes:

    python examples/demo_agent.py            # buggy: has deliberate flaws
    python examples/demo_agent.py --secure   # hardened: handles every case

Then, in another terminal:

    a2afuzz run http://127.0.0.1:9999/ -p a2a

Standard library only. Listens on 127.0.0.1 only.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TASKS: dict = {}
SECURE = False


def err(id_, code, message):
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


def ok(id_, result):
    return {"jsonrpc": "2.0", "id": id_, "result": result}


def handle_message_send(params):
    msg = params["message"]  # buggy mode: KeyError -> 500 + traceback
    if SECURE:
        parts = msg.get("parts")
        if not isinstance(parts, list) or not parts:
            raise ValueError("message.parts must be a non-empty array")
        if msg.get("role") != "user":
            raise ValueError("clients may only send role='user'")
        for p in parts:
            if p.get("kind") not in {"text", "file", "data"}:
                raise ValueError("unknown part kind")
            if p.get("kind") == "file" and "uri" in p.get("file", {}):
                if not str(p["file"]["uri"]).startswith("https://"):
                    raise ValueError("only https file URIs are accepted")
            if p.get("kind") == "file" and "bytes" in p.get("file", {}):
                base64.b64decode(p["file"]["bytes"], validate=True)  # raises ValueError
        task_id = msg.get("taskId")
        if task_id and task_id not in TASKS:
            raise LookupError("unknown task")
    task_id = msg.get("taskId") or str(uuid.uuid4())
    TASKS.setdefault(task_id, {"id": task_id, "status": {"state": "completed"}})
    text = " ".join(p.get("text", "") for p in msg.get("parts", []) if isinstance(p, dict))
    return {"kind": "message", "role": "agent", "messageId": str(uuid.uuid4()),
            "taskId": task_id, "parts": [{"kind": "text", "text": f"echo: {text}"}]}


def handle_tasks_get(params):
    tid = params.get("id")
    if not SECURE and tid == "*":
        return list(TASKS.values())  # buggy: wildcard returns every task
    if tid not in TASKS:
        raise LookupError("task not found")
    return TASKS[tid]


METHODS = {"message/send": handle_message_send, "tasks/get": handle_tasks_get,
           "ping": lambda p: "pong"}


def dispatch(req):
    if not isinstance(req, dict):
        return err(None, -32600, "Invalid Request")
    id_ = req.get("id")
    if SECURE:
        if req.get("jsonrpc") != "2.0" or not isinstance(req.get("method"), str):
            return err(id_ if isinstance(id_, (str, int)) else None, -32600, "Invalid Request")
        if "params" in req and not isinstance(req["params"], (dict, list)):
            return err(id_, -32600, "Invalid Request")
        if not isinstance(id_, (str, int, type(None))):
            return err(None, -32600, "Invalid Request")
    method = req.get("method")
    is_notification = "id" not in req
    fn = METHODS.get(method) if isinstance(method, str) else None
    if fn is None:
        return None if is_notification else err(id_, -32601, "Method not found")
    try:
        result = fn(req.get("params") or {})
    except (ValueError, LookupError, TypeError, AttributeError) as e:
        if SECURE:
            return err(id_, -32602, f"Invalid params: {e}")
        raise
    return None if is_notification else ok(id_, result)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # keep the console quiet
        pass

    def _send(self, status, payload):
        body = b"" if payload is None else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = min(int(self.headers.get("Content-Length") or 0), 4 * 1024 * 1024)
        raw = self.rfile.read(length)
        try:
            try:
                req = json.loads(raw)
            except (ValueError, UnicodeDecodeError):
                return self._send(200, err(None, -32700, "Parse error"))
            if isinstance(req, list):
                if not req:
                    return self._send(200, err(None, -32600, "Invalid Request"))
                out = [r for r in (dispatch(x) for x in req[:100 if SECURE else None]) if r]
                return self._send(200, out or None)
            return self._send(200, dispatch(req))
        except RecursionError:
            if SECURE:
                return self._send(200, err(None, -32600, "Request too deeply nested"))
            return self._send(500, {"error": traceback.format_exc()})
        except Exception:
            if SECURE:
                return self._send(200, err(None, -32603, "Internal error"))
            return self._send(500, {"error": traceback.format_exc()})


def main(argv=None):
    global SECURE
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--secure", action="store_true", help="run the hardened version")
    a = ap.parse_args(argv)
    SECURE = a.secure
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    print(f"demo agent ({'secure' if SECURE else 'buggy'}) on http://127.0.0.1:{a.port}/",
          file=sys.stderr)
    srv.serve_forever()


if __name__ == "__main__":
    main()
