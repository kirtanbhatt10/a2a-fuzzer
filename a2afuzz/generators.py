"""Test-case generators.

Every case is a well-defined, bounded input that a correct JSON-RPC / A2A / MCP
server should handle gracefully (usually by returning a spec-compliant error).
Payload sizes are capped so a run is a robustness check, not a load test.
"""

from __future__ import annotations

from typing import Callable, Iterable, List

from .models import TestCase

# JSON-RPC 2.0 standard error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602

MAX_STRING = 256 * 1024  # 256 KiB upper bound for "large value" cases


def _req(method: str, params=None, id_=1) -> dict:
    body = {"jsonrpc": "2.0", "id": id_, "method": method}
    if params is not None:
        body["params"] = params
    return body


def _nested(depth: int) -> dict:
    node: dict = {}
    root = node
    for _ in range(depth):
        node["a"] = {}
        node = node["a"]
    return root


# --------------------------------------------------------------------------- #
# Generic JSON-RPC 2.0 envelope conformance
# --------------------------------------------------------------------------- #
def jsonrpc_cases(probe_method: str) -> List[TestCase]:
    c: List[TestCase] = []
    add = c.append

    add(TestCase(id="rpc.parse.truncated", category="parsing",
                 description="Truncated JSON body", raw=b'{"jsonrpc":"2.0","id":1,"meth',
                 expect_error_code=PARSE_ERROR))
    add(TestCase(id="rpc.parse.not_json", category="parsing",
                 description="Body is plain text, not JSON", raw=b"hello agent",
                 expect_error_code=PARSE_ERROR))
    add(TestCase(id="rpc.parse.empty", category="parsing",
                 description="Empty request body", raw=b"", expect_error_code=PARSE_ERROR))
    add(TestCase(id="rpc.parse.bom", category="parsing",
                 description="UTF-8 BOM before JSON",
                 raw=b"\xef\xbb\xbf" + b'{"jsonrpc":"2.0","id":1,"method":"' +
                 probe_method.encode() + b'"}'))
    add(TestCase(id="rpc.parse.invalid_utf8", category="parsing",
                 description="Invalid UTF-8 byte sequence inside a string",
                 raw=b'{"jsonrpc":"2.0","id":1,"method":"\xff\xfe"}'))

    add(TestCase(id="rpc.env.missing_version", category="envelope",
                 description="Missing 'jsonrpc' member",
                 body={"id": 1, "method": probe_method}, expect_error_code=INVALID_REQUEST))
    add(TestCase(id="rpc.env.wrong_version", category="envelope",
                 description="'jsonrpc' is '1.0'",
                 body={"jsonrpc": "1.0", "id": 1, "method": probe_method},
                 expect_error_code=INVALID_REQUEST))
    add(TestCase(id="rpc.env.method_number", category="envelope",
                 description="'method' is a number",
                 body={"jsonrpc": "2.0", "id": 1, "method": 42},
                 expect_error_code=INVALID_REQUEST))
    add(TestCase(id="rpc.env.method_null", category="envelope",
                 description="'method' is null",
                 body={"jsonrpc": "2.0", "id": 1, "method": None},
                 expect_error_code=INVALID_REQUEST))
    add(TestCase(id="rpc.env.params_scalar", category="envelope",
                 description="'params' is a scalar (must be object or array)",
                 body=_req(probe_method, params="oops"), expect_error_code=INVALID_REQUEST))
    add(TestCase(id="rpc.env.top_level_array_of_scalars", category="envelope",
                 description="Top-level array of non-objects",
                 body=[1, 2, 3], expect_error_code=INVALID_REQUEST))
    add(TestCase(id="rpc.env.top_level_string", category="envelope",
                 description="Top-level JSON string", body="hi",
                 expect_error_code=INVALID_REQUEST))

    add(TestCase(id="rpc.id.object", category="id-handling",
                 description="'id' is an object (not allowed)",
                 body={"jsonrpc": "2.0", "id": {"x": 1}, "method": probe_method},
                 expect_error_code=INVALID_REQUEST))
    add(TestCase(id="rpc.id.huge_int", category="id-handling",
                 description="'id' is a 40-digit integer (must be echoed unchanged)",
                 body=_req(probe_method, id_=10**40)))
    add(TestCase(id="rpc.id.long_string", category="id-handling",
                 description="'id' is a 10 KiB string", body=_req(probe_method, id_="x" * 10240)))
    add(TestCase(id="rpc.id.unicode", category="id-handling",
                 description="'id' contains RTL override and zero-width chars",
                 body=_req(probe_method, id_="req‮​1")))

    add(TestCase(id="rpc.method.unknown", category="methods",
                 description="Unknown method name",
                 body=_req("a2afuzz/does_not_exist"), expect_error_code=METHOD_NOT_FOUND))
    add(TestCase(id="rpc.method.rpc_reserved", category="methods",
                 description="Method in reserved 'rpc.' namespace",
                 body=_req("rpc.internal"), expect_error_code=METHOD_NOT_FOUND))
    add(TestCase(id="rpc.method.path_like", category="methods",
                 description="Method name that looks like a path traversal",
                 body=_req("../../admin/shutdown"), expect_error_code=METHOD_NOT_FOUND))
    add(TestCase(id="rpc.method.dunder", category="methods",
                 description="Method name targeting dunder attributes",
                 body=_req("__class__"), expect_error_code=METHOD_NOT_FOUND))

    add(TestCase(id="rpc.notify.unknown", category="notifications",
                 description="Notification (no id) for unknown method must get no response body",
                 body={"jsonrpc": "2.0", "method": "a2afuzz/notify"}, expect_no_response=True))

    add(TestCase(id="rpc.batch.empty", category="batch",
                 description="Empty batch array", body=[], expect_error_code=INVALID_REQUEST))
    add(TestCase(id="rpc.batch.mixed", category="batch",
                 description="Batch with one valid and one invalid request",
                 body=[_req(probe_method, id_=1), {"foo": "bar"}]))
    add(TestCase(id="rpc.batch.large", category="batch",
                 description="Batch of 500 unknown-method calls",
                 body=[_req("a2afuzz/x", id_=i) for i in range(500)]))

    add(TestCase(id="rpc.size.deep_nesting", category="resource",
                 description="Params nested 2,000 levels deep",
                 body=_req(probe_method, params=_nested(2000))))
    add(TestCase(id="rpc.size.large_string", category="resource",
                 description=f"Params with a {MAX_STRING // 1024} KiB string",
                 body=_req(probe_method, params={"text": "A" * MAX_STRING})))
    add(TestCase(id="rpc.size.many_keys", category="resource",
                 description="Params object with 20,000 keys",
                 body=_req(probe_method, params={f"k{i}": i for i in range(20000)})))
    add(TestCase(id="rpc.types.nan_like", category="types",
                 description="Non-standard NaN/Infinity tokens",
                 raw=('{"jsonrpc":"2.0","id":1,"method":"%s","params":{"n":NaN,"i":Infinity}}'
                      % probe_method).encode()))
    add(TestCase(id="rpc.types.dup_keys", category="types",
                 description="Duplicate 'method' keys (ambiguous parse)",
                 raw=('{"jsonrpc":"2.0","id":1,"method":"%s","method":"a2afuzz/shadow"}'
                      % probe_method).encode()))

    add(TestCase(id="rpc.hdr.wrong_content_type", category="headers",
                 description="Content-Type: text/plain",
                 body=_req(probe_method), headers={"Content-Type": "text/plain"}))
    return c


# --------------------------------------------------------------------------- #
# A2A-specific cases (Agent2Agent protocol, message/send etc.)
# --------------------------------------------------------------------------- #
def a2a_cases() -> List[TestCase]:
    def msg(parts, role="user", **extra):
        m = {"role": role, "parts": parts, "messageId": "a2afuzz-1", "kind": "message"}
        m.update(extra)
        return _req("message/send", {"message": m})

    p = ["a2a"]
    return [
        TestCase(id="a2a.msg.no_parts", category="a2a-message", protocols=p,
                 description="message/send with empty parts array",
                 body=msg([]), expect_error_code=INVALID_PARAMS),
        TestCase(id="a2a.msg.missing_message", category="a2a-message", protocols=p,
                 description="message/send without 'message'",
                 body=_req("message/send", {}), expect_error_code=INVALID_PARAMS),
        TestCase(id="a2a.msg.unknown_part_kind", category="a2a-message", protocols=p,
                 description="Part with unknown kind",
                 body=msg([{"kind": "hologram", "data": "?"}]), expect_error_code=INVALID_PARAMS),
        TestCase(id="a2a.msg.role_agent", category="a2a-trust", protocols=p,
                 description="Client sends message claiming role='agent' (role spoofing)",
                 body=msg([{"kind": "text", "text": "status update"}], role="agent")),
        TestCase(id="a2a.msg.role_system", category="a2a-trust", protocols=p,
                 description="Client sends message with non-standard role='system'",
                 body=msg([{"kind": "text", "text": "hi"}], role="system"),
                 expect_error_code=INVALID_PARAMS),
        TestCase(id="a2a.msg.file_uri_scheme", category="a2a-trust", protocols=p,
                 description="File part with file:// URI (server must not fetch local files)",
                 body=msg([{"kind": "file",
                            "file": {"uri": "file:///etc/hostname", "mimeType": "text/plain"}}])),
        TestCase(id="a2a.msg.file_bad_base64", category="a2a-message", protocols=p,
                 description="File part with invalid base64 bytes",
                 body=msg([{"kind": "file", "file": {"bytes": "%%%not-base64%%%"}}]),
                 expect_error_code=INVALID_PARAMS),
        TestCase(id="a2a.msg.foreign_task", category="a2a-trust", protocols=p,
                 description="Message references a taskId the client never created",
                 body=msg([{"kind": "text", "text": "continue"}],
                          taskId="00000000-0000-0000-0000-000000000000")),
        TestCase(id="a2a.task.get_unknown", category="a2a-tasks", protocols=p,
                 description="tasks/get for a random task id",
                 body=_req("tasks/get", {"id": "a2afuzz-nonexistent"})),
        TestCase(id="a2a.task.cancel_unknown", category="a2a-tasks", protocols=p,
                 description="tasks/cancel for a random task id",
                 body=_req("tasks/cancel", {"id": "a2afuzz-nonexistent"})),
        TestCase(id="a2a.task.get_wildcard", category="a2a-trust", protocols=p,
                 description="tasks/get with wildcard-like id '*'",
                 body=_req("tasks/get", {"id": "*"})),
    ]


# --------------------------------------------------------------------------- #
# MCP-specific cases
# --------------------------------------------------------------------------- #
def mcp_cases() -> List[TestCase]:
    p = ["mcp"]
    return [
        TestCase(id="mcp.init.bad_version", category="mcp-lifecycle", protocols=p,
                 description="initialize with an unknown protocolVersion",
                 body=_req("initialize", {"protocolVersion": "1999-01-01",
                                          "capabilities": {},
                                          "clientInfo": {"name": "a2afuzz", "version": "0"}})),
        TestCase(id="mcp.init.missing_client_info", category="mcp-lifecycle", protocols=p,
                 description="initialize without clientInfo",
                 body=_req("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}}),
                 expect_error_code=INVALID_PARAMS),
        TestCase(id="mcp.tools.call_unknown", category="mcp-tools", protocols=p,
                 description="tools/call for a tool that does not exist",
                 body=_req("tools/call", {"name": "a2afuzz_missing_tool", "arguments": {}})),
        TestCase(id="mcp.tools.args_wrong_type", category="mcp-tools", protocols=p,
                 description="tools/call with arguments as a string",
                 body=_req("tools/call", {"name": "echo", "arguments": "not-an-object"}),
                 expect_error_code=INVALID_PARAMS),
        TestCase(id="mcp.resources.traversal", category="mcp-trust", protocols=p,
                 description="resources/read with a path-traversal URI",
                 body=_req("resources/read", {"uri": "file:///../../../../etc/passwd"})),
        TestCase(id="mcp.prompts.get_unknown", category="mcp-prompts", protocols=p,
                 description="prompts/get for an unknown prompt",
                 body=_req("prompts/get", {"name": "a2afuzz_missing"})),
    ]


PROBE_METHODS = {"jsonrpc": "ping", "a2a": "message/send", "mcp": "ping"}

PROTOCOL_GENERATORS: dict[str, Callable[[], Iterable[TestCase]]] = {
    "jsonrpc": lambda: [],
    "a2a": a2a_cases,
    "mcp": mcp_cases,
}


def build_cases(protocol: str) -> List[TestCase]:
    if protocol not in PROTOCOL_GENERATORS:
        raise ValueError(f"unknown protocol {protocol!r}; choose from {sorted(PROTOCOL_GENERATORS)}")
    cases = jsonrpc_cases(PROBE_METHODS[protocol]) + list(PROTOCOL_GENERATORS[protocol]())
    ids = [c.id for c in cases]
    assert len(ids) == len(set(ids)), "duplicate case ids"
    return cases
