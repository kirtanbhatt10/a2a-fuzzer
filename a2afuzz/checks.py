"""Oracles: turn a (case, response) pair into findings."""

from __future__ import annotations

import re
from typing import Callable, List

from .models import Finding, Response, Severity, TestCase

SLOW_MS = 5000.0

# Signatures that suggest a stack trace or internal detail leaked to the client.
LEAK_PATTERNS = [
    (re.compile(r"Traceback \(most recent call last\)"), "Python traceback"),
    (re.compile(r'File "[^"]+\.py", line \d+'), "Python source path"),
    (re.compile(r"\bat [\w$.<>]+ \([^)]*\.(?:js|ts|mjs):\d+:\d+\)"), "Node.js stack frame"),
    (re.compile(r"\bat [\w.$]+\([\w]+\.java:\d+\)"), "Java stack frame"),
    (re.compile(r"goroutine \d+ \[running\]"), "Go panic"),
    (re.compile(r"(?:/home|/Users|/var/www|C:\\\\Users)[/\\][^\s\"']+"), "filesystem path"),
    (re.compile(r"(?i)\b(?:sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36})"),
     "credential-like token"),
]

Check = Callable[[TestCase, Response], List[Finding]]


def _f(check, sev, title, detail, case, evidence="") -> Finding:
    return Finding(check=check, severity=sev, title=title, detail=detail,
                   case_id=case.id, evidence=evidence[:500])


def check_transport(case: TestCase, r: Response) -> List[Finding]:
    if r.transport_error == "timeout":
        return [_f("availability", Severity.HIGH, "Request timed out",
                   "Server did not answer within the timeout; input may cause a hang.", case)]
    if r.transport_error:
        return [_f("availability", Severity.HIGH, "Connection failed / dropped",
                   "Server closed or reset the connection; input may crash the process.",
                   case, r.transport_error)]
    return []


def check_server_error(case: TestCase, r: Response) -> List[Finding]:
    if r.status is not None and r.status >= 500:
        return [_f("crash", Severity.HIGH, f"HTTP {r.status} on malformed input",
                   "Unhandled exception. JSON-RPC errors should be returned as a JSON body.",
                   case, r.text)]
    return []


def check_leaks(case: TestCase, r: Response) -> List[Finding]:
    out = []
    for pat, label in LEAK_PATTERNS:
        m = pat.search(r.text)
        if m:
            sev = Severity.HIGH if label == "credential-like token" else Severity.MEDIUM
            out.append(_f("info-leak", sev, f"Response leaks {label}",
                          "Internal details in error responses help attackers map the system.",
                          case, m.group(0)))
    return out


def check_slow(case: TestCase, r: Response) -> List[Finding]:
    if r.transport_error is None and r.elapsed_ms > SLOW_MS:
        return [_f("availability", Severity.LOW, "Slow response",
                   f"Took {r.elapsed_ms:.0f} ms; input may be expensive to process.", case)]
    return []


def _first_obj(body):
    if isinstance(body, list):
        return body[0] if body and isinstance(body[0], dict) else None
    return body if isinstance(body, dict) else None


def check_conformance(case: TestCase, r: Response) -> List[Finding]:
    if r.transport_error or (r.status is not None and r.status >= 500):
        return []
    out: List[Finding] = []

    if case.expect_no_response:
        if r.text.strip() and r.json_body not in (None, [], {}):
            out.append(_f("conformance", Severity.LOW, "Notification received a response",
                          "JSON-RPC 2.0: the server MUST NOT reply to notifications.", case,
                          r.text))
        return out

    if r.json_body is None:
        out.append(_f("conformance", Severity.LOW, "Non-JSON response",
                      "Expected a JSON-RPC response object.", case, r.text))
        return out

    obj = _first_obj(r.json_body)
    if obj is None:
        return out

    if obj.get("jsonrpc") != "2.0":
        out.append(_f("conformance", Severity.INFO, "Response missing jsonrpc: '2.0'",
                      "Every response object must include jsonrpc: '2.0'.", case, r.text))

    if case.expect_error_code is not None:
        err = obj.get("error")
        if not isinstance(err, dict):
            out.append(_f("validation", Severity.MEDIUM, "Invalid input was accepted",
                          f"Expected error {case.expect_error_code}, got a success result. "
                          "The server may be skipping input validation.", case, r.text))
        elif err.get("code") != case.expect_error_code:
            out.append(_f("conformance", Severity.INFO, "Unexpected error code",
                          f"Expected {case.expect_error_code}, got {err.get('code')}.",
                          case, r.text))

    # id echo correctness for well-formed requests
    if isinstance(case.body, dict) and "id" in case.body and isinstance(case.body["id"], (int, str)):
        if "id" in obj and obj["id"] != case.body["id"] and case.expect_error_code is None:
            out.append(_f("conformance", Severity.LOW, "Response id does not match request id",
                          "Clients use id to correlate replies; a mismatch can mix up sessions.",
                          case, str(obj.get("id"))[:200]))
    return out


TRUST_CASES = {
    "a2a.msg.role_agent": "Server accepted a client message claiming to come from the agent.",
    "a2a.msg.foreign_task": "Server continued a task the client never created.",
    "a2a.task.get_wildcard": "Server returned data for a wildcard task id.",
    "a2a.msg.file_uri_scheme": "Server accepted a file:// URI; check it is never fetched.",
    "mcp.resources.traversal": "Server returned content for a path-traversal URI.",
}


def check_trust(case: TestCase, r: Response) -> List[Finding]:
    if case.id not in TRUST_CASES:
        return []
    obj = _first_obj(r.json_body)
    if obj is not None and "result" in obj and "error" not in obj:
        return [_f("trust-boundary", Severity.MEDIUM, "Trust-boundary input accepted",
                   TRUST_CASES[case.id], case, r.text)]
    return []


ALL_CHECKS: List[Check] = [
    check_transport,
    check_server_error,
    check_leaks,
    check_slow,
    check_conformance,
    check_trust,
]


def evaluate(case: TestCase, r: Response) -> List[Finding]:
    findings: List[Finding] = []
    for chk in ALL_CHECKS:
        findings.extend(chk(case, r))
    return findings
