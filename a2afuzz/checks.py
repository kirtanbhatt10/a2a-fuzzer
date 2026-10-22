"""Response oracles used to turn probe outcomes into actionable findings."""

from __future__ import annotations

import json
import re
from typing import Any

from .models import Finding, TestCase, TransportResponse

_STACK_TRACE = re.compile(
    r"(?:traceback \(most recent call last\)|\bfile \"/|\bat \S+ \([^\n]+:\d+:\d+\)|"
    r"\bjava\.[\w.]+exception\b|\bpanic:|\bfatal error:)",
    re.IGNORECASE,
)
_PATH_LEAK = re.compile(r"(?:/Users/|/home/|/app/|[A-Za-z]:\\(?:Users|\w+\\))")
_SECRET = re.compile(
    r"(?:\bsk-[A-Za-z0-9_-]{16,}|\b(?:api[_-]?key|authorization)\s*[:=]\s*['\"]?[A-Za-z0-9_-]{16,})",
    re.IGNORECASE,
)


def _response_json(response: TransportResponse) -> tuple[Any | None, bool]:
    if not response.body:
        return None, True
    try:
        return json.loads(response.text), True
    except json.JSONDecodeError:
        return None, False


def _success_result(payload: Any) -> bool:
    return isinstance(payload, dict) and "result" in payload and "error" not in payload


def _evidence(text: str, limit: int = 300) -> str:
    compact = " ".join(text.split())
    return compact[:limit] + ("…" if len(compact) > limit else "")


def evaluate_response(
    case: TestCase,
    response: TransportResponse,
    *,
    slow_after_ms: float | None = None,
) -> list[Finding]:
    """Evaluate a response without assuming a particular agent implementation."""

    findings: list[Finding] = []
    if response.timed_out:
        return [Finding("availability", "high", "Request timed out", response.error or "")]
    if response.error:
        return [Finding("availability", "low", "Connection failed or was dropped", response.error)]

    assert response.status_code is not None
    if response.status_code >= 500:
        findings.append(
            Finding(
                "crash", "high", f"Server returned HTTP {response.status_code}", response.text[:300]
            )
        )
    if slow_after_ms is not None and response.elapsed_ms > slow_after_ms:
        findings.append(
            Finding(
                "availability",
                "low",
                f"Slow response ({response.elapsed_ms:.0f} ms)",
                f"threshold: {slow_after_ms:.0f} ms",
            )
        )
    if response.body_truncated:
        findings.append(
            Finding(
                "availability",
                "low",
                "Response exceeded capture limit",
                "capture capped at 256 KiB",
            )
        )

    text = response.text
    if _SECRET.search(text):
        findings.append(
            Finding("info-leak", "high", "Response appears to expose a credential", _evidence(text))
        )
    elif _STACK_TRACE.search(text):
        findings.append(
            Finding("info-leak", "high", "Response exposes a server stack trace", _evidence(text))
        )
    elif _PATH_LEAK.search(text):
        findings.append(
            Finding("info-leak", "medium", "Response exposes a server file path", _evidence(text))
        )

    payload, is_json = _response_json(response)
    success = _success_result(payload)
    if case.expectation == "trust_reject" and success:
        findings.append(
            Finding(
                "trust-boundary",
                "medium",
                "Trust-boundary probe was accepted with a success result",
                _evidence(text),
            )
        )
    elif case.expectation == "reject" and success:
        findings.append(
            Finding(
                "validation",
                "medium",
                "Malformed or unsupported input was accepted with a success result",
                _evidence(text),
            )
        )

    if case.notification:
        if response.body:
            findings.append(
                Finding(
                    "conformance",
                    "low",
                    "Server replied to a JSON-RPC notification",
                    _evidence(text),
                )
            )
        return findings

    if response.status_code < 400 and response.body and not is_json:
        findings.append(
            Finding("conformance", "low", "Successful HTTP response is not JSON", _evidence(text))
        )
        return findings

    if isinstance(payload, dict):
        if payload.get("jsonrpc") != "2.0":
            findings.append(
                Finding(
                    "conformance",
                    "low",
                    "Response omits or has wrong jsonrpc version",
                    _evidence(text),
                )
            )
        # An invalid or deliberately oversized id may be indistinguishable from
        # an unparsable request. JSON-RPC permits a null error id in that case,
        # so do not turn a defensive rejection of an ``ids`` probe into a false
        # positive. Other probes retain strict response-id matching.
        if (
            case.category != "ids"
            and case.request_id is not None
            and "id" in payload
            and payload["id"] != case.request_id
        ):
            findings.append(
                Finding(
                    "conformance",
                    "low",
                    "Response id does not match request id",
                    f"request id {case.request_id!r}; response id {payload['id']!r}",
                )
            )
    return findings


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}


def meets_severity(finding: Finding, threshold: str | None) -> bool:
    """Whether a finding is at least a requested ``--fail-on`` severity."""

    if threshold is None:
        return False
    return SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[threshold]
