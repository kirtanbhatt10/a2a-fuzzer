"""Data models shared across the fuzzer."""

from __future__ import annotations

import json
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_serializer

PREVIEW_CHARS = 2000


def _preview(s: str) -> str:
    return s if len(s) <= PREVIEW_CHARS else s[:PREVIEW_CHARS] + f"... [{len(s)} chars]"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high"].index(self.value)


class TestCase(BaseModel):
    """A single request the fuzzer will send."""

    id: str
    category: str
    description: str
    protocols: List[str] = Field(default_factory=lambda: ["jsonrpc", "a2a", "mcp"])
    # Either a JSON-serialisable body, or raw bytes (for malformed-JSON cases).
    body: Any = None
    raw: Optional[bytes] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    # What a conformant server should return. None = "any well-formed JSON-RPC error".
    expect_error_code: Optional[int] = None
    expect_no_response: bool = False  # JSON-RPC notifications

    @field_serializer("raw")
    def _ser_raw(self, v: Optional[bytes]) -> Optional[str]:
        # Raw cases may contain invalid UTF-8 on purpose; keep reports valid JSON.
        return None if v is None else _preview(v.decode("utf-8", "backslashreplace"))

    @field_serializer("body")
    def _ser_body(self, v: Any) -> Optional[str]:
        # Bodies can be huge or nested thousands of levels deep; reports keep a preview.
        if v is None:
            return None
        try:
            return _preview(json.dumps(v))
        except (RecursionError, ValueError, TypeError):
            return "<body too deeply nested to preview>"


class Response(BaseModel):
    status: Optional[int] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    text: str = ""
    json_body: Any = None
    elapsed_ms: float = 0.0
    transport_error: Optional[str] = None


class Finding(BaseModel):
    check: str
    severity: Severity
    title: str
    detail: str
    case_id: str
    evidence: str = ""


class CaseResult(BaseModel):
    case: TestCase
    response: Response
    findings: List[Finding] = Field(default_factory=list)


class Report(BaseModel):
    tool_version: str
    target: str
    protocol: str
    started_at: str
    finished_at: str
    total_cases: int
    results: List[CaseResult]

    @property
    def findings(self) -> List[Finding]:
        return [f for r in self.results for f in r.findings]

    def counts(self) -> Dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def max_severity(self) -> Optional[Severity]:
        fs = self.findings
        return max((f.severity for f in fs), key=lambda s: s.rank) if fs else None
