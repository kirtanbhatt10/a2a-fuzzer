"""Small, serialisable data models used throughout a2afuzz."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class TestCase:
    """One bounded request and the property it is intended to exercise."""

    # Not a pytest test class, despite the name; keep collectors from warning.
    __test__ = False

    id: str
    category: str
    title: str
    body: bytes
    expectation: str = "reject"
    request_id: str | int | float | None = None
    notification: bool = False
    notes: str = ""

    @property
    def payload_size(self) -> int:
        return len(self.body)


@dataclass(slots=True)
class TransportResponse:
    """A capped response capture. Network failures are data, not exceptions."""

    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    elapsed_ms: float = 0.0
    error: str | None = None
    timed_out: bool = False
    body_truncated: bool = False

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


@dataclass(frozen=True, slots=True)
class Finding:
    oracle: str
    severity: str
    message: str
    evidence: str = ""


@dataclass(slots=True)
class CaseResult:
    case: TestCase
    response: TransportResponse
    findings: list[Finding] = field(default_factory=list)


@dataclass(slots=True)
class RunResult:
    target: str
    protocol: str
    started_at: str
    finished_at: str
    cases: list[CaseResult]

    @property
    def findings(self) -> list[Finding]:
        return [finding for case in self.cases for finding in case.findings]
