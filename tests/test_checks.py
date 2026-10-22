from __future__ import annotations

from a2afuzz.checks import evaluate_response, meets_severity
from a2afuzz.generators import generate_cases, select_cases
from a2afuzz.models import Finding, TransportResponse


def test_trust_success_is_reported() -> None:
    case = select_cases(generate_cases("a2a"), ["a2a-trust-agent-role"])[0]
    response = TransportResponse(
        status_code=200,
        body=b'{"jsonrpc":"2.0","id":1,"result":{"accepted":true}}',
    )
    findings = evaluate_response(case, response)
    assert any(
        finding.oracle == "trust-boundary" and finding.severity == "medium" for finding in findings
    )


def test_stack_trace_and_notification_reply_are_reported() -> None:
    case = select_cases(generate_cases("jsonrpc"), ["notification-replied"])[0]
    response = TransportResponse(
        status_code=500,
        body=b'Traceback (most recent call last):\n  File "/srv/app.py", line 1',
    )
    findings = evaluate_response(case, response)
    assert {finding.oracle for finding in findings} >= {"crash", "info-leak", "conformance"}


def test_defensive_null_id_for_an_invalid_id_probe_is_not_a_mismatch() -> None:
    case = select_cases(generate_cases("jsonrpc"), ["id-10k-string"])[0]
    response = TransportResponse(
        status_code=200,
        body=b'{"jsonrpc":"2.0","id":null,"error":{"code":-32600}}',
    )
    findings = evaluate_response(case, response)
    assert not any(
        finding.message == "Response id does not match request id" for finding in findings
    )


def test_severity_thresholds() -> None:
    finding = Finding("validation", "medium", "bad input accepted")
    assert meets_severity(finding, "low")
    assert meets_severity(finding, "medium")
    assert not meets_severity(finding, "high")
    assert not meets_severity(finding, None)
