from a2afuzz.checks import evaluate
from a2afuzz.models import Response, Severity, TestCase


def case(**kw):
    base = dict(id="t", category="x", description="d", body={"jsonrpc": "2.0", "id": 1,
                                                              "method": "m"})
    base.update(kw)
    return TestCase(**base)


def test_500_is_high():
    fs = evaluate(case(), Response(status=500, text="boom"))
    assert any(f.check == "crash" and f.severity == Severity.HIGH for f in fs)


def test_traceback_leak_detected():
    text = 'Traceback (most recent call last):\n  File "/srv/app.py", line 3'
    fs = evaluate(case(), Response(status=500, text=text))
    assert any(f.check == "info-leak" for f in fs)


def test_credential_leak_is_high():
    fs = evaluate(case(), Response(status=200, text="key=AKIAABCDEFGHIJKLMNOP",
                                   json_body={"jsonrpc": "2.0", "id": 1, "result": 1}))
    assert any(f.check == "info-leak" and f.severity == Severity.HIGH for f in fs)


def test_accepted_invalid_input():
    c = case(expect_error_code=-32600)
    r = Response(status=200, json_body={"jsonrpc": "2.0", "id": 1, "result": "ok"}, text="{}")
    assert any(f.check == "validation" for f in evaluate(c, r))


def test_correct_error_is_clean():
    c = case(expect_error_code=-32601)
    body = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "nf"}}
    assert evaluate(c, Response(status=200, json_body=body, text="{}")) == []


def test_notification_reply_flagged():
    c = case(body={"jsonrpc": "2.0", "method": "n"}, expect_no_response=True)
    body = {"jsonrpc": "2.0", "id": None, "result": 1}
    fs = evaluate(c, Response(status=200, json_body=body, text='{"x":1}'))
    assert any("Notification" in f.title for f in fs)


def test_timeout_is_high():
    fs = evaluate(case(), Response(transport_error="timeout"))
    assert fs and fs[0].severity == Severity.HIGH


def test_trust_case_accepted():
    c = case(id="a2a.task.get_wildcard")
    body = {"jsonrpc": "2.0", "id": 1, "result": [{"id": "x"}]}
    fs = evaluate(c, Response(status=200, json_body=body, text="{}"))
    assert any(f.check == "trust-boundary" for f in fs)
