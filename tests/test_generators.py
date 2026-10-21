import json

import pytest

from a2afuzz.generators import MAX_STRING, build_cases


@pytest.mark.parametrize("protocol", ["jsonrpc", "a2a", "mcp"])
def test_cases_are_unique_and_serialisable(protocol):
    cases = build_cases(protocol)
    assert len(cases) > 20
    assert len({c.id for c in cases}) == len(cases)
    for c in cases:
        payload = c.raw if c.raw is not None else json.dumps(c.body).encode()
        assert isinstance(payload, bytes)
        assert len(payload) < 2 * MAX_STRING  # every case stays bounded


def test_protocol_specific_cases_included():
    assert any(c.id.startswith("a2a.") for c in build_cases("a2a"))
    assert any(c.id.startswith("mcp.") for c in build_cases("mcp"))
    assert not any(c.id.startswith("a2a.") for c in build_cases("mcp"))


def test_unknown_protocol():
    with pytest.raises(ValueError):
        build_cases("smtp")
