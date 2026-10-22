from __future__ import annotations

from a2afuzz.generators import MAX_PAYLOAD_BYTES, generate_cases, select_cases


def test_generators_are_unique_and_size_capped() -> None:
    for protocol, minimum in (("jsonrpc", 26), ("a2a", 32), ("mcp", 31)):
        cases = generate_cases(protocol)
        assert len(cases) >= minimum
        assert len({case.id for case in cases}) == len(cases)
        assert all(0 <= case.payload_size <= MAX_PAYLOAD_BYTES for case in cases)


def test_a2a_cases_include_trust_probes_and_selection() -> None:
    cases = generate_cases("a2a")
    trust_cases = select_cases(cases, ["a2a-trust"])
    assert len(trust_cases) == 6
    assert all(case.expectation == "trust_reject" for case in trust_cases)
    assert [case.id for case in select_cases(cases, ["parsing"])] == [
        case.id for case in cases if case.category == "parsing"
    ]
