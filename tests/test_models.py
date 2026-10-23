from __future__ import annotations

import a2afuzz
from a2afuzz.models import TestCase


def test_testcase_is_not_collected_by_pytest() -> None:
    assert TestCase.__test__ is False


def test_public_api_and_version() -> None:
    assert a2afuzz.__version__.count(".") == 2
    for name in a2afuzz.__all__:
        assert hasattr(a2afuzz, name), name
