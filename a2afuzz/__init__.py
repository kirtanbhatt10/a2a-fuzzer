"""A bounded, opt-in robustness fuzzer for JSON-RPC agent endpoints."""

from ._version import __version__
from .generators import generate_cases, select_cases
from .models import CaseResult, Finding, RunResult, TestCase, TransportResponse
from .report import write_reports
from .runner import FuzzRunner, TargetAuthorizationError

__all__ = [
    "CaseResult",
    "Finding",
    "FuzzRunner",
    "RunResult",
    "TargetAuthorizationError",
    "TestCase",
    "TransportResponse",
    "__version__",
    "generate_cases",
    "select_cases",
    "write_reports",
]
