from __future__ import annotations

import importlib.util
import sys
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from types import ModuleType

import pytest

DEMO_PATH = Path(__file__).resolve().parents[1] / "examples" / "demo_agent.py"


def _load_demo() -> ModuleType:
    spec = importlib.util.spec_from_file_location("a2afuzz_demo_agent", DEMO_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def demo_module() -> ModuleType:
    return _load_demo()


@pytest.fixture
def demo_agent(demo_module: ModuleType) -> Iterator[Callable[[bool], str]]:
    """Start the bundled demo agent on a free loopback port; returns its URL."""

    servers = []

    def start(secure: bool) -> str:
        server = demo_module.DemoServer(("127.0.0.1", 0), demo_module.DemoHandler)
        server.secure = secure
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append((server, thread))
        return f"http://127.0.0.1:{server.server_address[1]}/"

    yield start
    for server, thread in servers:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
