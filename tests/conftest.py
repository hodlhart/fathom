"""Shared fixtures for fathom's tests.

No test contacts a real console. There are two doubles:

  `console`       an HTTP server that records the request and answers whatever
                  the test tells it to. It is how a request shape, an auth
                  header and each failure code are inspected.
  `stub_console`  scripts/stub_console.py, a process serving the wire shapes a
                  running console returned. It is how a tool is driven end to
                  end without inventing a response inside the test.

The environment is cleared of every WEIRVERN_* variable for each test, so a
developer's own credential cannot change a result.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class _ConsoleServer(ThreadingHTTPServer):
    """A server that carries the recorder state its handler reads."""

    daemon_threads = True


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):  # noqa: A002, ANN002
        """A test double that narrates buries the assertion output."""

    def _record_and_answer(self):  # noqa: ANN202
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        console = self.server.console  # type: ignore[attr-defined]
        console.records.append({
            "method": self.command,
            "path": self.path,
            "headers": {key.lower(): value for key, value in self.headers.items()},
            "body": json.loads(body) if body else None,
        })
        route = console.routes.get(self.path.split("?", 1)[0])
        if route is None:
            status, payload, raw, content_type = (
                404, {"error": "the test did not route this path"}, None, "application/json")
        else:
            status, payload, raw, content_type = route
        data = raw if raw is not None else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    do_GET = _record_and_answer
    do_POST = _record_and_answer


class RecordedConsole:
    """A local HTTP server that records requests and returns scripted answers."""

    def __init__(self) -> None:
        self.routes: dict[str, tuple[int, object, bytes | None, str]] = {}
        self.records: list[dict] = []
        self._server = _ConsoleServer(("127.0.0.1", 0), _Handler)
        self._server.console = self  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def base(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def route(self, path: str, status: int = 200, payload: object = None,
              raw: bytes | None = None, content_type: str = "application/json") -> None:
        """Answer `path` with `payload` (JSON) or `raw` (bytes, for a malformed body)."""
        self.routes[path] = (status, payload, raw, content_type)

    def start(self) -> RecordedConsole:
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def requests_for(self, path: str) -> list[dict]:
        return [r for r in self.records if r["path"].split("?", 1)[0] == path]


@pytest.fixture(autouse=True)
def _isolate_environment(monkeypatch):
    """No WEIRVERN_* value from the developer's shell reaches a test."""
    for name in list(os.environ):
        if name.startswith("WEIRVERN_"):
            monkeypatch.delenv(name, raising=False)


@pytest.fixture
def console():
    server = RecordedConsole().start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def stub_console():
    """Run scripts/stub_console.py and yield its base URL."""
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "scripts" / "stub_console.py"), "--port", "0"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout is not None
    line = proc.stdout.readline()
    if "http://" not in line:
        proc.kill()
        raise RuntimeError(f"the stub did not report an address: {line!r}")
    base = next(token for token in line.split() if token.startswith("http://")).rstrip("/")
    try:
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture
def stub_env(stub_console, monkeypatch):
    """Point the client at the stub, with a session credential it accepts."""
    monkeypatch.setenv("WEIRVERN_API_URL", stub_console)
    monkeypatch.setenv("WEIRVERN_SESSION", "stub-session-token")
    return stub_console
