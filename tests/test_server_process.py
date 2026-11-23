"""The server as a process: stdio framing, stdout purity, and the shipped scripts."""

from __future__ import annotations

import json
import select
import subprocess
import sys
import urllib.error
import urllib.request

import support
from support import ROOT

SERVER = ROOT / "server.py"


def _run_server(stdin: bytes, base: str = "http://127.0.0.1:1") -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SERVER)],
        input=stdin,
        capture_output=True,
        env=support.server_env(base),
        timeout=30,
    )


def test_startup_writes_only_to_stderr():
    result = _run_server(b"")

    assert result.returncode == 0
    assert result.stdout == b""
    assert b"fathom MCP server starting on stdio" in result.stderr


def test_every_byte_on_stdout_is_a_json_rpc_message(stub_console):
    """A stray print() would land between protocol frames and break the session."""
    proc = subprocess.Popen(
        [sys.executable, str(SERVER)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        env=support.server_env(stub_console),
    )
    stdin, stdout = proc.stdin, proc.stdout
    if stdin is None or stdout is None:
        raise AssertionError("the server did not open its pipes")

    def send(frame: dict) -> None:
        stdin.write(json.dumps(frame) + "\n")
        stdin.flush()

    def receive() -> dict:
        ready, _, _ = select.select([stdout], [], [], 15)
        assert ready, "the server did not answer in time"
        line = stdout.readline()
        assert line, "the server closed stdout without answering"
        return json.loads(line)

    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                         "clientInfo": {"name": "pytest", "version": "1"}}})
        assert receive()["id"] == 1

        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        listed = receive()
        assert listed["id"] == 2
        assert len(listed["result"]["tools"]) == 10

        stdin.close()
        proc.wait(timeout=15)
        remainder = stdout.read()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)

    for line in remainder.splitlines():
        if line.strip():
            json.loads(line)


def test_a_client_is_served_ten_tools(stub_console):
    names = support.list_tools(stub_console)
    assert names == sorted(support.CALLS)


def test_every_tool_answers_over_stdio(stub_env):
    answers = support.call_tools(stub_env)

    assert set(answers) == set(support.CALLS)
    for name, text in answers.items():
        assert text, f"{name} answered with nothing"
        assert "fathom could not complete" not in text, name
        assert "Traceback" not in text, name

    signatures = {
        "list_anomalies": "Anomalies in the last 24h",
        "hunt_flows": "Flows for src 192.0.2.10",
        "get_host": "Host 192.0.2.10",
        "get_finding_evidence": "Evidence for 192.0.2.10",
        "query_zeek": "Zeek dns log",
        "top_talkers": "Traffic shape",
        "dns_names": "Names resolved",
        "alert_audit": "Pipeline audit",
        "list_ripples": "Ripples in the last",
        "propose_block": "NOTHING IS BLOCKED YET",
    }
    for name, phrase in signatures.items():
        assert phrase in answers[name], name


def test_the_anomaly_tool_reaches_the_console_through_the_client(stub_env):
    answers = support.call_tools(stub_env, {"list_anomalies": {"hours": 24, "limit": 5}})
    assert "192.0.2.10" in answers["list_anomalies"]


def test_the_smoke_script_passes_against_its_stub():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "smoke_tools.py")],
        capture_output=True, text=True, timeout=120,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "all 10 tools answered" in result.stdout


def test_check_tools_sees_every_definition_registered():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check_tools.py")],
        capture_output=True, text=True, timeout=60,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "defined with @mcp.tool: 10" in result.stdout
    assert "registered at run():    10" in result.stdout


def test_list_tools_shows_ten_to_a_client():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "list_tools.py")],
        capture_output=True, text=True, timeout=60,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "tools visible to a client: 10" in result.stdout


def test_the_stub_refuses_an_unfiltered_flow_query(stub_console):
    try:
        urllib.request.urlopen(f"{stub_console}/api/flows", timeout=5)
    except urllib.error.HTTPError as exc:
        assert exc.code == 400
        body = json.loads(exc.read())
        assert "src" in body["error"]
    else:
        raise AssertionError("the stub answered a query the real console refuses")


def test_the_stub_answers_404_for_a_path_it_does_not_serve(stub_console):
    try:
        urllib.request.urlopen(f"{stub_console}/api/unknown", timeout=5)
    except urllib.error.HTTPError as exc:
        assert exc.code == 404
    else:
        raise AssertionError("the stub invented an answer for an unknown path")
