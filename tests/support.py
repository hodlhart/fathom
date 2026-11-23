"""Helpers for driving the real MCP server over stdio, the way a client does."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[1]

# Every tool, with arguments that the stub console answers. A tool missing from
# this mapping is a tool no test has ever called.
CALLS: dict[str, dict] = {
    "list_anomalies": {"hours": 24, "limit": 5},
    "hunt_flows": {"src": "192.0.2.10", "hours": 24, "limit": 5},
    "get_host": {"addr": "192.0.2.10"},
    "get_finding_evidence": {"addr": "192.0.2.10", "start": "2026-11-19T09:45:00"},
    "query_zeek": {"log": "dns", "hours": 24, "limit": 5},
    "top_talkers": {"hours": 24, "limit": 5},
    "dns_names": {"hours": 24, "limit": 5},
    "alert_audit": {"hours": 24, "limit": 5},
    "list_ripples": {"hours": 24, "limit": 5},
    "propose_block": {
        "host": "192.0.2.10",
        "reason": "steady beacon at a fixed interval with near zero payload",
        "evidence": "anomaly window 2026-11-19T09:45:00",
        "ttl_minutes": 60,
    },
}


def server_env(base_url: str) -> dict[str, str]:
    """The environment a client would hand the server process."""
    return {
        **os.environ,
        "WEIRVERN_API_URL": base_url,
        "WEIRVERN_SESSION": "stub-session-token",
    }


def list_tools(base_url: str) -> list[str]:
    """The tool names a real MCP client is served."""

    async def run() -> list[str]:
        params = StdioServerParameters(
            command=sys.executable, args=[str(ROOT / "server.py")], env=server_env(base_url))
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                listed = await session.list_tools()
                return sorted(tool.name for tool in listed.tools)

    return asyncio.run(run())


def call_tools(base_url: str, calls: dict[str, dict] | None = None) -> dict[str, str]:
    """Call tools through a real stdio session and return the text each one answered."""
    wanted = CALLS if calls is None else calls

    async def run() -> dict[str, str]:
        params = StdioServerParameters(
            command=sys.executable, args=[str(ROOT / "server.py")], env=server_env(base_url))
        answers: dict[str, str] = {}
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                for name, arguments in wanted.items():
                    result = await session.call_tool(name, arguments)
                    answers[name] = " ".join(
                        getattr(block, "text", "") for block in (result.content or [])
                    ).strip()
        return answers

    return asyncio.run(run())
