# INF601 - Advanced Programming in Python
# Samuel Hart
# Final Project

"""Print the tools a real MCP client sees when it spawns fathom over stdio.

`check_tools.py` answers "is every defined tool registered" by inspecting the
registry in-process. This answers a different question: what does an actual
client get back. They agree today, and when they disagree the client is right.

No console is contacted. The address is a documentation placeholder and the
token is a string that never leaves the machine, because listing tools is
handled by the server before any Weirvern call happens.

    .venv/bin/python scripts/list_tools.py
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "server.py"


async def main() -> int:
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(SERVER)],
        env={
            **os.environ,
            "WEIRVERN_API_URL": "https://192.0.2.10",
            "WEIRVERN_SESSION": "not-a-real-token",
        },
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            names = sorted(tool.name for tool in listed.tools)
            print(f"  tools visible to a client: {len(names)}")
            for name in names:
                print(f"    {name}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
