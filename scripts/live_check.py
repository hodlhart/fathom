# INF601 - Advanced Programming in Python
# Samuel Hart
# Final Project

"""Check fathom against the real console, once a credential exists.

DIFFERENT FROM THE OTHER TWO CHECKS, ON PURPOSE.

  check_tools.py   is every defined tool registered?          no console needed
  smoke_tools.py   does each tool work against known shapes?   stub console
  live_check.py    does the real console accept our credential
                   and answer our questions?                   real console

The order matters at demo time. A failure here is one of three things, and they
look identical from the outside: a refused credential (401), a credential with
the wrong role (403, only on propose_block), or a tool that cannot parse what the
console returns. So propose_block runs FIRST, because it is the only tool that
proves the admin role actually arrived.

Configuration comes from the environment, never from this file:

    WEIRVERN_API_URL        the console address
    WEIRVERN_TOKEN_FILE     a file holding a token minted in Settings
    WEIRVERN_CA_BUNDLE      optional, if the console uses its own CA

Run it with the project's interpreter, from the project's directory:

    .venv/bin/python scripts/live_check.py
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

# A DOCUMENTATION ADDRESS, deliberately. This files a real proposal in a real
# console, so the host must be one nobody can mistake for live infrastructure,
# and the reason says what it is. Dismiss the proposal afterwards.
PROBE_HOST = "192.0.2.10"
PROBE_REASON = (
    "fathom live check from the MCP client; RFC 5737 documentation address, "
    "no action needed, safe to dismiss"
)

# Ordered: the write first, because it is the only proof of the admin role.
CALLS: list[tuple[str, dict, bool]] = [
    ("propose_block", {"host": PROBE_HOST, "reason": PROBE_REASON,
                       "evidence": "live_check.py", "ttl_minutes": 15}, True),
    ("alert_audit", {"hours": 24, "limit": 5}, False),
    ("list_anomalies", {"hours": 24, "limit": 5}, False),
    ("top_talkers", {"hours": 24, "limit": 5}, False),
    ("dns_names", {"hours": 24, "limit": 5}, False),
    ("query_zeek", {"log": "dns", "hours": 24, "limit": 5}, False),
    # hunt_flows REFUSES an unfiltered call, which is correct: an unbounded flow
    # query is a scan, not a hunt. Give it a protocol so it has something to do.
    ("hunt_flows", {"proto": 6, "hours": 24, "limit": 5}, False),
]


def _diagnose(text: str) -> str:
    """Turn a failure sentence into the thing that is actually wrong."""
    lowered = text.lower()
    if "401" in text or "refused the credential" in lowered:
        return "credential refused: check the token value"
    if "403" in text:
        return "role too low: this needs an admin token, not readonly"
    if "certificate" in lowered or "ca bundle" in lowered:
        return "TLS: point WEIRVERN_CA_BUNDLE at the console's CA"
    if "could not reach" in lowered:
        return "address: WEIRVERN_API_URL is wrong or the console is down"
    if "no such weirvern resource" in lowered:
        return "route: the console does not serve that path"
    return "the console answered, but not with what the tool expected"


async def run() -> int:
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(SERVER)],
        env=dict(os.environ),
    )
    failures: list[str] = []
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            print(f"  tools served: {len(listed.tools)}")

            for name, args, is_write in CALLS:
                marker = "WRITE" if is_write else "read "
                try:
                    result = await session.call_tool(name, args)
                except Exception as exc:  # noqa: BLE001
                    failures.append(f"{name}: {exc}")
                    print(f"  FAIL  {marker} {name}: {exc}")
                    continue
                text = " ".join(
                    getattr(c, "text", "") for c in (result.content or [])
                ).strip()
                broke = not text or "fathom could not complete" in text
                if broke:
                    failures.append(f"{name}: {text[:160]}")
                    print(f"  FAIL  {marker} {name}: {_diagnose(text)}")
                    print(f"        console said: {text[:150]}")
                else:
                    first = text.splitlines()[0][:84]
                    print(f"  ok    {marker} {name}: {first}")

    print("")
    if failures:
        print(f"  {len(failures)} of {len(CALLS)} failed against the live console")
        return 1
    print(f"  all {len(CALLS)} answered against the live console")
    return 0


def main() -> int:
    missing = [k for k in ("WEIRVERN_API_URL",) if not os.environ.get(k)]
    if missing:
        print(f"  {', '.join(missing)} is not set; nothing to check against")
        return 2
    return asyncio.run(run())


if __name__ == "__main__":
    sys.exit(main())
