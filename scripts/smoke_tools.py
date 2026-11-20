# INF601 - Advanced Programming in Python
# Samuel Hart
# Final Project

"""Drive every fathom tool through a real MCP client against the stub console.

WHAT THIS PROVES, AND WHAT IT DOES NOT. It proves the whole path from an MCP
client call to a formatted answer: argument handling, the HTTP request fathom
builds, the parse, and the text returned to the model. It does NOT prove the real
console answers the same way. That is the live check, and pretending otherwise is
how a demo fails in front of an instructor.

It fails loudly per tool, so one broken tool does not hide behind the others.

    .venv/bin/python scripts/smoke_tools.py
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import time
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "server.py"
STUB = ROOT / "scripts" / "stub_console.py"

# name -> arguments. Every tool fathom exposes must appear here; a tool missing
# from this list is a tool nobody has ever called, which is the defect this file
# exists to make impossible to forget.
CALLS: dict[str, dict] = {
    "list_anomalies": {"hours": 24, "limit": 5},
    "hunt_flows": {"src": "192.0.2.0/24", "hours": 24, "limit": 5},
    "get_host": {"addr": "192.0.2.10"},
    "get_finding_evidence": {"addr": "192.0.2.10", "start": "2026-11-19T00:00:00"},
    "query_zeek": {"log": "dns", "hours": 24, "limit": 5},
    "top_talkers": {"hours": 24, "limit": 5},
    "dns_names": {"hours": 24, "limit": 5},
    "alert_audit": {"hours": 24, "limit": 5},
    "list_ripples": {"hours": 24, "limit": 5},
    "propose_block": {
        "host": "192.0.2.10",
        "reason": "steady beacon at a fixed interval with near zero payload",
        "evidence": "anomaly window 2026-11-19T10:00:00",
        "ttl_minutes": 60,
    },
}


def start_stub() -> tuple[subprocess.Popen, str]:
    """Start the stub on a free port and return it with its base URL."""
    proc = subprocess.Popen(
        [sys.executable, str(STUB), "--port", "0"],
        stdout=subprocess.PIPE,
        text=True,
    )
    line = proc.stdout.readline() if proc.stdout else ""
    # The stub prints its address; without it there is nothing to point at.
    for token in line.replace(",", " ").split():
        if token.startswith("http://"):
            return proc, token.rstrip("/")
    proc.kill()
    raise RuntimeError(f"the stub did not report an address: {line!r}")


async def run(base: str) -> int:
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(SERVER)],
        env={
            **os.environ,
            "WEIRVERN_API_URL": base,
            "WEIRVERN_SESSION": "stub-session-token",
        },
    )
    failures: list[str] = []
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            served = sorted(t.name for t in listed.tools)

            print(f"  tools served: {len(served)}")

            for name in sorted(CALLS):
                if name not in served:
                    failures.append(f"{name}: not served by the server")
                    print(f"  FAIL  {name}: not served")
                    continue
                try:
                    result = await session.call_tool(name, CALLS[name])
                except Exception as exc:  # noqa: BLE001
                    failures.append(f"{name}: {exc}")
                    print(f"  FAIL  {name}: {exc}")
                    continue
                text = " ".join(
                    getattr(c, "text", "") for c in (result.content or [])
                ).strip()
                # MATCH THE SERVER'S OWN FAILURE MARKER, not a guess at English.
                # _fail() prefixes every tool error with this exact sentence, so a
                # 404 or a refused credential cannot read as an answer. The first
                # version of this check looked for text STARTING with "could not"
                # and missed "fathom could not complete that read", which marked a
                # 404 as ok. Found by mutation, not by reading.
                bad = (
                    not text
                    or "fathom could not complete" in text
                    or "traceback" in text.lower()
                )
                if bad:
                    failures.append(f"{name}: {text[:120]}")
                    print(f"  FAIL  {name}: {text[:100]}")
                else:
                    print(f"  ok    {name}: {text.splitlines()[0][:88]}")
            # THE FAILURE SHAPE IS CHECKED SEPARATELY, and INSIDE the session. It sat outside the
            # `async with` at first and every call on the closed session raised a ClosedResourceError
            # whose string is empty, so the check reported failure with no reason at all.
            # A formatting bug here is the defect class this project keeps finding: a read that failed
            # must not come back looking like a quiet network. The stub answers available:false at 999.
            try:
                blind = await session.call_tool("list_ripples", {"hours": 999})
                blind_text = " ".join(
                    getattr(c, "text", "") for c in (blind.content or [])
                ).strip()
                says_failed = "could not be read" in blind_text
                says_quiet = "no ripple formed" in blind_text.lower()
                if says_failed and not says_quiet:
                    print("  ok    list_ripples: an unreadable evidence set is not reported as quiet")
                else:
                    failures.append(
                        f"list_ripples failure shape: failed={says_failed} quiet={says_quiet}"
                    )
                    print(f"  FAIL  list_ripples failure shape: {blind_text[:100]}")
            except Exception as exc:  # noqa: BLE001
                failures.append(f"list_ripples failure shape: {exc}")
                print(f"  FAIL  list_ripples failure shape: {exc}")

            # EVERY KIND OF EMPTY, AND EACH WITH ITS OWN SENTENCE. Before the payload carried its
            # measurement counts, every empty list rendered the same way, which is how "nothing
            # was measured" and "nothing was in scope" became the same answer to an operator.
            # One stub value per case, and each must produce its own phrase.
            empty_cases = {
                1: "nothing was measured",
                2: "reason is scope",
                3: "too short to judge",
                4: "measured empty result",
                5: "marked insufficient",
                6: "one family only",
            }
            # A ripple that rests on one family must say so, and must name its severity band.
            res = await session.call_tool("list_ripples", {"hours": 24})
            body = " ".join(getattr(c, "text", "") for c in (res.content or [])).strip()
            for needle in ("severity", "independent families"):
                if needle not in body:
                    failures.append(f"list_ripples does not report {needle}")
                    print(f"  FAIL  list_ripples does not report {needle}")
                else:
                    print(f"  ok    list_ripples reports {needle}")

            for hours_value, expected in empty_cases.items():
                try:
                    res = await session.call_tool("list_ripples", {"hours": hours_value})
                except Exception as exc:  # noqa: BLE001
                    failures.append(f"list_ripples empty case {hours_value}: {exc}")
                    print(f"  FAIL  list_ripples empty case {hours_value}: {exc}")
                    continue
                body = " ".join(
                    getattr(c, "text", "") for c in (res.content or [])
                ).strip()
                if expected in body.lower():
                    print(f"  ok    list_ripples empty case {hours_value}: says '{expected}'")
                else:
                    failures.append(f"list_ripples empty case {hours_value}: {body[:120]}")
                    print(f"  FAIL  list_ripples empty case {hours_value}: {body[:100]}")
    uncalled = [t for t in served if t not in CALLS]
    for name in uncalled:
        failures.append(f"{name}: served but never called by this test")
        print(f"  FAIL  {name}: served but not covered here")

    print("")
    if failures:
        print(f"  {len(failures)} tool(s) failed")
        return 1
    print(f"  all {len(CALLS)} tools answered")
    return 0


def main() -> int:
    proc, base = start_stub()
    try:
        # Give the listener a moment before the first request lands.
        time.sleep(0.2)
        return asyncio.run(run(base))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())
