# INF601 - Advanced Programming in Python
# Samuel Hart
# Final Project

"""Regenerate docs/transcript.md: one hunt, every tool, against the stub console.

The transcript is evidence that the tools assemble requests and return readable
answers end to end. It is NOT evidence that a particular deployment agrees, which
is what scripts/live_check.py is for, so the output says STUB in the title and in
the preamble rather than leaving a reader to infer it.

The stub is deterministic, so a rerun should produce the same file. If it does
not, the stub or a tool changed and the diff is the point.

    .venv/bin/python scripts/transcript.py > docs/transcript.md
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

HOST = "192.0.2.10"
C2 = "198.51.100.66"
WINDOW = "2026-11-19T09:45:00"

# (heading, why this call, tool, arguments). Every tool fathom serves appears
# once; a tool added without a step here is caught by the coverage check below.
STEPS: list[tuple[str, str, str, dict]] = [
    (
        "Start from the correlation, not the alert list",
        "The engine has already grouped evidence into ripples. Reading the group first avoids "
        "re-deriving it from individual decisions.",
        "list_ripples",
        {"hours": 24, "limit": 5},
    ),
    (
        "Read the detector rows behind it",
        "The ripple says conn and dns moved together. The anomaly rows name the score, the "
        "models that voted and the feature that moved.",
        "list_anomalies",
        {"hours": 24, "limit": 5},
    ),
    (
        "Describe the host",
        "Before calling anything malicious, establish what is normal for this address: volume, "
        "peers, ports and the Zeek services it uses.",
        "get_host",
        {"addr": HOST},
    ),
    (
        "Follow the conversation",
        "The host's top destination is outside the documentation prefix. The flow table gives "
        "the port, byte count and flow count for that pair.",
        "hunt_flows",
        {"src": HOST, "hours": 24, "limit": 5},
    ),
    (
        "Ask what it resolved",
        "A fixed external address is weaker evidence than a name. DNS shows what the host "
        "looked up, which is the part that survives reassignment.",
        "dns_names",
        {"hours": 24, "limit": 5},
    ),
    (
        "Read the protocol log",
        "The DNS log aggregates by host and name, so the resolver conversation is visible "
        "without pulling every query.",
        "query_zeek",
        {"log": "dns", "hours": 24, "limit": 5},
    ),
    (
        "Assemble the evidence for the finding",
        "The anomaly's window start turns a score into a bundle: the anomaly record, the flow "
        "summary, freshness per source, and the Zeek records behind it.",
        "get_finding_evidence",
        {"addr": HOST, "start": WINDOW},
    ),
    (
        "Orient in the segment's traffic",
        "Top talkers, protocol mix and destination spread separate a busy host from a host "
        "talking to one place on a fixed interval.",
        "top_talkers",
        {"hours": 24, "limit": 5},
    ),
    (
        "Check the pipeline before trusting the silence",
        "The self-audit answers a different question: are the sensors and rules healthy? A "
        "silent sensor can make a segment look quiet.",
        "alert_audit",
        {"hours": 24, "limit": 5},
    ),
    (
        "File the proposal, and stop there",
        "The evidence points at one host. This records a proposal with the reasoning attached; "
        "nothing is blocked until an operator applies it in the console.",
        "propose_block",
        {
            "host": HOST,
            "reason": (
                f"steady beacon to {C2}:443, twelve times the host's baseline connection "
                "count with near-zero payload, corroborated by DNS entropy in the 09:45 window"
            ),
            "evidence": f"ripple window {WINDOW}; anomaly score 0.94; beacon.example.com",
            "ttl_minutes": 60,
        },
    ),
]

PREAMBLE = """# A hunt, end to end — **STUB**

> **This transcript is from a STUB, not a live console.** It was produced by
> `scripts/transcript.py`, which starts `scripts/stub_console.py` and drives the
> real MCP server over stdio. The stub's payload shapes were transcribed from a
> running Weirvern console on 2026-11-23 and then rewritten onto RFC 5737
> documentation addresses and `example.com` names. No deployment's address,
> hostname or credential appears here.
>
> What it proves: each tool assembles a request, parses the console's shape, and
> returns text a model can read. What it does not prove: that your deployment
> answers the same way. That is `scripts/live_check.py`, against your console.
>
> Regenerate with:
>
> ```bash
> .venv/bin/python scripts/transcript.py > docs/transcript.md
> ```

**Question:** *Is anything on this segment beaconing? Start from the correlated
findings and show me the evidence, not just the score.*

**Answer, in one paragraph:** `192.0.2.10` is talking to `198.51.100.66:443` in
42 short flows, has a high detector score corroborated by two families, and
resolved `beacon.example.com` immediately before the window. The traffic volume is
small and the cadence is fixed. That is the beacon shape rather than the busy-host
shape. The hunt ends with a block proposal for an operator to decide, not a block.

"""


def start_stub() -> tuple[subprocess.Popen, str]:
    proc = subprocess.Popen(
        [sys.executable, str(STUB), "--port", "0"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout is not None
    line = proc.stdout.readline()
    if "http://" not in line:
        proc.kill()
        raise RuntimeError(f"the stub did not report an address: {line!r}")
    return proc, next(token for token in line.split() if token.startswith("http://")).rstrip("/")


async def collect(base: str) -> dict[str, str]:
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(SERVER)],
        env={
            **os.environ,
            "WEIRVERN_API_URL": base,
            "WEIRVERN_SESSION": "stub-session-token",
        },
    )
    answers: dict[str, str] = {}
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            served = {tool.name for tool in listed.tools}
            wanted = {step[2] for step in STEPS}
            if served != wanted:
                raise RuntimeError(
                    f"the transcript covers {sorted(wanted)} but the server serves "
                    f"{sorted(served)}"
                )
            for _heading, _why, tool, arguments in STEPS:
                result = await session.call_tool(tool, arguments)
                text = " ".join(
                    getattr(block, "text", "") for block in (result.content or [])
                ).strip()
                if not text or "fathom could not complete" in text:
                    raise RuntimeError(f"{tool} did not answer: {text[:200]}")
                answers[tool] = text
    return answers


def render(answers: dict[str, str]) -> str:
    parts = [PREAMBLE]
    for number, (heading, why, tool, arguments) in enumerate(STEPS, start=1):
        arguments_shown = ", ".join(
            f"{key}={value!r}" if isinstance(value, str) else f"{key}={value}"
            for key, value in arguments.items()
        )
        parts.append(f"## {number}. {heading}\n\n{why}\n\n")
        parts.append(f"**Call** `{tool}({arguments_shown})`\n\n")
        parts.append(f"**Answer**\n\n```text\n{answers[tool]}\n```\n\n")
    parts.append(
        "## What the transcript does not show\n\n"
        "- A real deployment's addresses, names or volumes. The stub carries one\n"
        "  synthetic host so the thread is easy to follow.\n"
        "- A successful token mint. The stub accepts any credential; the console's\n"
        "  token card has a deployment prerequisite, described in the README.\n"
        "- That the proposal was applied. It was not, and cannot be: only an\n"
        "  operator can apply one, and the tool says so in its answer.\n"
    )
    return "".join(parts)


def main() -> int:
    proc, base = start_stub()
    try:
        time.sleep(0.2)
        answers = asyncio.run(collect(base))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    sys.stdout.write(render(answers))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
