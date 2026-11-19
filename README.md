<div align="center">

<img src="docs/banner.png" alt="fathom: an MCP server for the Weirvern console" width="820">

</div>

# fathom

An [MCP](https://modelcontextprotocol.io) server that puts the Weirvern console in
front of a model as ten callable tools, so an investigation happens inside the
agent loop instead of in a terminal someone is copying output out of.

Ten tools. Nine read. One writes, and it files a proposal rather than a block.

## Why it exists

Weirvern collects flows, DNS, Zeek logs and detector decisions, and its console
already answers every question an analyst asks. What it could not do is answer
those questions to an agent, one after another, while the agent follows a thread.

Fathom is that seam. Ask it what talked to what, which host is beaconing, what the
alerting decided, and it will go and read the console and come back with an
answer. The agent never sees the console's API; it sees tools with docstrings that
describe what the answer will be.

## The tools

| Tool | What it answers |
|---|---|
| `list_ripples` | What grouped into one incident, with the evidence underneath it |
| `list_anomalies` | What did the detectors flag recently, highest score first |
| `hunt_flows` | Flows for one host, one port or one protocol |
| `get_host` | What is known about a host: name, volume, peers, ports, timeline |
| `get_finding_evidence` | The evidence behind one finding, as the console argues it |
| `query_zeek` | One Zeek log (dns, ssl, http, conn) |
| `top_talkers` | The shape of the traffic: loudest talkers, protocol mix, busiest ports |
| `dns_names` | Names hosts resolved recently, for command and control triage |
| `alert_audit` | What the alerting decided and what was done about it |
| `propose_block` | **Propose** blocking a host. See the boundary below |

**`list_ripples` says which kind of empty it is.** An empty ripple list has four different
meanings and the payload carries the counts that tell them apart: nothing was measured, nothing
measured was inside a monitored network, the baselines were too short to judge, or it was measured
and nothing grouped. Each gets its own sentence, because "no ripple" on its own has been read as a
quiet network when it meant a broken read.

The route is young and still moving. If its payload loses a field the tool needs, it says the shape
is not understood rather than rendering blanks, since a renamed key would otherwise look like a
ripple with nothing in it. Treat that as no answer, not an empty one.

## The write boundary

`propose_block` is the only tool that changes anything, and it does not block.

It records a proposal: host, reason, evidence, and how long a block should last.
A person then decides in the console. Nothing is blocked until someone clicks, and
the proposal carries who asked (`agent:fathom`) so the decision has a source.

That split is the reason an agent is allowed to call it at all. A detector that can
block directly can take a network away on a bad day, and a model that can block
directly can do it for a reason that reads convincing and is wrong. Filing a
proposal costs an operator three seconds and preserves the one check that is hard
to automate: a human reading the reasoning.

It needs an **admin** token. A readonly token reads everything and gets a 403 here,
which is the design working rather than a fault.

## Setup

Three environment variables. There is no default address on purpose: a
deployment's address is environment specific and does not belong in a repository.

| Variable | Meaning |
|---|---|
| `WEIRVERN_API_URL` | The console address, for example `https://console.example.com` |
| `WEIRVERN_TOKEN_FILE` | A file holding a token minted in Settings. Preferred. |
| `WEIRVERN_TOKEN` | The token itself, for a throwaway run. Avoid: shell history, `/proc` |
| `WEIRVERN_CA_BUNDLE` | Optional. The console's CA certificate, if it does not use a public one |
| `WEIRVERN_SESSION_FILE` / `WEIRVERN_SESSION` | A `/api/login` session, if that is what you have |
| `WEIRVERN_USERNAME` + `WEIRVERN_PASSWORD` | Signs in for you and uses the session |

### Mint a token

In the console: **Settings → Tokens → New token**. Choose the role:

- **readonly** (the console's `viewer` role) for the nine read tools
- **admin** if you want `propose_block` to file anything

The token is shown once. Save it to a file only you can read:

```bash
umask 077 && cat > ~/.weirvern-agent-token
# paste, Enter, then Ctrl-D
chmod 600 ~/.weirvern-agent-token
```

**A token and a session travel in different headers**, and the distinction is not
cosmetic. A minted token goes in `X-Weirvern-Token`; a session from `/api/login`
goes in `X-Weirvern-Session`. Sending a token as a session authenticates nothing
and the console answers a plain 401 that names neither.

### Install

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Wire it into Claude Code

Commit-ready example: [`.mcp.json.example`](.mcp.json.example). Copy it to
`.mcp.json` and put in absolute paths, because Claude Code spawns the interpreter
directly:

```json
{
  "mcpServers": {
    "fathom": {
      "command": "/absolute/path/to/fathom/.venv/bin/python",
      "args": ["/absolute/path/to/fathom/server.py"],
      "env": {
        "WEIRVERN_API_URL": "https://console.example.com",
        "WEIRVERN_TOKEN_FILE": "/absolute/path/to/agent-token",
        "WEIRVERN_CA_BUNDLE": "/absolute/path/to/ca-bundle.pem"
      }
    }
  }
}
```

Then, once:

```bash
claude mcp list     # fathom should appear; a project-scoped server needs one approval
claude              # then: "hunt for beaconing in the last 24 hours"
```

Fathom is a **stdio** server: Claude Code spawns it per session and kills it at the
end. There is no port and no address. Anything printed to stdout corrupts the
protocol, which is why diagnostics go to stderr.

## Verifying it

Three scripts, three different questions. Each exists because the others cannot
answer its question, and a green run from the wrong one is worse than no run.

```bash
.venv/bin/python scripts/check_tools.py    # is every defined tool registered?
.venv/bin/python scripts/smoke_tools.py    # does each tool work, against known shapes?
.venv/bin/python scripts/live_check.py     # does the real console accept us?
```

| Script | Question | Needs a console |
|---|---|---|
| `check_tools.py` | Every `@mcp.tool()` in `server.py` actually reaches the running server | no |
| `smoke_tools.py` | Each tool assembles a request and formats an answer | a stub, started for you |
| `live_check.py` | The real console accepts the credential and answers | yes, with a token |

`check_tools.py` exists because a tool written below
`if __name__ == "__main__": mcp.run()` is dead code: `run()` blocks, the decorator
never executes, and the file looks correct while the server serves one tool fewer.
It parses the decorators out of the syntax tree and compares them with the registry
at the moment `run()` is called.

`live_check.py` runs `propose_block` first, because it is the only call that proves
the admin role arrived. A 401 is a wrong credential, a 403 only on that tool is a
readonly token, and a certificate error is the CA bundle. They look identical from
outside and completely different from that script's output.

## The skills

`.claude/skills/threat-hunt/SKILL.md` encodes the investigation method: what to look
at first, what a beacon looks like next to a busy host, and when filing a proposal
is justified. It drives the tools above and is the second agentic piece of the final
project.

## Layout

```
server.py                  the MCP server: ten tools, stderr logging only
client.py                  the console API client, one credential path
scripts/check_tools.py     registration guard, no dependencies
scripts/smoke_tools.py     every tool against a stub console
scripts/stub_console.py    the stub: console wire shapes, 404 for anything else
scripts/live_check.py      the real console, with the failure named
scripts/list_tools.py      what a client is actually served
ca-bundle.pem              the console's CA, if it uses its own
.claude/skills/            the threat-hunt skill
```

## Requirements

Python 3.10 or newer, which is what `mcp` itself requires. `requirements.txt` is a
real freeze of the server's dependencies, not the development environment.

## Part of

The final project for INF 601, Advanced Programming with Python: a Flask console,
a detector pipeline and this MCP server on top of the Weirvern API.
