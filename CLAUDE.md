# fathom

An MCP server over the Weirvern read API, so an agent can hunt through network
telemetry that is already being collected.

## What it is for

Weirvern records flows, Zeek logs, host identities and detector findings, and
shows them in a console. fathom exposes those reads as tools, so the agent can be
asked a question in words and answer it by querying, rather than by a person
clicking through views.

fathom is deliberately **read-only**. `/api/sluice/block` exists and would be one
more tool, but an agent holding a blocking primitive is one bad prompt away from
an outage. Where an action has blast radius, the tool should propose it with the
evidence attached and leave the click to a human.

## The split with the skill

`fathom` gives the agent hands. The `threat-hunt` skill gives it a method: what to
check first, what counts as evidence rather than a guess, and when to escalate.
Neither is much use alone.

## Connection

| variable | meaning |
|---|---|
| `WEIRVERN_API_URL` | base URL of the console. Required, no default |
| `WEIRVERN_SESSION` | a session token minted elsewhere |
| `WEIRVERN_USERNAME` / `WEIRVERN_PASSWORD` | used to sign in when no token is set |
| `WEIRVERN_CA_BUNDLE` | the console's CA certificate, so TLS verification stays on |

Prefer the session credential over the operator token. A session belongs to one
account, appears in the audit log under that name, and is revoked by signing out.
The operator token is a deployment-wide break-glass admin credential and has no
business in a read-only tool.

Weirvern serves TLS from its own internal CA. Point `WEIRVERN_CA_BUNDLE` at
`ca-bundle.pem`, which is not committed because it belongs to one deployment.
Disabling verification instead would make the tool blind to exactly the
interception it exists to report on.

## Tools

| tool | answers |
|---|---|
| `list_anomalies` | what the detectors flagged, newest first |
| `hunt_flows` | who talked to whom, filtered by host, port or protocol |
| `get_host_evidence` | what is known about one host, as evidence |
| `query_zeek` | one Zeek log, per host |
| `top_talkers` | volume, protocol mix, busiest ports, destination spread |
| `dns_names` | what hosts resolved, for C2 triage |
| `alert_audit` | what the alerting decided and what followed |

Every tool returns a short block of text, not raw JSON. On failure it returns a
sentence naming what to check.

## Style rules for this project

- PEP 8, two blank lines between top-level definitions, no line over 100 chars.
- Every `.py` starts with the three header lines.
- Never `print()` to stdout: stdout is the MCP transport. Use `client._log`.
- Never hard-code a credential or a host. Everything comes from the environment.
- No em dashes, American spelling.

## Status

Seven tools register and the server imports with zero bytes on stdout. The client
is verified against the live console: the open probes return data, and all ten
read routes return a sentence rather than a traceback when the credential is
missing or wrong. The tool bodies have not yet been exercised against real data,
which needs a credential.
