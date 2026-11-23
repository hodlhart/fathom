# Setup

Fathom is a stdio MCP server. This guide covers the three things an install
needs: a credential, a client registration, and (optionally) the `threat-hunt`
skill. The README has the tool reference and the full environment table; this file
is the walkthrough.

- [What you need](#what-you-need)
- [1. Install](#1-install)
- [2. Configure a credential](#2-configure-a-credential)
- [3. Register the server](#3-register-the-server)
- [Install the threat-hunt skill](#install-the-threat-hunt-skill)
- [Troubleshooting](#troubleshooting)
- [Security notes](#security-notes)

## What you need

| | |
|---|---|
| Python | 3.11 or newer for the pinned install. 3.10 works with `mcp==1.30.0` and resolver-chosen dependencies |
| A console | A running [Weirvern](https://github.com/hodlhart/weirvern) console, reachable from this machine |
| A credential | A **viewer** token for the nine read tools. An **admin** token only if `propose_block` must file proposals |
| The console CA | Only if the console uses a private CA. Point `WEIRVERN_CA_BUNDLE` at it; do not disable verification |

## 1. Install

```bash
git clone https://github.com/hodlhart/fathom.git
cd fathom
python -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Confirm the server is intact before adding credentials:

```bash
.venv/bin/python scripts/check_tools.py   # defined 10, registered 10
.venv/bin/python -m pytest -q             # the suite, against a stub
```

## 2. Configure a credential

The preferred credential is a token minted in the console, stored in a file only
you can read. The exact UI path, the role names and the deployment prerequisite
are in the README section
[Generate a token in Weirvern](../README.md#generate-a-token-in-weirvern).

```bash
umask 077 && cat > ~/.weirvern-agent-token
# paste the token, press Enter, then Ctrl-D
chmod 600 ~/.weirvern-agent-token
```

If the console cannot mint tokens (its GUI pod is missing the
`weirvern-operator` service account), use a signed-in session instead:

```bash
# Option A: a session token obtained elsewhere
export WEIRVERN_SESSION='...'

# Option B: let fathom sign in; the session is exchanged at startup and kept in memory
export WEIRVERN_USERNAME='operator'
export WEIRVERN_PASSWORD='...'
```

Never commit a credential. Point at a file with `WEIRVERN_TOKEN_FILE` or
`WEIRVERN_SESSION_FILE` where the client supports it. If the value has to live in
the server's `env` block, use `WEIRVERN_TOKEN` for a minted token (it is read from
`X-Weirvern-Token`) and `WEIRVERN_SESSION` only for a login session; keep the
config at mode 600 and out of version control. A token in `WEIRVERN_SESSION` is
sent in the wrong header and answers 401.

### Verify the credential before wiring anything

```bash
WEIRVERN_API_URL=https://console.example.com \
WEIRVERN_TOKEN_FILE=$HOME/.weirvern-agent-token \
.venv/bin/python scripts/live_check.py
```

The output names the failure instead of making you guess: 401 is a wrong or
expired credential (or a token sent as a session), 403 is a role that is too low
(expected only on `propose_block` with a viewer token), a certificate error is
the CA bundle, and "Could not reach Weirvern" is the address or the console.

## 3. Register the server

Every MCP client registration has the same three parts: a command, arguments, and
an environment. The command must be the **virtualenv's** interpreter, because the
client does not activate a shell.

```json
{
  "mcpServers": {
    "fathom": {
      "command": "/absolute/path/to/fathom/.venv/bin/python",
      "args": ["/absolute/path/to/fathom/server.py"],
      "env": {
        "WEIRVERN_API_URL": "https://console.example.com",
        "WEIRVERN_TOKEN_FILE": "/home/you/.weirvern-agent-token"
      }
    }
  }
}
```

### Claude Code

The repository ships [`.mcp.json.example`](../.mcp.json.example). Copy it to
`.mcp.json` in the project where you want the tools, and replace every absolute
path:

```bash
cp .mcp.json.example .mcp.json
$EDITOR .mcp.json
claude mcp list        # fathom should appear
```

A project-scoped server needs one approval on first use. To register it for every
project instead, use Claude Code's user scope:

```bash
claude mcp add --scope user fathom \
  --env WEIRVERN_API_URL=https://console.example.com \
  --env WEIRVERN_TOKEN_FILE=$HOME/.weirvern-agent-token \
  -- /absolute/path/to/fathom/.venv/bin/python /absolute/path/to/fathom/server.py
```

### Claude Desktop

Add the same `mcpServers` block to the desktop configuration file, creating it if
it does not exist:

| OS | Path |
|---|---|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

Restart the client after editing. The tools appear with the other tools the
client offers; desktop clients do not print a separate confirmation.

### Any other stdio MCP client

Spawn the virtualenv interpreter with `server.py` as the only argument and the
environment above. Fathom speaks the standard stdio transport, prints nothing but
JSON-RPC on stdout, and exits when stdin closes. There is no port, no HTTP
endpoint and no authentication between the client and the server; the credential
is only for the console.

### Check what the client sees

```bash
.venv/bin/python scripts/list_tools.py
```

```
  tools visible to a client: 10
    alert_audit
    dns_names
    get_finding_evidence
    get_host
    hunt_flows
    list_anomalies
    list_ripples
    propose_block
    query_zeek
    top_talkers
```

If the client lists fewer, the cause is almost always a tool defined below
`mcp.run()`; `scripts/check_tools.py` detects exactly that.

## Install the threat-hunt skill

The skill is the method; fathom is the hands. It lives at
`.claude/skills/threat-hunt/SKILL.md`.

**Project scope (already done in this repository).** Open the fathom checkout in
Claude Code and the skill is discovered from `.claude/skills/`. To use it in a
different project, copy the directory:

```bash
mkdir -p /path/to/project/.claude/skills
cp -r /path/to/fathom/.claude/skills/threat-hunt /path/to/project/.claude/skills/
```

**User scope (every project).**

```bash
mkdir -p ~/.claude/skills
cp -r .claude/skills/threat-hunt ~/.claude/skills/
```

Restart the client after copying: skills are discovered at startup, not on a
filesystem watch. Verify by asking for it by name ("use the threat-hunt skill to
look at the last 24 hours"); the client lists it among its available skills.

For a non-Claude MCP client, the same file is a plain instruction document. Load
it as the agent's system or developer prompt, or paste it into the session before
the first question. Nothing in it is Claude-specific beyond the discovery path.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| The server does not appear in the client | Wrong interpreter path, or a relative path where the client expects an absolute one | Use the output of `realpath .venv/bin/python` and `realpath server.py` |
| `WEIRVERN_API_URL is not set` | The `env` block did not reach the process | The client passes only what you put in `env`; add it there, not to your shell profile |
| `401` | Wrong, expired or misrouted credential | A token goes in `WEIRVERN_TOKEN_FILE`; a session goes in `WEIRVERN_SESSION`; they use different headers |
| `403` on every tool | The credential cannot read the console | Use a viewer or admin token for this deployment |
| `403` only on `propose_block` | Viewer role | Mint an admin token if proposals are wanted; otherwise this is correct |
| `certificate is not trusted` | Private CA not trusted | Set `WEIRVERN_CA_BUNDLE`; never disable verification |
| Tools list, but every call fails | The console is down or the address is a proxy prefix | `WEIRVERN_API_URL` is the console root, for example `https://console.example.com` |
| The client hangs on startup | A stray `print()` reached stdout | Run `.venv/bin/python server.py` with stdin closed; it must print nothing to stdout |
| `502` from Create token | The GUI pod lacks the operator service account | Use a session credential, or fix the deployment; see the README |

## Security notes

- **Default to viewer.** The nine read tools are all an investigation needs.
  `propose_block` files a proposal and enforces nothing; use an admin credential
  only when that step is wanted.
- **A credential is not an account.** A token carries one role, is revoked on its
  own, and cannot mint or revoke another token. A session belongs to a person and
  ends when they sign out.
- **Only the proposal is writable.** No tool blocks, dismisses or changes a
  detector. Every other call is a GET.
- **TLS verification stays on.** `WEIRVERN_CA_BUNDLE` adds a CA; there is no
  insecure switch, because a tool that reports interception must not be blind to
  it.
- **Secrets stay out of the repository.** `.env`, `*.token`, `secrets.toml`,
  `ca-bundle.pem` and `.mcp.json` are gitignored. The tests clear every
  `WEIRVERN_*` variable and never contact a live console.
