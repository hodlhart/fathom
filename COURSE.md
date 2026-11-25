# INF601 - Advanced Programming in Python
# Samuel Hart
# Final Project

This file records the INF 601 Advanced Programming in Python requirements for the final project.
The product README covers the MCP server itself.

## The project

Fathom is the MCP server for the Weirvern console. It exposes ten tools over the console's HTTP API
and carries the `threat-hunt` skill, which encodes the investigation method.

## The graded surface

- **MCP server:** `server.py`, ten tools, nine read and one proposal write.
- **Agent skill:** `.claude/skills/threat-hunt/SKILL.md`.
- **Live demonstration:** `scripts/live_check.py` against the seeded console, with the write tool
  proving the admin role.
- **Documentation:** the README's tool table, setup, wiring and verification sections.

## AI Usage

Claude Code was the coding harness; an AI assistant was the second pair of eyes; every change was
reviewed, run and verified before commit. The author made the design decisions and accepted or
rejected each suggestion.

## Demo notes

- Run `scripts/check_tools.py` to prove every defined tool is registered.
- Run `scripts/smoke_tools.py` against the stub console for the tool shapes.
- Run `scripts/live_check.py` against the seeded console to prove the credential and the payloads.
- The skill's procedure is the one the demo follows.
