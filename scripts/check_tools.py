# INF601 - Advanced Programming in Python
# Samuel Hart
# Final Project

"""Fail when a tool defined in server.py never reaches the running server.

WHY THIS EXISTS. `if __name__ == "__main__": mcp.run()` blocks forever serving
stdio, so any `@mcp.tool()` written after it is never executed and its tool is
never registered. The file looks correct, an import-based test registers every
tool and passes, and the running server is missing a tool. That is how
`propose_block` shipped invisible: eight tools served, nine defined.

So this check runs the file the way a client runs it, as a script, and stops it
at the exact moment `mcp.run()` is called, which is the only moment that
matters. What it compares is the set of decorated functions in the source
against the set the registry actually holds.

Exit status: 0 when they match, 1 when they do not, with the mismatch named.

Run it with the project's interpreter, since it needs the same `mcp` version:

    .venv/bin/python scripts/check_tools.py
"""

from __future__ import annotations

import ast
import os
import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "server.py"

# server.py imports its sibling `client` by bare name, the way it does when
# python runs it as a script. runpy does not add the script's directory to
# sys.path, so it is added here or the check fails for the wrong reason.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def decorated_tool_names(path: Path) -> list[str]:
    """Every function in the file carrying an `@mcp.tool` decorator.

    Read from the syntax tree rather than by matching text, so a decorator
    inside a string or a comment cannot be counted as a real one.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if any(_is_tool_decorator(d) for d in node.decorator_list):
            names.append(node.name)
    return sorted(names)


def _is_tool_decorator(node: ast.expr) -> bool:
    """True for `@mcp.tool()` and for the undecorated form `@mcp.tool`."""
    target = node.func if isinstance(node, ast.Call) else node
    return isinstance(target, ast.Attribute) and target.attr == "tool"


def registered_tool_names(path: Path) -> tuple[list[str], bool]:
    """The registry at the moment `mcp.run()` is called, running as a script.

    Returns the names and whether `run()` was reached at all. A file that never
    calls `run()` is a different failure and is reported as such, rather than
    being mistaken for a clean run with no tools.
    """
    from mcp.server.fastmcp import FastMCP

    captured: dict[str, list[str]] = {}
    original_run = FastMCP.run

    def capture_run(self, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ARG001
        manager = getattr(self, "_tool_manager", None)
        tools = getattr(manager, "_tools", {}) if manager else {}
        captured["tools"] = sorted(tools)
        # Stop here rather than serve. This is the state a client would see.
        raise SystemExit(0)

    FastMCP.run = capture_run  # type: ignore[method-assign]
    try:
        runpy.run_path(str(path), run_name="__main__")
    except SystemExit:
        pass
    finally:
        FastMCP.run = original_run  # type: ignore[method-assign]

    return captured.get("tools", []), "tools" in captured


def main() -> int:
    if not SERVER.exists():
        print(f"  no server.py at {SERVER}")
        return 1

    # The server reads its address lazily, so a placeholder keeps import-time
    # checks quiet without touching anything real.
    os.environ.setdefault("WEIRVERN_API_URL", "https://192.0.2.10")
    os.environ.setdefault("WEIRVERN_SESSION", "not-a-real-token")

    defined = decorated_tool_names(SERVER)
    served, reached = registered_tool_names(SERVER)

    print(f"  defined with @mcp.tool: {len(defined)}")
    print(f"  registered at run():    {len(served)}")

    if not reached:
        print("  FAIL: mcp.run() was never reached, so nothing is served at all")
        return 1

    missing = [n for n in defined if n not in served]
    extra = [n for n in served if n not in defined]

    if missing:
        print("")
        print("  FAIL: these tools are defined but never registered:")
        for name in missing:
            print(f"    {name}")
        print("")
        print("  A tool written after `if __name__ == \"__main__\": mcp.run()` is dead")
        print("  code: run() blocks, so the decorator below it never executes. Move the")
        print("  entry point to the end of the file, after every tool definition.")
        return 1

    if extra:
        print("")
        print("  FAIL: these tools are registered but not defined in server.py:")
        for name in extra:
            print(f"    {name}")
        return 1

    print("  OK: every decorated tool is registered")
    return 0


if __name__ == "__main__":
    sys.exit(main())
