"""The documentation is part of the deliverable, so it is checked like code."""

from __future__ import annotations

import ipaddress
import re
import subprocess
import sys
from pathlib import Path

from support import ROOT

SKIP_DIRS = {".git", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache"}
TEXT_SUFFIXES = {".md", ".py", ".txt", ".json", ".yml", ".yaml", ".toml", ".ini", ".example"}

# RFC 5737 documentation ranges, plus loopback for the test doubles.
ALLOWED = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("127.0.0.0/8"),
]

IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def _text_files() -> list[Path]:
    files = []
    for path in ROOT.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and (path.suffix in TEXT_SUFFIXES or path.name == ".gitignore"):
            files.append(path)
    return files


def _check_relative_links(document: Path) -> None:
    text = document.read_text(encoding="utf-8")
    for match in re.finditer(r"\[[^\]]+\]\(([^)]+)\)", text):
        target = match.group(1).strip()
        if target.startswith(("http://", "https://", "#", "mailto:")):
            continue
        path = target.split("#", 1)[0]
        if not path:
            continue
        resolved = (document.parent / path).resolve()
        assert resolved.exists(), f"{document.relative_to(ROOT)} links to a missing {target}"


def test_the_documented_files_exist():
    for name in ("LICENSE", "README.md", "docs/SETUP.md", "docs/transcript.md",
                 ".mcp.json.example", "requirements.txt", "requirements-dev.txt",
                 ".github/workflows/tests.yml"):
        assert (ROOT / name).is_file(), name


def test_the_readme_links_resolve():
    _check_relative_links(ROOT / "README.md")


def test_the_setup_guide_links_resolve():
    _check_relative_links(ROOT / "docs" / "SETUP.md")


def test_the_readme_states_what_it_is_and_how_to_operate_it():
    text = (ROOT / "README.md").read_text(encoding="utf-8")

    for heading in ("## Why it exists", "## Install", "## Configuration", "## Usage",
                    "## Failure modes and limitations", "## License"):
        assert heading in text, heading
    assert "https://github.com/hodlhart/weirvern" in text
    assert "Generate a token in Weirvern" in text
    # The layout block used to list a file that is not in the repository.
    assert "OPTIONAL, gitignored" in text


def test_the_license_is_the_project_license():
    text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert text.startswith("MIT License")
    assert "Samuel Hart" in text


def test_the_transcript_is_labelled_stub_and_covers_every_tool():
    text = (ROOT / "docs" / "transcript.md").read_text(encoding="utf-8")
    assert text.splitlines()[0].endswith("**STUB**")
    assert "STUB, not a live console" in text
    for tool in ("list_ripples", "list_anomalies", "hunt_flows", "get_host",
                 "get_finding_evidence", "query_zeek", "top_talkers", "dns_names",
                 "alert_audit", "propose_block"):
        assert f"`{tool}(" in text, tool


def test_the_transcript_is_the_generator_s_output():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "transcript.py")],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == (ROOT / "docs" / "transcript.md").read_text(encoding="utf-8")


def test_no_undeclared_address_appears_anywhere():
    """Only RFC 5737 documentation ranges and loopback may be committed."""
    offenders = []
    for path in _text_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in IPV4.finditer(text):
            try:
                address = ipaddress.ip_address(match.group(0))
            except ValueError:
                continue  # a version number such as 1.2.3.400, not an address
            if not any(address in network for network in ALLOWED):
                offenders.append(f"{path.relative_to(ROOT)}: {address}")
    assert not offenders, "non-documentation addresses: " + ", ".join(offenders)
