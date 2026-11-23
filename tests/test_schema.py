"""The schemas a client is served: ten tools, stable defaults, honest required fields."""

from __future__ import annotations

import asyncio

import server

EXPECTED_TOOLS = {
    "list_ripples",
    "list_anomalies",
    "hunt_flows",
    "get_host",
    "get_finding_evidence",
    "query_zeek",
    "top_talkers",
    "dns_names",
    "alert_audit",
    "propose_block",
}

# tool -> {argument: default}. A default here is part of the contract: the model
# is told what it gets when it omits the argument.
DEFAULTS = {
    "list_ripples": {"hours": 24, "limit": 10},
    "list_anomalies": {"hours": 24, "limit": 20},
    "hunt_flows": {"src": "", "port": 0, "proto": 0, "hours": 24, "limit": 25},
    "get_host": {},
    "get_finding_evidence": {},
    "query_zeek": {"log": "dns", "hours": 24, "limit": 25},
    "top_talkers": {"hours": 24, "limit": 10},
    "dns_names": {"hours": 24, "limit": 25},
    "alert_audit": {"hours": 24, "limit": 25},
    "propose_block": {"evidence": "", "ttl_minutes": 0},
}

REQUIRED = {
    "get_host": {"addr"},
    "get_finding_evidence": {"addr", "start"},
    "propose_block": {"host", "reason"},
}


def _schemas() -> dict[str, dict]:
    tools = asyncio.run(server.mcp.list_tools())
    return {tool.name: tool.inputSchema for tool in tools}


def test_exactly_ten_tools_are_registered():
    assert set(_schemas()) == EXPECTED_TOOLS


def test_every_tool_declares_an_object_schema_with_arguments():
    for name, schema in _schemas().items():
        assert schema["type"] == "object", name
        assert schema["properties"], name


def test_every_advertised_default_is_the_one_the_function_uses():
    schemas = _schemas()
    for name, expected in DEFAULTS.items():
        properties = schemas[name]["properties"]
        for argument, default in expected.items():
            assert argument in properties, f"{name} has no {argument} argument"
            assert properties[argument].get("default") == default, f"{name}.{argument}"


def test_only_the_tools_that_need_input_require_it():
    schemas = _schemas()
    for name, schema in schemas.items():
        assert set(schema.get("required") or []) == REQUIRED.get(name, set()), name


def test_every_tool_description_says_what_it_answers_and_returns():
    tools = asyncio.run(server.mcp.list_tools())
    for tool in tools:
        description = tool.description or ""
        assert len(description) > 80, tool.name
        assert "Args:" in description, tool.name
        assert "Returns:" in description, tool.name


def test_the_risky_tool_says_it_does_not_block():
    tools = {tool.name: tool for tool in asyncio.run(server.mcp.list_tools())}
    assert "THIS DOES NOT BLOCK ANYTHING" in (tools["propose_block"].description or "")
