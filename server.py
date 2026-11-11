# INF601 - Advanced Programming in Python
# Samuel Hart
# Final Project - fathom MCP server

"""fathom: an MCP server over Weirvern's read API.

fathom gives an agent hands on a network monitoring system that already collects
flows, Zeek logs, host identities and detector findings. The tools are read-only
on purpose. A hunting assistant that can answer questions about a segment is
useful; one that can also block a host is an outage waiting for a bad prompt.

Every tool returns a short block of text rather than raw JSON. The model reads
these strings, so each one says what was asked, what came back, and, when a read
fails, what to check.

Nothing in this file may print to stdout: stdout carries the stdio protocol. Use
client._log, which writes to stderr.
"""

import json

from mcp.server.fastmcp import FastMCP

import client

mcp = FastMCP("fathom")


def _fail(exc):
    """Turn a client error into a sentence the model can act on."""
    return f"fathom could not complete that read. {exc}"


def _rows(items, fields, limit=20):
    """Render a list of dicts as aligned rows, newest first."""
    if not isinstance(items, list) or not items:
        return "  (nothing in this window)"
    lines = []
    for item in items[:limit]:
        if not isinstance(item, dict):
            continue
        cells = []
        for key in fields:
            value = item.get(key)
            if value is None:
                value = ""
            cells.append(str(value)[:40])
        lines.append("  " + "  ".join(cells))
    if len(items) > limit:
        lines.append(f"  ... {len(items) - limit} more not shown")
    return "\n".join(lines)


def _summary(value):
    """Render one dict as key and value lines, for payloads that are not lists."""
    if not isinstance(value, dict):
        return f"  {value}"
    lines = []
    for key, item in value.items():
        if isinstance(item, (list, dict)):
            lines.append(f"  {key}: {json.dumps(item)[:200]}")
        else:
            lines.append(f"  {key}: {item}")
    return "\n".join(lines[:25])


@mcp.tool()
def list_anomalies(hours: int = 24, limit: int = 20) -> str:
    """List what the detectors flagged recently, newest first.

    Use this first when asked what looks wrong, what fired, or whether anything
    suspicious has happened. It returns the detector's findings with the host and
    the reason, which is the starting point for every hunt.

    Args:
        hours: how far back to look, in hours. Defaults to 24.
        limit: how many findings to show.

    Returns:
        One line per finding, or a sentence explaining why the read failed.
    """
    try:
        payload = client.anomalies(hours=hours)
    except client.WeirvernError as exc:
        return _fail(exc)

    items = payload.get("anomalies", payload) if isinstance(payload, dict) else payload
    header = f"Anomalies in the last {hours}h:"
    return header + "\n" + _rows(items, ("ts", "host", "hostname", "score", "reason"), limit)


@mcp.tool()
def hunt_flows(host: str = "", port: int = 0, proto: int = 0, hours: int = 1,
               limit: int = 25) -> str:
    """Search flow records for conversations matching a host, port or protocol.

    Use this when asked who talked to whom, whether a host reached somewhere it
    should not have, or what happened on a port. This is the main hunting query:
    filters are ANDed, and an unset filter matches everything.

    Args:
        host: an address to match as either endpoint, or empty for any.
        port: a destination port to match, or 0 for any.
        proto: an IP protocol number (6 TCP, 17 UDP), or 0 for any.
        hours: how far back to search.
        limit: how many conversations to show.

    Returns:
        One line per conversation with time, endpoints, protocol, bytes and
        packets, or a sentence explaining why the search failed.
    """
    params = {"hours": hours}
    if host:
        params["host"] = host
    if port:
        params["port"] = port
    if proto:
        params["proto"] = proto
    try:
        payload = client.flows(**params)
    except client.WeirvernError as exc:
        return _fail(exc)

    items = payload.get("flows", payload) if isinstance(payload, dict) else payload
    scope = " ".join(
        part for part in (
            f"host {host}" if host else "",
            f"port {port}" if port else "",
            f"proto {proto}" if proto else "",
        ) if part
    ) or "no filter"
    header = f"Flows matching {scope} in the last {hours}h:"
    return header + "\n" + _rows(
        items, ("ts", "src", "dst", "dport", "proto", "bytes", "packets"), limit
    )


@mcp.tool()
def get_host_evidence(host: str) -> str:
    """Assemble what is known about one host, as evidence rather than opinion.

    Use this when asked to look at a specific address, to explain a finding, or
    to answer whether something is normal for that host. It returns the identity,
    what it talked to, and the stages a finding would be argued from.

    Args:
        host: the address to assemble evidence for.

    Returns:
        The host's identity and evidence stages, or a sentence explaining why the
        read failed.
    """
    try:
        detail = client.host(host)
        bundle = client.evidence(host=host)
    except client.WeirvernError as exc:
        return _fail(exc)

    parts = [f"Evidence for {host}:"]
    parts.append("identity:")
    parts.append(_summary(detail))
    stages = bundle.get("stages", bundle) if isinstance(bundle, dict) else bundle
    parts.append("stages:")
    if isinstance(stages, dict):
        parts.append(_summary(stages))
    else:
        parts.append(_rows(stages, ("name", "state", "detail")))
    return "\n".join(parts)


@mcp.tool()
def query_zeek(table: str = "dns", hours: int = 24, limit: int = 25) -> str:
    """Read one Zeek log, grouped by host.

    Use this when a flow alone is not enough: DNS to triage for beaconing, conn
    for a connection record, ssl for certificate names, http for requests. Each
    log answers a question the flow record cannot.

    Args:
        table: the Zeek log name, for example dns, conn, ssl, http, files.
        hours: how far back to read.
        limit: how many hosts to show.

    Returns:
        Per-host counts for that log, or a sentence explaining why the read failed.
    """
    try:
        payload = client.zeeklog(table, hours=hours)
    except client.WeirvernError as exc:
        return _fail(exc)

    items = payload.get("hosts", payload) if isinstance(payload, dict) else payload
    header = f"Zeek {table} log, last {hours}h, per host:"
    return header + "\n" + _rows(items, ("host", "hostname", "count"), limit)


@mcp.tool()
def top_talkers(hours: int = 24, limit: int = 10) -> str:
    """Show the shape of the traffic: volume, protocol mix, busiest ports.

    Use this to orient before a hunt, or when asked for an overview of what the
    segment was doing. Destination spread is included because a host talking to
    many destinations is the scan and beacon shape rather than the busy-host shape.

    Args:
        hours: how far back to summarise.
        limit: how many entries per section.

    Returns:
        Three sections: volume over time, protocol mix, and the busiest
        destination ports, or a sentence explaining why the read failed.
    """
    try:
        payload = client.netflow(hours=hours)
    except client.WeirvernError as exc:
        return _fail(exc)

    if not isinstance(payload, dict):
        return _summary(payload)
    parts = [f"Traffic shape over the last {hours}h:"]
    for section in ("volume", "protocols", "ports", "spread"):
        if section not in payload:
            continue
        value = payload[section]
        parts.append(f"{section}:")
        if isinstance(value, list):
            parts.append(_rows(value, ("name", "label", "count", "bytes"), limit))
        else:
            parts.append(_summary(value))
    return "\n".join(parts)


@mcp.tool()
def dns_names(hours: int = 24, limit: int = 25) -> str:
    """List the domain names hosts resolved recently.

    Use this when hunting for command and control, or when asked what a host was
    resolving. Names matter because an address can be reassigned but a
    registration belongs to somebody.

    Args:
        hours: how far back to look.
        limit: how many names to show.

    Returns:
        One line per name with the querying host and count, or a sentence
        explaining why the read failed.
    """
    try:
        payload = client.dns(hours=hours)
    except client.WeirvernError as exc:
        return _fail(exc)

    items = payload.get("names", payload) if isinstance(payload, dict) else payload
    header = f"Names resolved in the last {hours}h:"
    return header + "\n" + _rows(items, ("name", "host", "count", "rcode"), limit)


@mcp.tool()
def alert_audit(hours: int = 24, limit: int = 25) -> str:
    """Read what the alerting decided and what was done about it.

    Use this when asked whether anything was blocked, whether a rule fired, or
    what happened after a finding. This is the record of decisions, not of
    detections, so it answers a different question from list_anomalies.

    Args:
        hours: how far back to read.
        limit: how many decisions to show.

    Returns:
        One line per decision, or a sentence explaining why the read failed.
    """
    try:
        payload = client.review(hours=hours)
    except client.WeirvernError as exc:
        return _fail(exc)

    items = payload.get("decisions", payload) if isinstance(payload, dict) else payload
    header = f"Alert decisions in the last {hours}h:"
    return header + "\n" + _rows(
        items, ("ts", "host", "hostname", "rule", "action", "outcome"), limit
    )


if __name__ == "__main__":
    client._log("fathom MCP server starting on stdio")
    mcp.run()
