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

The field names below are the API's, measured against a running console rather
than assumed. The first draft guessed at several of them and the tools printed
blanks without complaining.

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
    """Render a list of dicts as aligned rows."""
    if not isinstance(items, list) or not items:
        return "  (nothing in this window)"
    lines = []
    for item in items[:limit]:
        if not isinstance(item, dict):
            continue
        cells = []
        for key in fields:
            value = item.get(key)
            cells.append("" if value is None else str(value)[:38])
        lines.append("  " + "  ".join(cells))
    if len(items) > limit:
        lines.append(f"  ... {len(items) - limit} more not shown")
    return "\n".join(lines)


def _summary(value, limit=16):
    """Render one dict as key and value lines, for payloads that are not lists."""
    if not isinstance(value, dict):
        return f"  {value}"
    lines = []
    for key, item in list(value.items())[:limit]:
        if isinstance(item, (list, dict)):
            lines.append(f"  {key}: {json.dumps(item)[:160]}")
        else:
            lines.append(f"  {key}: {item}")
    return "\n".join(lines)


@mcp.tool()
def list_anomalies(hours: int = 24, limit: int = 20) -> str:
    """List what the detectors flagged recently, highest score first.

    Use this first when asked what looks wrong, what fired, or whether anything
    suspicious has happened. It returns each finding with the host, the score and
    which models voted for it, and that is the starting point for a hunt.

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

    if not isinstance(payload, dict):
        return _summary(payload)
    rows = payload.get("rows") or []
    header = f"Anomalies in the last {hours}h"
    if payload.get("severity_counts"):
        header += f", severity counts {payload['severity_counts']}"
    if payload.get("watch_error"):
        header += f", watch error: {str(payload['watch_error'])[:80]}"
    body = _rows(rows, ("detected_at", "hostname", "anomaly_score", "confidence",
                        "detected_by_models"), limit)
    return header + ":\n" + body


@mcp.tool()
def hunt_flows(src: str = "", port: int = 0, proto: int = 0, hours: int = 24,
               limit: int = 25) -> str:
    """Search flow records for one host, one port or one protocol.

    Use this when asked who a host talked to, whether it reached somewhere it
    should not have, or what happened on a port. The console refuses an
    unfiltered flow query, so pass at least one of src, port or proto.

    Args:
        src: the source address to match. Usually what you want.
        port: a destination port, or 0 for any.
        proto: an IP protocol number (6 TCP, 17 UDP), or 0 for any.
        hours: how far back to search.
        limit: how many records to show.

    Returns:
        One line per flow with time, endpoints, port and volume, or a sentence
        explaining why the search failed.
    """
    if not (src or port or proto):
        return (
            "fathom needs a filter: pass src (a host address), port, or proto. "
            "The console refuses an unfiltered flow query on purpose, because it "
            "would return the whole segment."
        )
    try:
        payload = client.flows(src=src or None, port=port or None,
                               proto=proto or None, hours=hours)
    except client.WeirvernError as exc:
        return _fail(exc)

    if not isinstance(payload, dict):
        return _summary(payload)
    rows = payload.get("points") or []
    scope = " ".join(part for part in (
        f"src {src}" if src else "", f"port {port}" if port else "",
        f"proto {proto}" if proto else "") if part)
    header = f"Flows for {scope} in the last {hours}h"
    if payload.get("total_flows") is not None:
        header += f" ({payload.get('total_flows')} flows, {payload.get('total_pairs')} pairs)"
    if payload.get("truncated"):
        header += ", truncated"
    return header + ":\n" + _rows(
        rows, ("ts", "src_addr", "dst_addr", "dst_port", "proto", "bytes", "packets"), limit
    )


@mcp.tool()
def get_host(addr: str) -> str:
    """Show what is known about one host: name, volume, peers, ports, timeline.

    Use this when asked to look at a specific address, or to decide whether
    something is normal for that host. This is the conversation-level view. For
    the evidence behind one specific finding, use get_finding_evidence.

    Args:
        addr: the address to describe.

    Returns:
        The host's name, totals, top destinations and ports, or a sentence
        explaining why the read failed.
    """
    try:
        detail = client.host(addr)
    except client.WeirvernError as exc:
        return _fail(exc)

    if not isinstance(detail, dict):
        return _summary(detail)
    title = f"Host {addr}"
    if detail.get("hostname"):
        title += f" ({detail['hostname']})"
    parts = [title + ":", "totals:", _summary(detail.get("totals") or {})]
    parts.append("top destinations:")
    parts.append(_rows(detail.get("top_destinations"),
                       ("dst_addr", "hostname", "bytes", "flows"), 8))
    parts.append("top ports:")
    parts.append(_rows(detail.get("top_ports"), ("dst_port", "proto", "bytes", "flows"), 8))
    if detail.get("errors"):
        parts.append(f"note: {str(detail['errors'])[:200]}")
    return "\n".join(parts)


@mcp.tool()
def get_finding_evidence(addr: str, start: str) -> str:
    """Assemble the evidence behind one finding, as the console argues it.

    Use this when a specific detection needs defending, or when asked what proof
    exists for a finding. It needs the moment the finding covers, which
    list_anomalies reports as detected_at, because evidence is assembled around a
    moment rather than around a host in general.

    Args:
        addr: the address the finding is about.
        start: the finding's window start, as detected_at reports it.

    Returns:
        The evidence stages, or a sentence explaining why the read failed.
    """
    try:
        bundle = client.evidence(addr, start)
    except client.WeirvernError as exc:
        return _fail(exc)

    if not isinstance(bundle, dict):
        return _summary(bundle)
    parts = [f"Evidence for {addr} from {start}:"]
    for key, value in list(bundle.items())[:10]:
        if isinstance(value, list):
            parts.append(f"{key}: {len(value)} item(s)")
            parts.append(_rows(value, ("name", "state", "detail", "value"), 6))
        elif isinstance(value, dict):
            parts.append(f"{key}:")
            parts.append(_summary(value))
        else:
            parts.append(f"  {key}: {value}")
    return "\n".join(parts)


@mcp.tool()
def query_zeek(log: str = "dns", hours: int = 24, limit: int = 25) -> str:
    """Read one Zeek log.

    Use this when a flow alone is not enough: dns to triage beaconing, conn for
    connection records, ssl for certificate names, http for requests, files for
    transfers. Each log answers a question the flow record cannot.

    Args:
        log: the Zeek log name, for example dns, conn, ssl, http, files.
        hours: how far back to read.
        limit: how many entries to show.

    Returns:
        Entries from that log, or a sentence explaining why the read failed.
    """
    try:
        payload = client.zeeklog(log, hours=hours)
    except client.WeirvernError as exc:
        return _fail(exc)

    header = f"Zeek {log} log, last {hours}h:"
    if isinstance(payload, dict):
        rows = payload.get("rows") or payload.get("hosts")
        if isinstance(rows, list):
            return header + "\n" + _rows(rows, ("host", "hostname", "count", "name"), limit)
    if isinstance(payload, list):
        return header + "\n" + _rows(payload, ("host", "hostname", "count", "name"), limit)
    return header + "\n" + _summary(payload)


@mcp.tool()
def top_talkers(hours: int = 24, limit: int = 10) -> str:
    """Show the shape of the traffic: who is loudest, protocol mix, busiest ports.

    Use this to orient before a hunt, or when asked what the segment was doing.
    Destination spread is included because a host talking to many destinations is
    the scan and beacon shape rather than the busy-host shape.

    Args:
        hours: how far back to summarise.
        limit: how many entries per section.

    Returns:
        The busiest talkers, protocol mix and top ports, or a sentence explaining
        why the read failed.
    """
    try:
        payload = client.netflow(hours=hours)
        dashboard = client.overview()
    except client.WeirvernError as exc:
        return _fail(exc)
    if not isinstance(payload, dict):
        return _summary(payload)

    parts = [f"Traffic shape over the last {hours}h:", "busiest talkers:"]
    # The per-host rows are on the dashboard summary, not in the netflow payload,
    # whose sections are all aggregates.
    talkers = dashboard.get("top_talkers") if isinstance(dashboard, dict) else None
    parts.append(_rows(talkers, ("src_addr", "hostname", "bytes", "flows", "destinations"), limit))
    for section in ("protocols", "ports", "volume", "spread", "noise"):
        value = payload.get(section)
        if not value:
            continue
        parts.append(f"{section}:")
        if isinstance(value, list):
            parts.append(_rows(value, ("name", "label", "count", "bytes"), limit))
        else:
            parts.append(_summary(value))
    return "\n".join(parts)


@mcp.tool()
def dns_names(hours: int = 24, limit: int = 25) -> str:
    """List the names hosts resolved recently, for command and control triage.

    Use this when hunting for beaconing, or when asked what a host was looking
    up. Names matter because an address can be reassigned but a registration
    belongs to somebody.

    Args:
        hours: how far back to look.
        limit: how many queries to show.

    Returns:
        One line per query with time, client, name and type, or a sentence
        explaining why the read failed.
    """
    try:
        payload = client.dns(hours=hours)
    except client.WeirvernError as exc:
        return _fail(exc)

    if not isinstance(payload, dict):
        return _summary(payload)
    if not payload.get("available", True):
        return f"DNS data is unavailable: {payload.get('reason', 'no reason given')}"
    rows = payload.get("rows") or []
    header = f"Names resolved in the last {hours}h ({payload.get('total', len(rows))} total):"
    return header + "\n" + _rows(
        rows, ("ts", "client", "query", "qtype_label", "rcode_label"), limit
    )


@mcp.tool()
def alert_audit(hours: int = 24, limit: int = 25) -> str:
    """Read what the alerting decided and what was done about it.

    Use this when asked whether anything was blocked, whether a rule fired, or
    what happened after a finding. This is the record of decisions rather than of
    detections, so it answers a different question from list_anomalies.

    Args:
        hours: how far back to read.
        limit: how many findings to show.

    Returns:
        One line per finding with its decision, or a sentence explaining why the
        read failed.
    """
    try:
        payload = client.audit(hours=hours)
    except client.WeirvernError as exc:
        return _fail(exc)

    if not isinstance(payload, dict):
        return _summary(payload)
    if not payload.get("available", True):
        return f"The audit is unavailable: {payload.get('reason', 'no reason given')}"
    findings = payload.get("findings")
    header = f"Alert audit for the last {hours}h"
    if payload.get("counts"):
        header += f", counts {payload['counts']}"
    if isinstance(findings, list):
        return header + ":\n" + _rows(
            findings, ("detected_at", "hostname", "score", "action", "state", "reason"), limit)
    if isinstance(findings, dict):
        return header + ":\n" + _summary(findings)
    return header + ":\n  (nothing in this window)"


@mcp.tool()
def propose_block(host: str, reason: str, evidence: str = "", ttl_minutes: int = 0) -> str:
    """Propose blocking a host. THIS DOES NOT BLOCK ANYTHING on its own.

    Use this when the evidence points at a host that should be blocked, and say why. The
    proposal is recorded with your reason and evidence, and an operator decides in the console:
    nothing is blocked until a person clicks. That is deliberate, and it is why this tool exists
    at all in a server that is otherwise read-only.

    Be specific and honest in `reason`. An unexplained proposal cannot be reviewed, so it will
    be dismissed, and a proposal that misstates what was seen is worse than none.

    Args:
        host: the address or domain to block, for example 192.0.2.10 or ads.example.com.
        reason: why, in the words you would use to defend it to the operator.
        evidence: what pointed at it, for example an anomaly window, a rule id, or a URL.
        ttl_minutes: how long the block should last. 0 means indefinite.

    Returns:
        A sentence confirming the proposal and its id, or a sentence explaining why it was
        refused. A refusal names the field that was wrong, so it can be corrected and retried.
    """
    try:
        payload = client.propose_block(host, reason, evidence=evidence, ttl_minutes=ttl_minutes)
    except client.WeirvernError as exc:
        return _fail(exc)

    if not isinstance(payload, dict) or not payload.get("ok"):
        return _summary(payload)

    prop = payload.get("proposal") or {}
    return (
        f"Proposed blocking {prop.get('host') or host} (id {prop.get('proposal_id') or '?'}). "
        f"NOTHING IS BLOCKED YET: an operator must apply it in the console. "
        f"Duration: {'indefinite' if not prop.get('ttl_minutes') else str(prop['ttl_minutes']) + ' min'}."
    )


@mcp.tool()
def list_ripples(hours: int = 24, limit: int = 10) -> str:
    """Show correlated findings: what grouped into an incident, and the evidence under it.

    A ripple is several pieces of evidence that line up in one time window on one host, each
    measured against that host's own trailing history with an empirical p-value. START HERE
    rather than from the raw alert list: the detectors have already done the correlation, and
    re-deriving it from individual decisions wastes the context and tends to miss the grouping.

    A low combined_p is the strength of the group, not the severity of the traffic. The
    explanation says what changed and in which direction.

    Args:
        hours: how far back to look, 1 to 168. Grouping windows are short, so 24 is usually
            enough and a week is rarely useful.
        limit: how many ripples to return, newest first.

    Returns:
        The ripples with their host, score, combined p-value, channels and explanation, each
        followed by its strongest evidence. When the evidence cannot be read it says so in
        those words: that is a different answer from "no ripple formed", and treating the two
        as the same is how a broken query gets reported as a quiet network.
    """
    try:
        payload = client.ripples(hours=hours)
    except client.WeirvernError as exc:
        return _fail(exc)

    if not isinstance(payload, dict):
        return _summary(payload)
    if not payload.get("available", True):
        # NOT "no ripples". The read failed, and the operator needs that sentence instead.
        reason = str(payload.get("reason") or "").strip()
        return (
            "The ripple evidence could not be read, so this is NOT a statement that the "
            f"network was quiet. {reason}"
        ).strip()

    found = payload.get("ripples") or []
    window = payload.get("window_hours", hours)
    if not found:
        return (
            f"No ripple formed in the last {window}h. A ripple needs several pieces of "
            "evidence lining up on one host in one window, so a quiet result here is not a "
            "claim that nothing happened: check list_anomalies or top_talkers before "
            "concluding a host was idle."
        )

    lines = [f"Ripples in the last {window}h, newest first ({len(found)} found):"]
    for ripple in found[: max(1, limit)]:
        channels = ", ".join(ripple.get("channels") or [])
        lines.append("")
        lines.append(
            f"  {ripple.get('host') or '?'} at {ripple.get('window_start') or '?'} "
            f"score {ripple.get('score')} p={ripple.get('combined_p')} [{channels}]"
        )
        if ripple.get("explanation"):
            lines.append(f"    {ripple['explanation']}")
        for item in (ripple.get("evidence") or [])[:3]:
            pieces = [str(item.get("channel") or "?")]
            if item.get("scale"):
                pieces.append(f"at {item['scale']}")
            if item.get("direction"):
                pieces.append(str(item["direction"]))
            if item.get("pvalue") is not None:
                pieces.append(f"p={item['pvalue']}")
            if item.get("value") is not None and item.get("baseline_median") is not None:
                pieces.append(f"{item['value']} vs baseline {item['baseline_median']}")
            lines.append("      - " + ", ".join(pieces))
    return "\n".join(lines)


# THE ENTRY POINT GOES LAST, and this is not style. `mcp.run()` blocks forever serving stdio, so any
# `@mcp.tool()` written after it never executes and its tool is never registered. That is exactly what
# happened to `propose_block`: the file served 8 tools and silently omitted the 9th.
if __name__ == "__main__":
    client._log("fathom MCP server starting on stdio")
    mcp.run()
