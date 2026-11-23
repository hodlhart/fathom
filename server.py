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


def _rows(items, fields, limit=20, wide=()):
    """Render a list of dicts as aligned rows.

    A missing value prints as `-` rather than an empty cell: the hostname column
    is blank on a host the console has not resolved, and a blank cell is
    indistinguishable from a column that was never filled at all.

    Fields named in `wide` are not cut at the column width. A model's `reason` or
    a finding's `detail` is a sentence, and truncating it to 38 characters
    removed the part that says what happened.
    """
    if not isinstance(items, list) or not items:
        return "  (nothing in this window)"
    lines = []
    for item in items[:limit]:
        if not isinstance(item, dict):
            continue
        cells = []
        for key in fields:
            value = item.get(key)
            if value is None or value == "":
                cells.append("-")
                continue
            text = str(value)
            cells.append(text if key in wide else text[:38])
        lines.append("  " + "  ".join(cells))
    if len(items) > limit:
        lines.append(f"  ... {len(items) - limit} more not shown")
    return "\n".join(lines)


def _summary(value, limit=16):
    """Render one dict as key and value lines, for payloads that are not lists.

    Empty fields are omitted rather than printed as `None`. The console sends a
    null for a hostname it has not resolved and an empty reason on a healthy
    route, and a wall of `key: None` buries the fields that do carry an answer.
    """
    if not isinstance(value, dict):
        return f"  {value}"
    lines = []
    for key, item in list(value.items())[:limit]:
        if key in ("available", "reason") and item in (True, "", None):
            continue
        if item is None or item == "" or item == [] or item == {}:
            continue
        if isinstance(item, (list, dict)):
            lines.append(f"  {key}: {json.dumps(item)[:160]}")
        else:
            lines.append(f"  {key}: {item}")
    return "\n".join(lines) or "  (nothing to report)"


def _points(value):
    """The rows inside a section, whether the console sends a list or a {points: []} envelope.

    /api/netflow and /api/zeeklog wrap their rows in a section object with
    `available` and `reason` beside `points`. Reading the section as a dict of
    scalars is what printed a raw JSON blob where a table belonged.
    """
    if isinstance(value, dict):
        for key in ("points", "rows"):
            if isinstance(value.get(key), list):
                return value[key]
        return None
    return value if isinstance(value, list) else None


def _counts(value):
    """Render a counts payload as one short phrase, or an empty string.

    Two shapes reach here: `/api/anomalies` sends {counts: [{severity, count}]}
    and `/api/audit` sends a plain {class: count}. Printing the envelope put a
    Python dict in the middle of the sentence a model reads.
    """
    if isinstance(value, dict):
        rows = value.get("counts")
        if isinstance(rows, list):
            pairs = [
                f"{row.get('severity') or row.get('band') or '?'} {row.get('count')}"
                for row in rows if isinstance(row, dict)
            ]
            if pairs:
                return ", ".join(pairs)
        elif rows:
            return ", ".join(f"{key} {count}" for key, count in list(rows.items())[:8])
        plain = [f"{key} {count}" for key, count in list(value.items())[:8]
                 if key not in ("available", "reason")]
        if plain and not rows:
            return ", ".join(plain)
        return ""
    if value:
        return str(value)[:80]
    return ""


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
    counts = _counts(payload.get("severity_counts"))
    if counts:
        header += f", severity counts {counts}"
    if payload.get("watch_error"):
        header += f", watch error: {str(payload['watch_error'])[:80]}"
    # src_addr, not hostname: /api/anomalies carries the address on every row and
    # resolves `hostname` only sometimes. The row used to render the hostname
    # column, which printed blank beside every live finding.
    body = _rows(rows, ("detected_at", "src_addr", "anomaly_score", "confidence",
                        "detected_by_models"), limit, wide=("detected_by_models",))
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
        One line per conversation with its endpoints, port and volume, or a sentence
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
    if payload.get("available") is False:
        return f"Flow data is unavailable: {payload.get('reason') or 'no reason given'}"
    rows = payload.get("points") or []
    scope = " ".join(part for part in (
        f"src {src}" if src else "", f"port {port}" if port else "",
        f"proto {proto}" if proto else "") if part)
    header = f"Flows for {scope} in the last {hours}h"
    if payload.get("total_flows") is not None:
        header += f" ({payload.get('total_flows')} flows, {payload.get('total_pairs')} pairs)"
    if payload.get("truncated"):
        header += ", truncated"
    # The route returns aggregated conversations: no per-flow timestamp and no
    # protocol on the point, so asking for those columns printed blanks.
    return header + ":\n" + _rows(
        rows, ("src_addr", "dst_addr", "dst_port", "bytes", "flows"), limit
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
                       ("dst_addr", "hostname", "bytes", "flows", "ports"), 8))
    parts.append("top ports:")
    parts.append(_rows(detail.get("top_ports"), ("dst_port", "proto", "bytes", "flows"), 8))
    services = detail.get("zeek_services")
    if isinstance(services, list) and services:
        parts.append("zeek services:")
        parts.append(_rows(services, ("service", "conns", "bytes"), 6))
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
    if bundle.get("notice") and isinstance(bundle["notice"], str):
        parts.append(f"  notice: {bundle['notice']}")
    # Each stage has its own record shape, so each gets its own columns. The
    # generic name/state/detail/value set printed blank rows beside real Zeek
    # records, which is exactly the "looks empty" failure this bundle exists to
    # prevent.
    columns = {
        "flows": ("src_addr", "dst_addr", "dst_port", "bytes", "flows"),
        "zeek_conn": ("ts", "dst_addr", "dst_port", "proto", "service", "conn_state"),
        "zeek_ssl": ("ts", "dst_addr", "dst_port", "version", "server_name",
                     "validation_status"),
        "zeek_dns": ("ts", "dst_addr", "query", "qtype_label", "rcode_label"),
        "notice": ("ts", "note", "msg", "src_addr"),
    }
    # No arbitrary prefix here: the bundle carries the anomaly, the flow summary,
    # freshness per source and one list per Zeek log, and a ten-key cut dropped
    # the DNS and notice sections entirely.
    for key, value in bundle.items():
        if key == "notice" and isinstance(value, str):
            continue
        if isinstance(value, list):
            parts.append(f"{key}: {len(value)} item(s)")
            parts.append(_rows(value, columns.get(key, ("name", "state", "detail", "value")), 6))
        elif isinstance(value, dict):
            parts.append(f"{key}:")
            parts.append(_summary(value))
        elif value is not None and value != "":
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
    if isinstance(payload, dict) and payload.get("available") is False:
        return f"Zeek {log} is unavailable: {payload.get('reason') or 'no reason given'}"
    # The live route answers {log, table, hours, points: [{addr, n, name}]}. The
    # old code looked for rows/hosts, found neither, and printed the envelope as a
    # JSON blob where a table belonged.
    rows = _points(payload)
    if rows is not None:
        return header + "\n" + _rows(rows, ("addr", "n", "name"), limit)
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
    # Every netflow section is {available, reason, points}, and the columns differ
    # by section. Reading a section as a flat dict printed the whole JSON envelope
    # under the heading instead of the rows it wraps.
    columns = {
        "protocols": ("proto", "label", "bytes", "flows"),
        "ports": ("port", "proto", "bytes", "flows"),
        "volume": ("t", "bytes", "flows"),
        "spread": ("src_addr", "destinations", "flows"),
        "noise": ("flows", "bytes"),
    }
    for section, fields in columns.items():
        value = payload.get(section)
        if not value:
            continue
        points = _points(value)
        if isinstance(points, list):
            if not points:
                continue
            parts.append(f"{section}:")
            parts.append(_rows(points, fields, limit))
        elif isinstance(value, dict):
            parts.append(f"{section}:")
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
    """Read the pipeline's self-audit: what the console says is wrong with it.

    Use this when asked whether the deployment is healthy, whether a sensor has
    gone silent, whether a rule expired, or why a finding might be missing. This
    is the console auditing itself rather than the traffic: it answers "is the
    thing that watches the network working", which is a different question from
    what the detectors found.

    Args:
        hours: how far back to read.
        limit: how many findings to show.

    Returns:
        One line per finding with its severity, class, subject and detail, or a
        sentence explaining why the read failed.
    """
    try:
        payload = client.audit(hours=hours)
    except client.WeirvernError as exc:
        return _fail(exc)

    if not isinstance(payload, dict):
        return _summary(payload)
    if not payload.get("available", True):
        return f"The pipeline audit is unavailable: {payload.get('reason', 'no reason given')}"
    findings = payload.get("findings")
    header = f"Pipeline audit for the last {hours}h"
    counts = _counts(payload.get("counts"))
    if counts:
        header += f", counts {counts}"
    if payload.get("errors"):
        header += f", unreadable checks {_counts(payload['errors'])}"
    if isinstance(findings, list):
        return header + ":\n" + _rows(
            findings, ("severity", "class", "subject", "detail"), limit, wide=("detail",))
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
        "Duration: "
        + ("indefinite" if not prop.get("ttl_minutes") else str(prop["ttl_minutes"]) + " min")
        + "."
    )


@mcp.tool()
def list_ripples(hours: int = 24, limit: int = 10) -> str:
    """Show correlated findings: what grouped into an incident, and the evidence under it.

    A ripple is several pieces of evidence that line up in one time window on one host, each
    measured against that host's own trailing history. START HERE rather than from the raw alert
    list: the detectors have already done the correlation, and re-deriving it from individual
    decisions wastes the context and tends to miss the grouping.

    How one forms, in the engine's own terms: two or more distinct FAMILIES significant at
    p <= 0.01 in the same window, or exactly one family at p <= 0.001. The second case is reported
    as a single family with nothing corroborating it, which is a weaker statement than it looks.

    `score` is the joint surprise, the sum of -log10(p) over the significant families, so it ranks
    ripples and is not a probability. `combined_p` is the calibrated combination of the same
    p-values. `severity` is the engine's own band over those two, not a judgement this tool makes.

    A low combined_p is the strength of the group, not the severity of the traffic. The
    explanation says what changed and in which direction.

    Args:
        hours: how far back to look, 1 to 168. Grouping windows are short, so 24 is usually
            enough and a week is rarely useful.
        limit: how many ripples to return, newest first.

    Returns:
        The ripples with their host, score, severity, families, combined p-value and explanation,
        each followed by its strongest evidence. When the evidence cannot be read it says so in
        those words: that is a different answer from "no ripple formed", and treating the two as
        the same is how a broken query gets reported as a quiet network.
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
        # FOUR DIFFERENT FACTS USED TO PRODUCE THE SAME SENTENCE. The payload now carries the
        # measurement counts behind the empty list, so which of these it is can be said instead of
        # guessed: nothing was measured, nothing measured was in a monitored network, the baselines
        # were too short to judge, or it was measured and nothing grouped. An operator asked to act
        # on "no ripple" deserves to know which one they are looking at.
        counts = payload.get("evidence") or {}
        rows = int(counts.get("rows") or 0)
        in_scope = int(counts.get("monitored_rows") or 0)
        subjects = int(counts.get("subjects") or 0)
        short = int(counts.get("baseline_short_rows") or 0)
        undecided = int(counts.get("insufficient_rows") or 0)

        # WHAT THE DEPLOYMENT COULD MEASURE AT ALL. A scale is only usable when its lookback
        # holds enough windows, and the lookback is derived from the retention in force, so a
        # short retention quietly removes scales. Without this the reader cannot tell "nothing
        # lined up" from "only one scale was even available, so nothing could corroborate".
        retention = payload.get("retention") or {}
        retention_days = retention.get("days")
        methods = payload.get("methods") or {}
        scales = sorted((methods.get("by_scale") or {}).keys())
        scale_note = ""
        if scales:
            scale_note = f" Scales measured: {', '.join(scales)}"
            if retention_days is not None:
                scale_note += f" (retention {retention_days}d, source: {retention.get('source')})"
            scale_note += (
                ". One scale is enough when two families line up at it, but a "
                "deployment holding a short retention may only be able to see one."
              if len(scales) == 1
              else "."
            )

        if rows == 0:
            return (
                f"Nothing was measured in the last {window}h: the evidence table has no rows in "
                "this window, so this is not a statement that the network was quiet. It means the "
                "measurement did not run or returned nothing to judge."
            )
        if in_scope == 0:
            return (
                f"No ripple formed, and the reason is scope: {rows} evidence rows were measured "
                "in the last "
                f"{window}h but none belong to a monitored host, so nothing could be grouped. "
                "Check which networks the console is monitoring before reading anything into this."
            )
        if undecided == in_scope:
            return (
                f"No ripple formed and none could have: all {in_scope} measured rows on "
                f"{subjects} host(s) were marked insufficient, so the test did not have enough "
                "samples to decide either way. This is a measurement gap, not a quiet network."
            )
        if short == in_scope:
            return (
                f"No ripple formed: all {in_scope} measured rows on {subjects} host(s) had a "
                "baseline too short to judge, so no p-value was attainable. The lookback is the "
                "limit here, not the traffic."
            )
        return (
            f"No ripple formed in the last {window}h, though {in_scope} evidence rows across "
            f"{subjects} monitored host(s) were measured"
            + (
                f" ({short} of them had a baseline too short to judge)"
                if short
                else ""
            )
            + ". That is a measured empty result rather than a missing one: nothing lined up "
            "strongly enough on one host in one window. Check list_anomalies or top_talkers before "
            "concluding a host was idle."
            + scale_note
        )

    # THE ROUTE IS STILL BEING BUILT, so its shape can move under this tool. Every field below is
    # read with .get(), which means a renamed key would print a blank line and look like a quiet
    # ripple instead of a broken assumption. These three are the ones a ripple is useless without,
    # so their absence is reported as the contract change it is.
    required = ("host", "score", "explanation")
    thin = [r for r in found if not all(r.get(k) not in (None, "") for k in required)]
    if thin:
        missing = sorted({k for r in thin for k in required if r.get(k) in (None, "")})
        return (
            "The console returned ripples in a shape fathom does not understand: "
            f"{len(thin)} of {len(found)} are missing {', '.join(missing)}. The ripple route is "
            "still being built, so its payload may have changed. Treat this as no answer rather "
            "than an empty one, and re-check the route's shape."
        )

    lines = [f"Ripples in the last {window}h, newest first ({len(found)} found):"]
    for ripple in found[: max(1, limit)]:
        channels = ", ".join(ripple.get("channels") or [])
        families = ", ".join(ripple.get("families") or [])
        severity = str(ripple.get("severity") or "").strip()
        # ONE FAMILY IS NOT CORROBORATION. A ripple can form on a single family when that family
        # clears the extreme bar, and calling that "an incident with three signals" would overstate
        # it. The engine flags it, so the line does too.
        corroboration = (
            "one family only, corroborated by nothing else"
            if ripple.get("single_family")
            else f"{len(ripple.get('families') or [])} independent families: {families}"
        )
        lines.append("")
        lines.append(
            f"  {ripple.get('host') or '?'} at {ripple.get('window_start') or '?'} "
            f"score {ripple.get('score')} p={ripple.get('combined_p')}"
          + (f" severity {severity}" if severity else "")
          + f" [{channels}]"
        )
        lines.append(f"    {corroboration}")
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
# `@mcp.tool()` written after it never executes and its tool is never registered. That is exactly
# what happened to `propose_block`: the file served 8 tools and silently omitted the 9th.
if __name__ == "__main__":
    client._log("fathom MCP server starting on stdio")
    mcp.run()
