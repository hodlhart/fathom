# INF601 - Advanced Programming in Python
# Samuel Hart
# Final Project

"""A stand-in Weirvern console, so fathom can be exercised without one.

WHY THIS EXISTS. Once the console mints tokens, a tool that fails could be
failing for three different reasons: the address is wrong, the credential is
wrong, or the tool itself is broken. Debugging those at once is how an afternoon
disappears. This serves the shapes fathom reads, so every tool can be driven end
to end before a token exists and the only variable left later is the credential.

It is a fixture, not a simulation. The payloads below were transcribed from a
running console (2026-11-23) and then rewritten onto RFC 5737 documentation
addresses, so the field names are the console's and no real host is described. An
unknown path still answers 404 rather than inventing a shape: a stub that guesses
is a stub that hides drift.

Run it standalone if you want to poke at it with curl:

    .venv/bin/python scripts/stub_console.py --port 8899
"""

from __future__ import annotations

import argparse
import copy
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Documentation addresses only (RFC 5737). One host carries the story so a
# reader can follow a single investigation from anomaly to proposal.
HOST = "192.0.2.10"
PEER = "192.0.2.11"
RESOLVER = "192.0.2.53"
C2 = "198.51.100.66"
CDN = "203.0.113.20"
WINDOW = "2026-11-19T10:00:00"
WINDOW_START = "2026-11-19T09:45:00"

ANOMALIES = [
    {
        "detected_at": WINDOW,
        "window_start": WINDOW_START,
        "src_addr": HOST,
        "hostname": "",
        "anomaly_score": 0.94,
        "confidence": 0.91,
        "severity": "high",
        "detected_by_models": "Isolation Forest,Adaptive Baseline",
        "model_agreement": 0.8,
        "primary_deviation_feature": "conn_volume",
    },
    {
        "detected_at": WINDOW,
        "window_start": WINDOW_START,
        "src_addr": PEER,
        "hostname": "",
        "anomaly_score": 0.61,
        "confidence": 0.54,
        "severity": "medium",
        "detected_by_models": "LOF",
        "model_agreement": 0.4,
        "primary_deviation_feature": "unique_destinations",
    },
]

# The console wraps the severity tally, and the counts are rows rather than a
# bare mapping. The header used to print the whole envelope.
SEVERITY_COUNTS = {
    "available": True,
    "reason": "",
    "counts": [
        {"severity": "high", "count": 1},
        {"severity": "medium", "count": 1},
    ],
}

FLOWS = [
    {"src_addr": HOST, "dst_addr": C2, "dst_port": 443, "bytes": 812, "flows": 42},
    {"src_addr": HOST, "dst_addr": RESOLVER, "dst_port": 53, "bytes": 140, "flows": 9},
    {"src_addr": PEER, "dst_addr": HOST, "dst_port": 445, "bytes": 4096, "flows": 3},
]

FLOWS_PAYLOAD = {
    "available": True,
    "reason": "",
    "port": 0,
    "proto": 0,
    "hours": 24,
    "points": FLOWS,
    "total_flows": 54,
    "total_pairs": 3,
    "truncated": False,
}

HOST_DETAIL = {
    "src_addr": HOST,
    "hostname": "",
    "hours": 24,
    "errors": "",
    "totals": {
        "bytes": 5048,
        "packets": 37,
        "flows": 54,
        "unique_destinations": 2,
        "unique_ports": 2,
        "first_seen": WINDOW_START,
        "last_seen": WINDOW,
    },
    "top_destinations": [
        {"dst_addr": C2, "hostname": "", "bytes": 812, "flows": 42, "ports": 1},
        {"dst_addr": RESOLVER, "hostname": "", "bytes": 140, "flows": 9, "ports": 1},
    ],
    "top_ports": [
        {"dst_port": 443, "proto": 6, "bytes": 812, "flows": 42},
        {"dst_port": 53, "proto": 17, "bytes": 140, "flows": 9},
    ],
    "timeline": [
        {"hour": "2026-11-19T09:00:00", "bytes": 2000, "flows": 22},
        {"hour": "2026-11-19T10:00:00", "bytes": 3048, "flows": 32},
    ],
    "anomalies": ANOMALIES[:1],
    "zeek_services": [
        {"service": "ssl", "conns": 42, "bytes": 812},
        {"service": "dns", "conns": 9, "bytes": 140},
    ],
    "external": {"available": True, "addr": HOST, "hours": 24},
    "exposure": {"available": True, "reason": "", "exposure": {}},
}

EVIDENCE = {
    "src_addr": HOST,
    "hostname": "",
    "window_start": WINDOW_START,
    "window_end": WINDOW,
    "anomaly": {
        "anomaly_score": 0.94,
        "severity": "high",
        "detected_by_models": "Isolation Forest,Adaptive Baseline",
        "primary_deviation_feature": "conn_volume",
        "severity_basis": "two independent families",
        "review_state": "open",
    },
    "flow_summary": {
        "bytes": 5048,
        "packets": 37,
        "flows": 54,
        "unique_destinations": 2,
        "unique_ports": 2,
        "first_seen": WINDOW_START,
        "last_seen": WINDOW,
    },
    "source_freshness": {
        "flows": {"state": "fresh", "age_s": 42.0},
        "zeek_conn": {"state": "fresh", "age_s": 51.0},
        "zeek_ssl": {"state": "fresh", "age_s": 51.0},
        "zeek_dns": {"state": "fresh", "age_s": 44.0},
        "zeek_notice": {"state": "fresh", "age_s": 61.0},
    },
    "flows": FLOWS[:1],
    "zeek_conn": [
        {
            "ts": WINDOW,
            "dst_addr": C2,
            "dst_port": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": 0.42,
            "orig_bytes": 180,
            "resp_bytes": 632,
            "conn_state": "SF",
            "hostname": "",
        }
    ],
    "zeek_ssl": [
        {
            "ts": WINDOW,
            "dst_addr": C2,
            "dst_port": 443,
            "version": "TLSv13",
            "server_name": "beacon.example.com",
            "ja4": "t13d1516h2_8daaf6152771_02713d6af862",
            "ja4_orig": "",
            "validation_status": "ok",
            "hostname": "",
        }
    ],
    "zeek_dns": [
        {
            "ts": WINDOW,
            "dst_addr": RESOLVER,
            "query": "beacon.example.com",
            "qtype": 1,
            "qtype_label": "A",
            "rcode": 0,
            "rcode_label": "NOERROR",
        }
    ],
    "notice": [],
    "errors": None,
}

ZEEKLOG = {
    "available": True,
    "reason": "",
    "log": "dns",
    "table": "zeek_dns",
    "hours": 24,
    "points": [
        {"addr": HOST, "n": 42, "name": "beacon.example.com"},
        {"addr": PEER, "n": 9, "name": "cdn.example.com"},
    ],
}

DNS = {
    "available": True,
    "reason": "",
    "rows": [
        {
            "ts": WINDOW,
            "client": HOST,
            "query": "beacon.example.com",
            "qtype": 1,
            "qtype_label": "A",
            "rcode": 0,
            "rcode_label": "NOERROR",
            "answers": "198.51.100.66",
            "answer_ips": [C2],
        },
        {
            "ts": WINDOW,
            "client": PEER,
            "query": "cdn.example.com",
            "qtype": 1,
            "qtype_label": "A",
            "rcode": 0,
            "rcode_label": "NOERROR",
            "answers": "203.0.113.20",
            "answer_ips": [CDN],
        },
    ],
    "total": 2,
    "limit": 25,
    "offset": 0,
    "bucket_s": 60,
    "histogram": [],
    "facets": {},
}

OVERVIEW = {
    "health": {"ok": True, "fetched_at": WINDOW, "checks": []},
    "sensor": {"reported": 1, "running": 1, "stale": 0},
    "anomalies": ANOMALIES,
    "top_talkers": [
        {"src_addr": HOST, "hostname": "", "bytes": 5048, "flows": 54, "destinations": 2},
        {"src_addr": PEER, "hostname": "", "bytes": 4096, "flows": 3, "destinations": 1},
    ],
    "capabilities": {"cluster_available": True, "reason": ""},
    "data_error": "",
}

NETFLOW = {
    "volume": {
        "available": True,
        "reason": "",
        "hours": 24,
        "bucket_s": 900,
        "points": [
            {"t": "2026-11-19T09:00:00", "bytes": 2000, "flows": 22},
            {"t": "2026-11-19T10:00:00", "bytes": 3048, "flows": 32},
        ],
    },
    "protocols": {
        "available": True,
        "reason": "",
        "points": [
            {"proto": 6, "label": "TCP", "bytes": 4908, "flows": 45},
            {"proto": 17, "label": "UDP", "bytes": 140, "flows": 9},
        ],
    },
    "ports": {
        "available": True,
        "reason": "",
        "points": [
            {"port": 443, "proto": 6, "bytes": 812, "flows": 42},
            {"port": 53, "proto": 17, "bytes": 140, "flows": 9},
        ],
    },
    "spread": {
        "available": True,
        "reason": "",
        "points": [
            {"src_addr": HOST, "hostname": "", "destinations": 2, "flows": 54},
            {"src_addr": PEER, "hostname": "", "destinations": 1, "flows": 3},
        ],
    },
    "noise": {"available": True, "reason": "", "flows": 0, "bytes": 0},
    "talkers": {
        "available": True,
        "reason": "",
        "points": [
            {"src_addr": HOST, "hostname": "", "bytes": 5048, "flows": 54, "destinations": 2},
        ],
    },
}

AUDIT = {
    "available": True,
    "reason": "",
    "now": WINDOW,
    # The route is the pipeline auditing itself, so a finding names a class of
    # deployment problem and the console surface that fixes it.
    "findings": [
        {
            "class": "silent_sensor",
            "severity": "warn",
            "subject": "sensor-a",
            "detail": "silent for 2h (stale after 45s)",
            "elapsed_s": 7200,
            "fix": {"view": "weirlings", "sensor": "sensor-a", "label": "open the sensor"},
        },
        {
            "class": "expired_rules",
            "severity": "info",
            "subject": "sluice",
            "detail": "1 blocking rule expired during the window",
            "elapsed_s": None,
            "fix": {"view": "sluice", "label": "open the gate"},
        },
    ],
    "counts": {"silent_sensor": 1, "expired_rules": 1},
    "errors": {},
}

PROPOSALS = {"proposals": [], "total": 0}

# A ripple as weirvern/models/ripple_evidence.overview returns it: a group of evidence for one
# host in one window, each piece carrying its own scale, p-value and the baseline it beat.
RIPPLES = {
    "available": True,
    "reason": "",
    "window_hours": 24,
    "model_version": "ripple-phase1",
    "count": 1,
    "signature_channels": ["conn_volume", "dns_entropy"],
    "severity_bands": {"low": {"min_score": 3.0, "min_families": 1},
                       "medium": {"min_score": 4.0, "min_families": 2},
                       "high": {"min_score": 6.0, "min_families": 3}},
    "retention": {"days": 7, "source": "ttl", "reason": "", "tables": {}, "unknown": []},
    "methods": {"by_method": {"empirical": 2}, "by_scale": {"1h": {"empirical": 2}},
                "tail_scales": [], "tail_kinds": [], "observed_windows": {"1h": 167,
                                                                          "6h": 27,
                                                                          "24h": 6,
                                                                          "7d": 0}},
    "ripples": [
        {
            "host": HOST,
            "window_start": WINDOW_START,
            "window_end": WINDOW,
            "score": 8.31,
            "combined_p": 0.00042,
            "channels": ["conn_volume", "dns_entropy"],
            "families": ["conn", "dns"],
            "single_family": False,
            "severity": "medium",
            "explanation": (
                "connection count rose to twelve times this host's baseline while DNS query "
                "entropy rose, in the same window"
            ),
            "evidence": [
                {
                    "channel": "conn_volume",
                    "family": "conn",
                    "scale": "1h",
                    "model_id": "baseline",
                    "model_version": "1",
                    "score": 0.91,
                    "pvalue": 0.003,
                    "freshness_s": 42.0,
                    "present": True,
                    "host": HOST,
                    "observed_at": WINDOW,
                    "value": 310.0,
                    "baseline_median": 25.0,
                    "sample_count": 167,
                    "coverage": 0.98,
                    "direction": "above",
                },
                {
                    "channel": "dns_entropy",
                    "family": "dns",
                    "scale": "1h",
                    "model_id": "baseline",
                    "model_version": "1",
                    "score": 0.74,
                    "pvalue": 0.012,
                    "freshness_s": 42.0,
                    "present": True,
                    "host": HOST,
                    "observed_at": WINDOW,
                    "value": 3.9,
                    "baseline_median": 2.1,
                    "sample_count": 167,
                    "coverage": 0.98,
                    "direction": "above",
                },
            ],
        }
    ],
}

# The console answers a failed evidence read with 200 and available:false, so the stub can too.
RIPPLES_UNAVAILABLE = {
    "available": False,
    "reason": "could not read the ripple evidence: OperationalError: clickhouse unavailable",
    "window_hours": 24,
    "model_version": "ripple-phase1",
    "count": 0,
    "ripples": [],
}


def ripples_empty(*, rows: int, monitored: int, subjects: int, short: int,
                  insufficient: int = 0) -> dict:
    """An empty ripple list, with the measurement counts that say WHICH kind of empty it is.

    Four different facts used to render as one sentence. The counts are what tells them apart:
    nothing measured, nothing measured in scope, baselines too short, or measured and ungrouped.
    """
    return {
        "available": True,
        "reason": "",
        "window_hours": 24,
        "model_version": "ripple-phase1",
        "count": 0,
        "signature_channels": [],
        "severity_bands": {"low": {"min_score": 3.0, "min_families": 1}},
        "retention": {"days": 7, "source": "ttl", "reason": "", "tables": {}, "unknown": []},
        "methods": {"by_method": {}, "by_scale": {"1h": {"empirical": 0}}, "tail_scales": [],
                    "tail_kinds": [], "observed_windows": {"1h": 167, "6h": 27, "24h": 6,
                                                           "7d": 0}},
        "ripples": [],
        "monitored_networks": ["192.0.2.0/24"],
        "baseline": {"1h": {"windows": 167}, "6h": {"windows": 27}},
        "evidence": {
            "rows": rows,
            "monitored_rows": monitored,
            "subjects": subjects,
            "baseline_short_rows": short,
            "insufficient_rows": insufficient,
        },
    }


def _created_proposal(body: dict) -> dict:
    """The shape the console returns from POST /api/proposals.

    Mirrors weirvern/proposals.py: the response wraps the record and the id key
    is `proposal_id`. fathom reads exactly that, so the stub must not drift.
    """
    return {
        "ok": True,
        "proposal": {
            "proposal_id": "bp_00000000deadbeef",
            "proposed_by": body.get("proposed_by") or "agent:unknown",
            "host": body.get("host") or "",
            "reason": body.get("reason") or "",
            "evidence": body.get("evidence") or "",
            "ttl_minutes": int(body.get("ttl_minutes") or 0),
            "status": "proposed",
            "proposed_at": WINDOW,
            "decided_at": "",
            "decided_by": "",
            "rule_id": "",
        },
    }


class Handler(BaseHTTPRequestHandler):
    """Answers the paths fathom calls, and refuses to guess at anything else."""

    server_version = "stub-console/1"

    def log_message(self, format: str, *args) -> None:  # noqa: A002, ANN002
        """Quiet by default. A stub that narrates buries the tool output."""

    def _send(self, payload: object, status: int = 200) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _failure(self, message: str) -> dict:
        """The house error body. Every non-200 answer on the real console is this shape."""
        return {"ok": False, "error": message}

    def do_GET(self) -> None:  # noqa: N802
        path, _, query = self.path.partition("?")
        params = dict(pair.split("=", 1) for pair in query.split("&") if "=" in pair)
        # The unavailable branch is reachable on purpose: hours=999 asks the stub for the shape
        # the console returns when the evidence cannot be read, so a check can prove the tool
        # says "could not read" instead of "none formed".
        if path == "/api/ripples":
            hours = params.get("hours", "")
            # One value per empty case, so the four-way distinction can be tested rather than
            # asserted: 1 nothing measured, 2 measured out of scope, 3 baselines too short,
            # 4 measured in scope and ungrouped, 5 insufficient, 999 unreadable.
            if hours == "999":
                self._send(RIPPLES_UNAVAILABLE)
                return
            if hours == "1":
                self._send(ripples_empty(rows=0, monitored=0, subjects=0, short=0))
                return
            if hours == "2":
                self._send(ripples_empty(rows=120, monitored=0, subjects=0, short=0))
                return
            if hours == "3":
                self._send(ripples_empty(rows=40, monitored=40, subjects=3, short=40))
                return
            if hours == "4":
                self._send(ripples_empty(rows=200, monitored=200, subjects=5, short=0))
                return
            if hours == "5":
                self._send(ripples_empty(rows=66, monitored=66, subjects=22, short=0,
                                         insufficient=66))
                return
            if hours == "6":
                # A single-family ripple: legal in the engine when one family clears the extreme
                # bar, and it must not be presented as corroborated.
                payload = copy.deepcopy(RIPPLES)
                payload["ripples"][0].update({
                    "channels": ["dns_entropy"], "families": ["dns"], "single_family": True,
                    "score": 3.2, "combined_p": 0.0006, "severity": "low",
                })
                payload["count"] = 1
                self._send(payload)
                return
            payload = RIPPLES
            if os.environ.get("STUB_MUTATE_RIPPLES"):
                # STANDS IN FOR THE CONTRACT MOVING. The ripple route is still being built, so a
                # renamed or dropped key is a real possibility. This shape keeps the envelope and
                # strips what a ripple is useless without, which is what a rename looks like from
                # the tool's side.
                payload = copy.deepcopy(RIPPLES)
                for ripple in payload["ripples"]:
                    for key in ("host", "score", "explanation"):
                        ripple.pop(key, None)
            self._send(payload)
            return
        if path == "/api/flows":
            # The console refuses an unfiltered flow query. Answering one here would let a
            # broken tool look correct against the stub and fail against the deployment.
            if not (params.get("src") or params.get("port") or params.get("proto")):
                self._send(self._failure("pass port, proto or src"), status=400)
                return
            payload = copy.deepcopy(FLOWS_PAYLOAD)
            payload["hours"] = int(params.get("hours") or 24)
            self._send(payload)
            return
        if path == "/api/zeeklog":
            payload = copy.deepcopy(ZEEKLOG)
            payload["log"] = params.get("log") or "dns"
            payload["table"] = f"zeek_{payload['log']}"
            self._send(payload)
            return
        routes = {
            "/api/healthz": {"ok": True},
            "/api/session": {"accounts": True, "role": "admin", "via": "token"},
            "/api/overview": OVERVIEW,
            "/api/anomalies": {
                "rows": ANOMALIES,
                "total_unfiltered": len(ANOMALIES),
                "watch_error": "",
                "fused": {},
                "discipline": {},
                "severity_counts": SEVERITY_COUNTS,
                "band_counts": SEVERITY_COUNTS,
            },
            "/api/host": HOST_DETAIL,
            "/api/evidence": EVIDENCE,
            "/api/zeek": ZEEKLOG,
            "/api/netflow": NETFLOW,
            "/api/dns": DNS,
            "/api/audit": AUDIT,
            "/api/write-trail": {"entries": [], "total": 0},
            "/api/proposals": PROPOSALS,
            "/api/episodes": {"episodes": [], "total": 0},
            "/api/incident": {"addr": HOST, "events": []},
        }
        if path in routes:
            self._send(routes[path])
            return
        self._send(self._failure(f"the stub does not serve {path}"), status=404)

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            self._send(self._failure("the body must be a JSON object"), status=400)
            return
        if path == "/api/login":
            # The key is `session`, not `token`: client.py reads `session` from this route.
            self._send({"ok": True, "session": "stub-session-token", "username": "operator",
                        "role": "admin", "must_change": False})
            return
        if path == "/api/proposals":
            if not str(body.get("reason") or "").strip():
                self._send(self._failure("a proposal needs a reason"), status=400)
                return
            self._send(_created_proposal(body), status=201)
            return
        self._send(self._failure(f"the stub does not accept a POST to {path}"), status=404)


def main() -> int:
    parser = argparse.ArgumentParser(description="Serve a stand-in Weirvern console.")
    parser.add_argument("--port", type=int, default=0, help="0 picks a free port")
    parser.add_argument("--quiet", action="store_true", help="do not print the address")
    args = parser.parse_args()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    if not args.quiet:
        host, port = server.server_address[:2]
        print(f"  stub console on http://{host}:{port}", flush=True)
        print("  serving the shapes fathom reads; unknown paths answer 404", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
