# INF601 - Advanced Programming in Python
# Samuel Hart
# Final Project

"""A stand-in Weirvern console, so fathom can be exercised without one.

WHY THIS EXISTS. Once the console mints tokens, a tool that fails could be
failing for three different reasons: the address is wrong, the credential is
wrong, or the tool itself is broken. Debugging those at once is how an afternoon
disappears. This serves the shapes fathom reads, so every tool can be driven end
to end before a token exists and the only variable left later is the credential.

It is a fixture, not a simulation. The payloads are written to match the console's
own wire shapes, and where a shape is unknown the stub answers an empty list
rather than inventing fields that the real API would not send. A tool that works
here is proven to assemble a request and format an answer; it is NOT proof that
the console agrees, which is what the live check is for.

Run it standalone if you want to poke at it with curl:

    .venv/bin/python scripts/stub_console.py --port 8899
"""

from __future__ import annotations

import argparse
import copy
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# One host reused across payloads so a reader can follow a single story.
HOST = "192.0.2.10"
SECOND_HOST = "192.0.2.11"
WINDOW = "2026-11-19T10:00:00"

ANOMALIES = [
    {
        "detected_at": WINDOW,
        "hostname": HOST,
        "score": 0.91,
        "action": "blocked",
        "state": "open",
        "reason": "steady beacon to a single destination, 42 flows, near zero bytes",
    },
    {
        "detected_at": WINDOW,
        "hostname": SECOND_HOST,
        "score": 0.44,
        "action": "observed",
        "state": "open",
        "reason": "port sweep, 300 flows, almost no payload",
    },
]

FLOWS = [
    {
        "src_addr": HOST,
        "dst_addr": SECOND_HOST,
        "dst_port": 443,
        "proto": 6,
        "total_bytes": 812,
        "total_packets": 22,
        "flow_count": 42,
        "window_start": WINDOW,
    },
    {
        "src_addr": SECOND_HOST,
        "dst_addr": HOST,
        "dst_port": 53,
        "proto": 17,
        "total_bytes": 140,
        "total_packets": 6,
        "flow_count": 9,
        "window_start": WINDOW,
    },
]

HOST_DETAIL = {
    "addr": HOST,
    "flows": FLOWS,
    "anomalies": ANOMALIES[:1],
    "first_seen": WINDOW,
    "last_seen": WINDOW,
}

EVIDENCE = {
    "addr": HOST,
    "findings": [
        {
            "detected_at": WINDOW,
            "hostname": HOST,
            "score": 0.91,
            "action": "blocked",
            "state": "open",
            "reason": "steady beacon",
        }
    ],
}

ZEEKLOG = [
    {
        "ts": WINDOW,
        "id_orig_h": HOST,
        "id_resp_h": SECOND_HOST,
        "query": "update.example.com",
        "proto": "udp",
        "service": "dns",
    }
]

DNS = [
    {"query": "update.example.com", "count": 42, "hosts": [HOST]},
    {"query": "cdn.example.net", "count": 9, "hosts": [SECOND_HOST]},
]

TOP_TALKERS = [
    {"addr": HOST, "total_bytes": 4096, "flow_count": 42},
    {"addr": SECOND_HOST, "total_bytes": 1024, "flow_count": 9},
]

AUDIT = {
    "decisions": ANOMALIES,
    "total": len(ANOMALIES),
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
    "signature_channels": ["conn_dst", "dns_query"],
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
            "window_start": WINDOW,
            "window_end": "2026-11-19T10:30:00",
            "score": 8.31,
            "combined_p": 0.00042,
            "channels": ["flow_bytes", "dns_entropy"],
            "families": ["dns", "flow"],
            "single_family": False,
            "severity": "medium",
            "explanation": (
                "outbound bytes fell to a twentieth of this host's baseline while DNS query "
                "entropy rose, in the same window"
            ),
            "evidence": [
                {
                    "channel": "flow_bytes",
                    "family": "volume",
                    "scale": "1h",
                    "model_id": "baseline",
                    "model_version": "1",
                    "score": 0.91,
                    "pvalue": 0.003,
                    "freshness_s": 42.0,
                    "present": True,
                    "host": HOST,
                    "observed_at": WINDOW,
                    "value": 812.0,
                    "baseline_median": 16800.0,
                    "sample_count": 167,
                    "coverage": 0.98,
                    "direction": "down",
                },
                {
                    "channel": "dns_entropy",
                    "family": "shape",
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
                    "direction": "up",
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

    def do_GET(self) -> None:  # noqa: N802
        path, _, query = self.path.partition("?")
        # The unavailable branch is reachable on purpose: hours=999 asks the stub for the shape
        # the console returns when the evidence cannot be read, so a check can prove the tool
        # says "could not read" instead of "none formed".
        if path == "/api/ripples":
            hours = ""
            for pair in query.split("&"):
                if pair.startswith("hours="):
                    hours = pair.split("=", 1)[1]
            # One value per empty case, so the four-way distinction can be tested rather than
            # asserted: 1 nothing measured, 2 measured out of scope, 3 baselines too short,
            # 4 measured in scope and ungrouped, 999 unreadable.
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
        routes = {
            "/api/healthz": {"ok": True},
            "/api/session": {"accounts": True, "role": "admin", "via": "token"},
            "/api/overview": {"hosts": 2, "flows": len(FLOWS)},
            "/api/anomalies": ANOMALIES,
            "/api/flows": FLOWS,
            "/api/host": HOST_DETAIL,
            "/api/evidence": EVIDENCE,
            "/api/zeeklog": ZEEKLOG,
            "/api/zeek": ZEEKLOG,
            "/api/netflow": FLOWS,
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
        self._send({"error": f"the stub does not serve {path}"}, status=404)

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            self._send({"error": "the body must be a JSON object"}, status=400)
            return
        if path == "/api/login":
            self._send({"token": "stub-session-token"}, status=200)
            return
        if path == "/api/proposals":
            if not str(body.get("reason") or "").strip():
                self._send({"error": "a proposal needs a reason"}, status=400)
                return
            self._send(_created_proposal(body), status=201)
            return
        self._send({"error": f"the stub does not accept a POST to {path}"}, status=404)


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
