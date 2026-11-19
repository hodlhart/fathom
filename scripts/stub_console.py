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
import json
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
        path = self.path.split("?", 1)[0]
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
