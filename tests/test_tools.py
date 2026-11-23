"""What each tool returns, what it refuses, and what it says when a read fails.

These call the decorated functions directly against a double. The stdio path,
where a real client asks for the tool and the server dispatches it, is covered in
test_server_process.py; this file is about the text the model receives.
"""

from __future__ import annotations

import pytest

import server


def test_list_anomalies_renders_the_address_and_a_readable_severity_tally(stub_env):
    text = server.list_anomalies(hours=24, limit=5)

    assert text.startswith("Anomalies in the last 24h, severity counts high 1, medium 1:")
    assert "192.0.2.10" in text
    assert "Isolation Forest,Adaptive Baseline" in text
    assert "None" not in text
    assert "{" not in text


def test_hunt_flows_renders_conversations(stub_env):
    text = server.hunt_flows(src="192.0.2.10", hours=24, limit=5)

    assert text.startswith("Flows for src 192.0.2.10 in the last 24h (54 flows, 3 pairs):")
    assert "198.51.100.66" in text
    assert "443" in text
    assert "812" in text


def test_hunt_flows_refuses_an_unfiltered_query_without_calling_the_console(console, monkeypatch):
    monkeypatch.setenv("WEIRVERN_API_URL", console.base)
    monkeypatch.setenv("WEIRVERN_SESSION", "test-session")

    text = server.hunt_flows()

    assert "needs a filter" in text
    assert "src" in text and "port" in text and "proto" in text
    assert console.records == []


def test_get_host_reports_totals_destinations_ports_and_services(stub_env):
    text = server.get_host("192.0.2.10")

    assert text.startswith("Host 192.0.2.10:")
    assert "unique_destinations: 2" in text
    assert "top destinations:" in text
    assert "198.51.100.66" in text
    assert "zeek services:" in text
    assert "ssl" in text
    assert "None" not in text


def test_a_host_without_a_name_keeps_its_columns_aligned(stub_env):
    text = server.get_host("192.0.2.10")

    # The console sends hostname: "" for an unresolved host. A blank cell used to
    # collapse the row; a dash keeps the address, bytes and flow count in place.
    assert "  198.51.100.66  -  812  42  1" in text


def test_get_finding_evidence_renders_each_stage(stub_env):
    text = server.get_finding_evidence("192.0.2.10", "2026-11-19T09:45:00")

    assert "Evidence for 192.0.2.10 from 2026-11-19T09:45:00:" in text
    assert "anomaly_score: 0.94" in text
    assert "beacon.example.com" in text          # the ssl and dns stages
    assert "TLSv13" in text
    assert "SF" in text                          # conn_state
    assert "None" not in text


def test_query_zeek_renders_rows_not_the_envelope(stub_env):
    text = server.query_zeek("dns", hours=24, limit=5)

    assert text.startswith("Zeek dns log, last 24h:")
    assert "192.0.2.10  42  beacon.example.com" in text
    assert "points" not in text
    assert "{" not in text


def test_top_talkers_unwraps_every_netflow_section(stub_env):
    text = server.top_talkers(hours=24, limit=5)

    assert "busiest talkers:" in text
    assert "192.0.2.10" in text
    assert "protocols:" in text and "TCP" in text
    assert "ports:" in text and "443" in text
    assert "volume:" in text
    assert "spread:" in text
    assert "{" not in text


def test_dns_names_renders_queries(stub_env):
    text = server.dns_names(hours=24, limit=5)

    assert text.startswith("Names resolved in the last 24h (2 total):")
    assert "beacon.example.com" in text
    assert "NOERROR" in text


def test_alert_audit_reads_the_pipeline_audit_and_keeps_the_detail(stub_env):
    text = server.alert_audit(hours=24, limit=5)

    assert text.startswith(
        "Pipeline audit for the last 24h, counts silent_sensor 1, expired_rules 1:")
    assert "silent_sensor" in text
    assert "sensor-a" in text
    # The whole sentence, not a 38-character stub: this is the part an operator acts on.
    assert "1 blocking rule expired during the window" in text


def test_propose_block_says_what_it_actually_did(stub_env):
    text = server.propose_block("192.0.2.10", "steady beacon", evidence="anomaly window")

    assert "Proposed blocking 192.0.2.10" in text
    assert "bp_00000000deadbeef" in text
    assert "NOTHING IS BLOCKED YET" in text
    assert "indefinite" in text


def test_propose_block_reports_a_finite_ttl(stub_env):
    text = server.propose_block("192.0.2.10", "steady beacon", ttl_minutes=60)
    assert "60 min" in text


def test_list_ripples_reports_corroboration_and_severity(stub_env):
    text = server.list_ripples(hours=24, limit=5)

    assert "score 8.31" in text
    assert "severity medium" in text
    assert "2 independent families: conn, dns" in text
    assert "baseline 25.0" in text


def test_an_unreadable_ripple_set_is_not_reported_as_a_quiet_network(stub_env):
    text = server.list_ripples(hours=999)

    assert "could not be read" in text
    assert "no ripple formed" not in text.lower()


@pytest.mark.parametrize("hours,expected", [
    (1, "nothing was measured"),
    (2, "reason is scope"),
    (3, "too short to judge"),
    (4, "measured empty result"),
    (5, "marked insufficient"),
])
def test_each_kind_of_empty_has_its_own_sentence(stub_env, hours, expected):
    text = server.list_ripples(hours=hours)
    assert expected in text.lower()


def test_a_single_family_ripple_is_not_called_corroborated(stub_env):
    text = server.list_ripples(hours=6)
    assert "one family only, corroborated by nothing else" in text


def test_a_renamed_ripple_field_is_reported_as_a_contract_change(console, monkeypatch):
    monkeypatch.setenv("WEIRVERN_API_URL", console.base)
    monkeypatch.setenv("WEIRVERN_SESSION", "test-session")
    console.route("/api/ripples", payload={
        "available": True,
        "window_hours": 24,
        "count": 1,
        "ripples": [{"window_start": "2026-11-19T09:45:00", "families": ["conn"]}],
    })

    text = server.list_ripples(hours=24)

    assert "shape fathom does not understand" in text
    for field in ("host", "score", "explanation"):
        assert field in text


READ_CALLS = {
    "list_anomalies": lambda: server.list_anomalies(),
    "hunt_flows": lambda: server.hunt_flows(src="192.0.2.10"),
    "get_host": lambda: server.get_host("192.0.2.10"),
    "get_finding_evidence": lambda: server.get_finding_evidence(
        "192.0.2.10", "2026-11-19T09:45:00"),
    "query_zeek": lambda: server.query_zeek(),
    "top_talkers": lambda: server.top_talkers(),
    "dns_names": lambda: server.dns_names(),
    "alert_audit": lambda: server.alert_audit(),
    "list_ripples": lambda: server.list_ripples(),
}


@pytest.mark.parametrize("name", sorted(READ_CALLS))
def test_a_refused_credential_is_a_sentence_in_every_read_tool(console, monkeypatch, name):
    monkeypatch.setenv("WEIRVERN_API_URL", console.base)
    monkeypatch.setenv("WEIRVERN_TOKEN", "wrong-token")
    console.route("/api/anomalies", status=401, payload={"error": "session expired"})
    console.route("/api/flows", status=401, payload={"error": "session expired"})
    console.route("/api/host", status=401, payload={"error": "session expired"})
    console.route("/api/evidence", status=401, payload={"error": "session expired"})
    console.route("/api/zeeklog", status=401, payload={"error": "session expired"})
    console.route("/api/netflow", status=401, payload={"error": "session expired"})
    console.route("/api/overview", status=401, payload={"error": "session expired"})
    console.route("/api/dns", status=401, payload={"error": "session expired"})
    console.route("/api/audit", status=401, payload={"error": "session expired"})
    console.route("/api/ripples", status=401, payload={"error": "session expired"})

    text = READ_CALLS[name]()

    assert "fathom could not complete that read" in text
    assert "401" in text
    assert "Traceback" not in text


def test_a_403_on_propose_block_reads_as_a_role_problem(console, monkeypatch):
    monkeypatch.setenv("WEIRVERN_API_URL", console.base)
    monkeypatch.setenv("WEIRVERN_TOKEN", "readonly-token")
    console.route("/api/proposals", status=403, payload={"error": "admin access is required"})

    text = server.propose_block("192.0.2.10", "steady beacon")

    assert "fathom could not complete that read" in text
    assert "403" in text


def test_the_tools_write_nothing_to_stdout(stub_env, capsys):
    for name, call in READ_CALLS.items():
        text = call()
        assert text, f"{name} returned nothing"
    server.propose_block("192.0.2.10", "steady beacon")

    captured = capsys.readouterr()
    assert captured.out == ""
