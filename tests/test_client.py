"""The console client: credential selection, request shapes, and what it sends."""

from __future__ import annotations

import json
import urllib.parse

import pytest

import client


def _query(record: dict) -> dict[str, list[str]]:
    return urllib.parse.parse_qs(urllib.parse.urlsplit(record["path"]).query)


@pytest.fixture
def api(console, monkeypatch):
    """A recording console, with a minted token configured."""
    monkeypatch.setenv("WEIRVERN_API_URL", console.base)
    monkeypatch.setenv("WEIRVERN_TOKEN", "test-token-value")
    return console


def test_base_url_is_required_rather_than_guessed(monkeypatch):
    with pytest.raises(client.WeirvernError) as caught:
        client.base_url()
    assert "WEIRVERN_API_URL is not set" in str(caught.value)


def test_base_url_strips_a_trailing_slash(monkeypatch):
    monkeypatch.setenv("WEIRVERN_API_URL", "https://console.example.com/")
    assert client.base_url() == "https://console.example.com"


def test_a_minted_token_travels_in_the_token_header(api):
    api.route("/api/overview", payload={"hosts": 2})
    assert client.overview() == {"hosts": 2}

    record = api.requests_for("/api/overview")[0]
    assert record["method"] == "GET"
    assert record["headers"]["x-weirvern-token"] == "test-token-value"
    assert "x-weirvern-session" not in record["headers"]


def test_a_token_file_is_read_and_sent(api, monkeypatch, tmp_path):
    token_file = tmp_path / "agent-token"
    token_file.write_text("token-from-a-file\n", encoding="utf-8")
    monkeypatch.delenv("WEIRVERN_TOKEN")
    monkeypatch.setenv("WEIRVERN_TOKEN_FILE", str(token_file))
    api.route("/api/overview", payload={"hosts": 1})

    client.overview()

    sent = api.requests_for("/api/overview")[0]
    assert sent["headers"]["x-weirvern-token"] == "token-from-a-file"


def test_an_empty_token_file_is_refused(api, monkeypatch, tmp_path):
    token_file = tmp_path / "empty-token"
    token_file.write_text("   \n", encoding="utf-8")
    monkeypatch.delenv("WEIRVERN_TOKEN")
    monkeypatch.setenv("WEIRVERN_TOKEN_FILE", str(token_file))

    with pytest.raises(client.WeirvernError) as caught:
        client.overview()
    assert "is empty" in str(caught.value)


def test_a_missing_token_file_names_the_path(api, monkeypatch, tmp_path):
    missing = tmp_path / "nope"
    monkeypatch.delenv("WEIRVERN_TOKEN")
    monkeypatch.setenv("WEIRVERN_TOKEN_FILE", str(missing))

    with pytest.raises(client.WeirvernError) as caught:
        client.overview()
    assert str(missing) in str(caught.value)


def test_a_session_travels_in_the_session_header(api, monkeypatch):
    monkeypatch.delenv("WEIRVERN_TOKEN")
    monkeypatch.setenv("WEIRVERN_SESSION", "session-value")
    api.route("/api/overview", payload={})

    client.overview()

    record = api.requests_for("/api/overview")[0]
    assert record["headers"]["x-weirvern-session"] == "session-value"
    assert "x-weirvern-token" not in record["headers"]


def test_a_token_wins_over_a_session(api, monkeypatch):
    monkeypatch.setenv("WEIRVERN_SESSION", "session-value")
    api.route("/api/overview", payload={})

    client.overview()

    record = api.requests_for("/api/overview")[0]
    assert record["headers"]["x-weirvern-token"] == "test-token-value"
    assert "x-weirvern-session" not in record["headers"]


def test_username_and_password_sign_in_then_use_the_session(api, monkeypatch):
    monkeypatch.delenv("WEIRVERN_TOKEN")
    monkeypatch.setenv("WEIRVERN_USERNAME", "operator")
    monkeypatch.setenv("WEIRVERN_PASSWORD", "not-a-real-password")
    api.route("/api/login", payload={
        "ok": True, "session": "session-from-login", "username": "operator",
        "role": "admin", "must_change": False,
    })
    api.route("/api/overview", payload={"hosts": 3})

    assert client.overview() == {"hosts": 3}

    login, overview = api.records
    assert login["method"] == "POST"
    assert login["body"] == {"username": "operator", "password": "not-a-real-password"}
    assert overview["headers"]["x-weirvern-session"] == "session-from-login"


def test_an_account_that_must_change_its_password_is_refused(api, monkeypatch):
    monkeypatch.delenv("WEIRVERN_TOKEN")
    monkeypatch.setenv("WEIRVERN_USERNAME", "operator")
    monkeypatch.setenv("WEIRVERN_PASSWORD", "not-a-real-password")
    api.route("/api/login", payload={
        "ok": True, "session": "session-from-login", "must_change": True,
    })

    with pytest.raises(client.WeirvernError) as caught:
        client.overview()
    assert "must change its password" in str(caught.value)


def test_no_credential_explains_every_option(console, monkeypatch):
    monkeypatch.setenv("WEIRVERN_API_URL", console.base)

    with pytest.raises(client.WeirvernError) as caught:
        client.overview()
    message = str(caught.value)
    assert "WEIRVERN_TOKEN_FILE" in message
    assert "WEIRVERN_SESSION" in message
    assert "WEIRVERN_USERNAME" in message
    assert console.records == []


def test_flows_sends_only_the_filters_it_was_given(api):
    api.route("/api/flows", payload={"points": []})

    client.flows(src="192.0.2.10", port=443, hours=12)

    query = _query(api.requests_for("/api/flows")[0])
    assert query == {"hours": ["12"], "src": ["192.0.2.10"], "port": ["443"]}


def test_anomalies_forwards_its_filters(api):
    api.route("/api/anomalies", payload={"rows": []})

    client.anomalies(hours=6, limit=5)

    query = _query(api.requests_for("/api/anomalies")[0])
    assert query == {"hours": ["6"], "limit": ["5"]}


def test_host_sends_the_address(api):
    api.route("/api/host", payload={})

    client.host("192.0.2.10")

    assert _query(api.requests_for("/api/host")[0]) == {"addr": ["192.0.2.10"]}


def test_evidence_sends_the_address_and_the_window(api):
    api.route("/api/evidence", payload={})

    client.evidence("192.0.2.10", "2026-11-19T09:45:00")

    query = _query(api.requests_for("/api/evidence")[0])
    assert query == {"addr": ["192.0.2.10"], "start": ["2026-11-19T09:45:00"]}


def test_zeeklog_uses_log_rather_than_table(api):
    api.route("/api/zeeklog", payload={"points": []})

    client.zeeklog("dns", hours=24, limit=5)

    query = _query(api.requests_for("/api/zeeklog")[0])
    assert query == {"log": ["dns"], "hours": ["24"], "limit": ["5"]}


@pytest.mark.parametrize("name,path", [
    ("netflow", "/api/netflow"),
    ("dns", "/api/dns"),
    ("audit", "/api/audit"),
    ("ripples", "/api/ripples"),
])
def test_summary_reads_send_their_window(api, name, path):
    api.route(path, payload={})

    getattr(client, name)(hours=6)

    assert _query(api.requests_for(path)[0]) == {"hours": ["6"]}


def test_propose_block_posts_the_whole_record(api):
    api.route("/api/proposals", status=201, payload={"ok": True, "proposal": {}})

    client.propose_block("192.0.2.10", "steady beacon", evidence="anomaly window", ttl_minutes=60)

    record = api.requests_for("/api/proposals")[0]
    assert record["method"] == "POST"
    assert record["headers"]["content-type"] == "application/json"
    assert record["body"] == {
        "host": "192.0.2.10",
        "reason": "steady beacon",
        "evidence": "anomaly window",
        "ttl_minutes": 60,
        "proposed_by": "agent:fathom",
    }


def test_urlopen_is_given_a_bounded_timeout(api, monkeypatch):
    seen: dict = {}

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return json.dumps({"ok": True}).encode()

    def fake_urlopen(request, timeout=None, context=None):
        seen["timeout"] = timeout
        return _Response()

    monkeypatch.setattr(client.urllib.request, "urlopen", fake_urlopen)

    assert client.health() == {"ok": True}
    assert seen["timeout"] == 25


def test_a_missing_ca_bundle_is_reported_not_raised_as_a_traceback(api, monkeypatch, tmp_path):
    monkeypatch.setenv("WEIRVERN_API_URL", "https://console.example.com")
    monkeypatch.setenv("WEIRVERN_CA_BUNDLE", str(tmp_path / "missing-ca.pem"))

    with pytest.raises(client.WeirvernError) as caught:
        client.health()
    message = str(caught.value)
    assert "Could not load the CA bundle" in message
    assert "missing-ca.pem" in message
