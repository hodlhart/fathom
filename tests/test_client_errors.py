"""Every way a console read can fail, and the sentence the model receives."""

from __future__ import annotations

import socket
import ssl
import urllib.error

import pytest

import client


@pytest.fixture
def api(console, monkeypatch):
    monkeypatch.setenv("WEIRVERN_API_URL", console.base)
    monkeypatch.setenv("WEIRVERN_TOKEN", "test-token-value")
    return console


def test_a_401_names_the_credential_and_keeps_the_detail(api):
    api.route("/api/overview", status=401, payload={"error": "session expired"})

    with pytest.raises(client.WeirvernError) as caught:
        client.overview()

    message = str(caught.value)
    assert "refused the credential (401)" in message
    assert "session expired" in message


def test_a_403_names_the_role(api):
    api.route("/api/proposals", status=403, payload={"error": "admin access is required"})

    with pytest.raises(client.WeirvernError) as caught:
        client.propose_block("192.0.2.10", "steady beacon")

    message = str(caught.value)
    assert "refused this read for that account (403)" in message
    assert "admin access is required" in message


def test_a_404_names_the_missing_resource(api):
    api.route("/api/host", status=404, payload={"error": "no such host"})

    with pytest.raises(client.WeirvernError) as caught:
        client.host("192.0.2.99")
    assert "No such Weirvern resource (404)" in str(caught.value)


def test_any_other_status_is_reported_with_its_code(api):
    api.route("/api/overview", status=500, payload={"error": "the database is down"})

    with pytest.raises(client.WeirvernError) as caught:
        client.overview()

    message = str(caught.value)
    assert "Weirvern returned 500" in message
    assert "the database is down" in message


def test_a_non_json_error_body_still_produces_a_sentence(api):
    api.route("/api/overview", status=502, raw=b"<html>bad gateway</html>",
              content_type="text/html")

    with pytest.raises(client.WeirvernError) as caught:
        client.overview()

    message = str(caught.value)
    assert "Weirvern returned 502" in message
    assert "bad gateway" in message


def test_a_malformed_json_answer_is_named_as_such(api):
    api.route("/api/overview", raw=b"<html>this is not json</html>", content_type="text/html")

    with pytest.raises(client.WeirvernError) as caught:
        client.overview()
    assert "not JSON" in str(caught.value)


def test_an_empty_answer_is_an_empty_mapping(api):
    api.route("/api/overview", raw=b"")
    assert client.overview() == {}


def test_a_timeout_is_reported_as_unreachable(api, monkeypatch):
    def fake_urlopen(request, timeout=None, context=None):
        raise urllib.error.URLError(socket.timeout("timed out"))

    monkeypatch.setattr(client.urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(client.WeirvernError) as caught:
        client.overview()

    message = str(caught.value)
    assert "Could not reach Weirvern" in message
    assert "timed out" in message
    assert "WEIRVERN_API_URL" in message


def test_a_refused_connection_is_reported_as_unreachable(api, monkeypatch):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    monkeypatch.setenv("WEIRVERN_API_URL", f"http://127.0.0.1:{port}")

    with pytest.raises(client.WeirvernError) as caught:
        client.overview()
    assert "Could not reach Weirvern" in str(caught.value)


def test_a_certificate_problem_points_at_the_ca_bundle(api, monkeypatch):
    def fake_urlopen(request, timeout=None, context=None):
        raise urllib.error.URLError(
            ssl.SSLCertVerificationError("certificate verify failed: unable to get local issuer"))

    monkeypatch.setattr(client.urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(client.WeirvernError) as caught:
        client.overview()

    message = str(caught.value)
    assert "certificate is not trusted" in message
    assert "WEIRVERN_CA_BUNDLE" in message
