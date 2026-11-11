# INF601 - Advanced Programming in Python
# Samuel Hart
# Final Project - fathom MCP server

"""HTTP client for the Weirvern read API.

fathom talks to Weirvern over its existing HTTP interface, so it needs no code
from that repository and cannot disturb it. This module holds every detail of
talking to it: the base URL, the credential, the read helpers, and the mapping
from an HTTP failure to a sentence a model can act on.

Authentication uses the account session header, not the deployment-wide operator
token. A session belongs to one signed-in account, is attributable in the audit
log, and can be revoked by signing out. The operator token is a break-glass admin
credential and has no business in a read-only tool.

Nothing here prints to stdout; stdout carries the MCP protocol.
"""

import json
import os
import ssl
import sys
import urllib.error
import urllib.request

# No default on purpose. The deployment address is environment specific and does
# not belong in a repository, so fathom refuses to guess and says so instead.
API_URL_ENV = "WEIRVERN_API_URL"

# The header a Weirvern session travels in. Deliberately not a cookie: a custom
# header cannot be set by a cross-site form, so the session cannot ride along on
# a forged request.
SESSION_HEADER = "X-Weirvern-Session"


def _log(message):
    """Write a diagnostic line to stderr, never to stdout."""
    print(message, file=sys.stderr)


class WeirvernError(Exception):
    """An API call that could not be completed, with a message for the model."""


def _ssl_context():
    """Trust the deployment's own CA when one is supplied, else verify normally.

    Weirvern serves TLS with a certificate from its internal console CA. Pointing
    WEIRVERN_CA_BUNDLE at that certificate keeps verification on; the alternative,
    disabling verification, would make fathom blind to exactly the interception
    it exists to report on.
    """
    bundle = os.environ.get("WEIRVERN_CA_BUNDLE", "").strip()
    if bundle:
        return ssl.create_default_context(cafile=bundle)
    return ssl.create_default_context()


def base_url():
    """The Weirvern base URL, without a trailing slash.

    Raises:
        WeirvernError: if WEIRVERN_API_URL is unset, rather than guessing one.
    """
    url = os.environ.get(API_URL_ENV, "").strip()
    if not url:
        raise WeirvernError(
            f"{API_URL_ENV} is not set. Point it at the Weirvern console, for "
            "example the address you use in a browser."
        )
    return url.rstrip("/")


def _session_token():
    """Return a session token, logging in if only a username and password exist.

    Order of preference:
      1. WEIRVERN_SESSION, a token minted elsewhere and handed in.
      2. WEIRVERN_USERNAME with WEIRVERN_PASSWORD, exchanged at /api/login.

    Returns:
        str: the session token.

    Raises:
        WeirvernError: if no credential is configured, or the login is refused.
    """
    token = os.environ.get("WEIRVERN_SESSION", "").strip()
    if token:
        return token

    username = os.environ.get("WEIRVERN_USERNAME", "").strip()
    password = os.environ.get("WEIRVERN_PASSWORD", "")
    if not username or not password:
        raise WeirvernError(
            "No Weirvern credential is configured. Set WEIRVERN_SESSION to a session "
            "token, or set WEIRVERN_USERNAME and WEIRVERN_PASSWORD so fathom can "
            "sign in for itself."
        )

    payload = _send(
        "POST",
        "/api/login",
        body={"username": username, "password": password},
        token=None,
    )
    token = str(payload.get("session") or "")
    if not token:
        raise WeirvernError("The login succeeded but returned no session token.")
    if payload.get("must_change"):
        raise WeirvernError(
            "This account must change its password before it can read anything. "
            "Sign in through the console once to finish that."
        )
    _log(f"signed in to Weirvern as {payload.get('username', username)}")
    return token


def _send(method, path, body=None, params=None, token=""):
    """Perform one request and return parsed JSON.

    Args:
        method: HTTP method.
        path: absolute API path, for example '/api/flows'.
        body: dict sent as JSON, or None.
        params: dict of query parameters, or None.
        token: session token, or None to send none.

    Returns:
        The decoded JSON body, or {} for an empty response.

    Raises:
        WeirvernError: with a sentence describing what went wrong.
    """
    url = base_url() + path
    if params:
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        if query:
            url = f"{url}?{query}"

    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers[SESSION_HEADER] = token

    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=25, context=_ssl_context()) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        detail = ""
        try:
            detail = str(json.loads(raw).get("error") or "")
        except (ValueError, AttributeError):
            detail = raw.decode("utf-8", "replace")[:200]
        if exc.code == 401:
            raise WeirvernError(
                "Weirvern refused the credential (401). The session token is wrong or "
                f"expired, or the account is not signed in. {detail}".strip()
            ) from exc
        if exc.code == 403:
            raise WeirvernError(
                f"Weirvern refused this read for that account (403). {detail}".strip()
            ) from exc
        if exc.code == 404:
            raise WeirvernError(f"No such Weirvern resource (404). {detail}".strip()) from exc
        raise WeirvernError(
            f"Weirvern returned {exc.code}. {detail}".strip()
        ) from exc
    except urllib.error.URLError as exc:
        reason = exc.reason
        cert_problem = isinstance(reason, ssl.SSLCertVerificationError)
        cert_problem = cert_problem or "CERTIFICATE_VERIFY_FAILED" in str(reason)
        if cert_problem:
            raise WeirvernError(
                f"Weirvern's certificate is not trusted by this machine ({reason}). "
                "Point WEIRVERN_CA_BUNDLE at the console's CA certificate, for example "
                "the ca-bundle.pem next to this file."
            ) from exc
        raise WeirvernError(
            f"Could not reach Weirvern at {base_url()}: {reason}. Check that the "
            "console is running and that WEIRVERN_API_URL is right."
        ) from exc

    if not raw:
        return {}
    try:
        return json.loads(raw)
    except ValueError as exc:
        raise WeirvernError("Weirvern returned something that is not JSON.") from exc


def get(path, params=None, token=None):
    """GET an API path as the configured account."""
    return _send("GET", path, params=params, token=token or _session_token())


# ---------------------------------------------------------------- read helpers
# One function per read surface fathom exposes. Everything above is plumbing;
# these are the only places that know a route name.


def health():
    """Liveness. Open, needs no credential."""
    return _send("GET", "/api/healthz")


def session_state():
    """Whether accounts exist and whether the caller is signed in. Open."""
    return _send("GET", "/api/session")


def overview(token=None):
    """The dashboard summary: fleet state, recent counts, health roll-up."""
    return get("/api/overview", token=token)


def flows(token=None, **filters):
    """Flow records matching the given filters."""
    return get("/api/flows", params=filters, token=token)


def anomalies(token=None, **filters):
    """Detector findings, newest first."""
    return get("/api/anomalies", params=filters, token=token)


def host(host_id, token=None):
    """One host's detail: identity, services, counters."""
    return get("/api/host", params={"id": host_id}, token=token)


def evidence(token=None, **filters):
    """The evidence bundle for a host: the five stages a finding is argued from."""
    return get("/api/evidence", params=filters, token=token)


def zeek(token=None, **filters):
    """Zeek protocol summaries."""
    return get("/api/zeek", params=filters, token=token)


def zeeklog(table, token=None, **filters):
    """Records from one Zeek log, per host."""
    params = dict(filters)
    params["table"] = table
    return get("/api/zeeklog", params=params, token=token)


def netflow(token=None, **filters):
    """NetFlow volume, protocol mix, top ports and destination spread."""
    return get("/api/netflow", params=filters, token=token)


def review(token=None, **filters):
    """The alert audit: what fired, what was done about it."""
    return get("/api/review", params=filters, token=token)


def dns(token=None, **filters):
    """DNS names seen, for triage of beaconing and command and control."""
    return get("/api/dns", params=filters, token=token)


def episodes(token=None, **filters):
    """Correlated activity episodes."""
    return get("/api/episodes", params=filters, token=token)


def incident(token=None, **filters):
    """Incident detail assembled from the surrounding window."""
    return get("/api/incident", params=filters, token=token)
