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

# THE TWO HEADERS ARE NOT INTERCHANGEABLE. A token minted in console Settings is
# read from X-Weirvern-Token; a session issued by /api/login is read from
# X-Weirvern-Session. Sending a token as a session authenticates nothing, and the
# failure is a plain 401 that says nothing about which header was wrong.
TOKEN_HEADER = "X-Weirvern-Token"
TOKEN_ENV = "WEIRVERN_TOKEN"
TOKEN_FILE_ENV = "WEIRVERN_TOKEN_FILE"


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


def _read_secret_file(path: str, what: str) -> str:
    """Read a credential from a file, with an error that names the file.

    A file is preferred over the environment for a long-lived secret: an exported
    variable is readable from /proc/<pid>/environ by anything running as the same
    user, and it survives in shell history if it was set inline.
    """
    try:
        with open(os.path.expanduser(path), encoding="utf-8") as handle:
            value = handle.read().strip()
    except OSError as exc:
        raise WeirvernError(
            f"Could not read the {what} file at {path}: {exc.strerror}."
        ) from exc
    if not value:
        raise WeirvernError(f"The {what} file at {path} is empty.")
    return value


def _credential() -> tuple[str, str]:
    """Return (header name, value) for the credential fathom should present.

    TWO KINDS OF CREDENTIAL, TWO DIFFERENT HEADERS, and mixing them up fails
    silently as a 401. The console reads a token minted in Settings from
    `X-Weirvern-Token` (weirvern/admin/gui_auth.py, AUTH_HEADER) and a login
    session from `X-Weirvern-Session` (SESSION_HEADER). This module used to send
    everything as a session, which is why a minted token would never have
    authenticated.

    Order of preference:
      1. WEIRVERN_TOKEN or WEIRVERN_TOKEN_FILE: a token minted in the console
         Settings tab. It carries a role, it is revocable, and it is the right
         credential for an agent.
      2. WEIRVERN_SESSION or WEIRVERN_SESSION_FILE: a session token from
         /api/login, handed in.
      3. WEIRVERN_USERNAME with WEIRVERN_PASSWORD, exchanged at /api/login now.

    Raises:
        WeirvernError: if no credential is configured, or the login is refused.
    """
    token = os.environ.get(TOKEN_ENV, "").strip()
    if not token:
        path = os.environ.get(TOKEN_FILE_ENV, "").strip()
        if path:
            token = _read_secret_file(path, "token")
    if token:
        return TOKEN_HEADER, token

    session = os.environ.get("WEIRVERN_SESSION", "").strip()
    if session:
        return SESSION_HEADER, session
    path = os.environ.get("WEIRVERN_SESSION_FILE", "").strip()
    if path:
        return SESSION_HEADER, _read_secret_file(path, "session")

    username = os.environ.get("WEIRVERN_USERNAME", "").strip()
    password = os.environ.get("WEIRVERN_PASSWORD", "")
    if not username or not password:
        raise WeirvernError(
            "No Weirvern credential is configured. Set WEIRVERN_TOKEN_FILE to a "
            "file holding a token minted in console Settings, or WEIRVERN_TOKEN to "
            "the token itself. A session from /api/login works through "
            "WEIRVERN_SESSION_FILE or WEIRVERN_SESSION, and WEIRVERN_USERNAME with "
            "WEIRVERN_PASSWORD signs in for you."
        )

    payload = _send(
        "POST",
        "/api/login",
        body={"username": username, "password": password},
        token=None,
    )
    session = str(payload.get("session") or "")
    if not session:
        raise WeirvernError("The login succeeded but returned no session token.")
    if payload.get("must_change"):
        raise WeirvernError(
            "This account must change its password before it can read anything. "
            "Sign in through the console once to finish that."
        )
    _log(f"signed in to Weirvern as {payload.get('username', username)}")
    return SESSION_HEADER, session


def _session_token():
    """The credential value alone, for callers that only need the secret."""
    return _credential()[1]


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
        # A tuple carries its own header, so a minted token and a login session
        # cannot be sent the same way by accident. A bare string is treated as a
        # session, which is what every caller outside _credential() means.
        if isinstance(token, tuple):
            name, value = token
        else:
            name, value = SESSION_HEADER, token
        if value:
            headers[name] = value

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
    return _send("GET", path, params=params, token=token or _credential())


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


def flows(src=None, port=None, proto=None, hours=24, token=None):
    """Flow records for one host or one port. At least one filter is required.

    The API refuses a bare call: it answers 400 asking for port, proto or src.
    """
    params = {"hours": hours}
    if src:
        params["src"] = src
    if port:
        params["port"] = port
    if proto:
        params["proto"] = proto
    return get("/api/flows", params=params, token=token)


def anomalies(token=None, **filters):
    """Detector findings, newest first."""
    return get("/api/anomalies", params=filters, token=token)


def host(addr, token=None):
    """One host's detail: identity, totals, top destinations, ports and timeline."""
    return get("/api/host", params={"addr": addr}, token=token)


def evidence(addr, start, token=None, **filters):
    """The evidence bundle behind one finding.

    Needs the finding's window start as well as the address: evidence is
    assembled around a moment, not around a host in general.
    """
    params = dict(filters)
    params["addr"] = addr
    params["start"] = start
    return get("/api/evidence", params=params, token=token)


def zeek(token=None, **filters):
    """Zeek protocol summaries."""
    return get("/api/zeek", params=filters, token=token)


def zeeklog(log, token=None, **filters):
    """Records from one Zeek log, per host. The parameter is `log`, not `table`."""
    params = dict(filters)
    params["log"] = log
    return get("/api/zeeklog", params=params, token=token)


def netflow(token=None, **filters):
    """NetFlow volume, protocol mix, top ports and destination spread."""
    return get("/api/netflow", params=filters, token=token)


def audit(token=None, **filters):
    """The alert audit: what fired and what was done about it."""
    return get("/api/audit", params=filters, token=token)


def write_trail(token=None, **filters):
    """The record of writes made through the console."""
    return get("/api/write-trail", params=filters, token=token)


def post(path, body, token=None):
    """POST an API path as the configured account. The only write fathom performs."""
    return _send("POST", path, body=body, token=token or _credential())


def propose_block(host, reason, evidence="", ttl_minutes=0, token=None):
    """Ask Weirvern to consider blocking a host. This ENFORCES NOTHING on its own.

    The proposal is recorded with its reason and evidence, and a person decides in the console. That
    split is why an agent is allowed to call this at all: a detector that can block directly can take
    a network away on a bad day.
    """
    return post("/api/proposals", {
        "host": host,
        "reason": reason,
        "evidence": evidence,
        "ttl_minutes": int(ttl_minutes or 0),
        "proposed_by": "agent:fathom",
    }, token=token)


def proposals(token=None, **filters):
    """The proposals, optionally filtered by status."""
    return get("/api/proposals", params=filters, token=token)


def dns(token=None, **filters):
    """DNS names seen, for triage of beaconing and command and control."""
    return get("/api/dns", params=filters, token=token)


def episodes(token=None, **filters):
    """Correlated activity episodes."""
    return get("/api/episodes", params=filters, token=token)


def incident(addr, start, token=None, **filters):
    """Incident detail for one address around one moment."""
    params = dict(filters)
    params["addr"] = addr
    params["start"] = start
    return get("/api/incident", params=params, token=token)
