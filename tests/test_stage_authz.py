"""authz stage: missing/invalid credentials, BOLA and passive response checks, against fake APIs."""
import importlib.util
import json
import re
import socket
import threading
import time
from pathlib import Path

import httpx
import pytest

from sprat.config import Config
from sprat.proc import Cancelled
from sprat.spec import Operation, Spec, filter_operations, load_spec
from sprat.stages import authz
from sprat.testlog import TestLog, iter_entries

BASE = "http://api.test"
NOSNIFF = {"x-content-type-options": "nosniff"}
TOKENS = {"Bearer token-a": 1, "Bearer token-b": 2}
BOLA_ORDER = {"method": "GET", "path": "/users/{uid}/orders/{oid}", "params": {"uid": 1, "oid": 10}}


def op(method="get", path="/things", secured=True, has_body=False, path_params=None, query=None):
    return Operation(method, path, secured, has_body, dict(path_params or {}), dict(query or {}))


def spec_of(*ops, base=BASE):
    return Spec({}, base + "/openapi.json", "openapi3", base, list(ops))


def cfg_of(tmp_path=None, **kw):
    got = []
    kw.setdefault("headers", {"Authorization": "Bearer token-a"})
    c = Config(on_progress=got.append, **kw)
    if tmp_path is not None:
        c.testlog = TestLog(tmp_path / "test-log.ndjson", ["token-a", "token-b"])
    c.got = got  # progress events, for assertions
    return c


def entries(cfg):
    return list(iter_entries(cfg.testlog.path))


class FakeApi:
    """Stands in for discover.client_for: an httpx client over a MockTransport whose behavior the test controls."""

    def __init__(self, handler):
        self.handler, self.requests, self.base, self.kw = handler, [], None, None

    def __call__(self, base, **kw):
        self.base, self.kw = base, kw
        return httpx.Client(transport=httpx.MockTransport(self._handle), timeout=kw.get("timeout", 5),
                            follow_redirects=kw.get("follow_redirects", False))

    def _handle(self, request):
        self.requests.append(request)
        return self.handler(request)

    def paths(self):
        return [r.url.path for r in self.requests]


@pytest.fixture
def fake(monkeypatch):
    def install(handler):
        api = FakeApi(handler)
        monkeypatch.setattr(authz, "client_for", api)
        return api
    return install


def secure(request):
    """A correctly secured API: tokens checked, users only see their own data, nosniff everywhere."""
    if request.url.path == "/health":
        return httpx.Response(200, json={"ok": True}, headers=NOSNIFF)
    user = TOKENS.get(request.headers.get("authorization", ""))
    if user is None:
        return httpx.Response(401, json={"detail": "Unauthorized"}, headers=NOSNIFF)
    m = re.match(r"/users/(\d+)/", request.url.path)
    if m and int(m[1]) != user:
        return httpx.Response(404, json={"detail": "not found"}, headers=NOSNIFF)
    return httpx.Response(200, json={"id": 1}, headers=NOSNIFF)


def insecure(request):
    """Serves everything to everyone."""
    return httpx.Response(200, json={"id": 1}, headers=NOSNIFF)


def titles(res):
    return [f.title for f in res.findings]


# ---------- base URL ----------

def test_no_base_url_is_an_error(fake, tmp_path):
    api = fake(secure)
    res = authz.run(spec_of(op(), base=""), cfg_of(), tmp_path)
    assert (res.status, res.note) == ("error", "No base URL (pass --base-url)")
    assert res.findings == [] and api.requests == []


def test_base_url_from_config_overrides_spec(fake, tmp_path):
    api = fake(secure)
    authz.run(spec_of(op(path="/x"), base="http://spec.example"), cfg_of(base_url="http://override.test"), tmp_path)
    assert api.base == "http://override.test"
    assert {str(r.url) for r in api.requests} == {"http://override.test/x"}


@pytest.mark.parametrize("base", ["http://api.test/v1", "http://api.test/v1/"])
def test_base_url_with_path_prefix_and_trailing_slash(fake, tmp_path, base):
    api = fake(secure)
    authz.run(spec_of(op(path="/items"), base=base), cfg_of(), tmp_path)
    assert {str(r.url) for r in api.requests} == {"http://api.test/v1/items"}


def test_client_gets_configured_timeout_and_never_follows_redirects(fake, tmp_path):
    api = fake(lambda r: httpx.Response(302, headers={"location": "/login", **NOSNIFF}))
    res = authz.run(spec_of(op()), cfg_of(timeout=3.5), tmp_path)
    assert api.kw == {"timeout": 3.5, "follow_redirects": False}
    assert len(api.requests) == 2  # the redirect to /login was not followed
    assert res.findings == []  # a redirect to a login page is a refusal


# ---------- no / invalid credentials ----------

def test_secured_endpoint_on_secure_api_has_no_findings(fake, tmp_path):
    api = fake(secure)
    cfg = cfg_of(tmp_path)
    res = authz.run(spec_of(op(path="/admin/stats")), cfg, tmp_path)
    assert res.status == "ok" and res.findings == []
    no_creds, bad_creds = api.requests
    assert "authorization" not in no_creds.headers
    assert bad_creds.headers["authorization"] == "Bearer invalid.token.value"
    assert res.note == ("2 requests sent; 0 BOLA scenario(s) configured "
                        "(add `bola:` entries to the config to test cross-user access)")


def test_secured_endpoint_served_without_auth_is_critical_twice(fake, tmp_path):
    fake(insecure)
    res = authz.run(spec_of(op(path="/admin/stats")), cfg_of(), tmp_path)
    assert [(f.stage, f.severity, f.title, f.endpoint) for f in res.findings] == [
        ("authz", "critical", "Secured endpoint accepted no credentials (HTTP 200)", "GET /admin/stats"),
        ("authz", "critical", "Secured endpoint accepted invalid credentials (HTTP 200)", "GET /admin/stats"),
    ]
    assert all("declares security" in f.detail for f in res.findings)


def test_only_garbage_token_accepted(fake, tmp_path):
    # Treats any Bearer token as valid (e.g. signature never verified) but refuses a missing one
    fake(lambda r: httpx.Response(200 if "authorization" in r.headers else 401, headers=NOSNIFF))
    res = authz.run(spec_of(op()), cfg_of(), tmp_path)
    assert titles(res) == ["Secured endpoint accepted invalid credentials (HTTP 200)"]


def test_only_missing_token_accepted(fake, tmp_path):
    # Anonymous access falls through, but a bad token is rejected
    fake(lambda r: httpx.Response(401 if "authorization" in r.headers else 200, headers=NOSNIFF))
    res = authz.run(spec_of(op()), cfg_of(), tmp_path)
    assert titles(res) == ["Secured endpoint accepted no credentials (HTTP 200)"]


@pytest.mark.parametrize("status,flagged", [(200, True), (201, True), (204, True), (299, True), (300, False),
                                            (302, False), (400, False), (401, False), (403, False), (404, False),
                                            (405, False), (500, False)])
def test_only_2xx_counts_as_served(fake, tmp_path, status, flagged):
    fake(lambda r: httpx.Response(status, headers=NOSNIFF))
    res = authz.run(spec_of(op()), cfg_of(), tmp_path)
    crit = [f for f in res.findings if f.severity == "critical"]
    assert len(crit) == (2 if flagged else 0)
    if flagged:
        assert crit[0].title == f"Secured endpoint accepted no credentials (HTTP {status})"


def test_user_a_credentials_are_not_sent_in_the_unauthenticated_probes(fake, tmp_path):
    api = fake(secure)
    cfg = cfg_of(headers={"Authorization": "Bearer token-a", "X-Api-Key": "secret-key-a"})
    authz.run(spec_of(op()), cfg, tmp_path)
    for r in api.requests:
        assert "x-api-key" not in r.headers
        assert r.headers.get("authorization") != "Bearer token-a"


def test_several_secured_operations_each_reported(fake, tmp_path):
    fake(insecure)
    res = authz.run(spec_of(op(path="/a"), op("delete", "/b")), cfg_of(), tmp_path)
    assert [f.endpoint for f in res.findings if f.severity == "critical"] == ["GET /a", "GET /a", "DELETE /b",
                                                                              "DELETE /b"]
    assert res.note.startswith("4 requests sent")


# ---------- request building ----------

def test_path_params_query_params_and_body(fake, tmp_path):
    api = fake(secure)
    o = op("post", "/users/{uid}/orders/{oid}", has_body=True, path_params={"uid": "1", "oid": "abc"},
           query={"q": "1", "limit": "10"})
    authz.run(spec_of(o), cfg_of(), tmp_path)
    for r in api.requests:
        assert r.method == "POST"
        assert r.url.path == "/users/1/orders/abc"
        assert dict(r.url.params) == {"q": "1", "limit": "10"}
        assert json.loads(r.content) == {} and r.headers["content-type"] == "application/json"


def test_get_without_body_sends_no_content(fake, tmp_path):
    api = fake(secure)
    authz.run(spec_of(op("get", "/x")), cfg_of(), tmp_path)
    assert all(r.content == b"" for r in api.requests)


def test_url_helper():
    assert authz._url("http://h/", "/a/{x}/{y}", {"x": "1", "y": "z"}) == "http://h/a/1/z"
    assert authz._url("http://h", "/a/{x}", {}) == "http://h/a/{x}"  # unknown params left alone
    assert authz._url("http://h/api", "/a/{x}/{x}", {"x": "7"}) == "http://h/api/a/7/7"


def test_operations_from_a_real_spec_document(fake, tmp_path):
    doc = {
        "openapi": "3.0.1", "servers": [{"url": "http://real.test/api"}],
        "components": {"securitySchemes": {"b": {"type": "http", "scheme": "bearer"}}},
        "security": [{"b": []}],
        "paths": {
            "/things/{id}": {"get": {"parameters": [{"name": "id", "in": "path", "required": True,
                                                     "schema": {"type": "string", "format": "uuid"}},
                                                    {"name": "v", "in": "query", "required": True,
                                                     "schema": {"type": "integer"}},
                                                    {"name": "opt", "in": "query",
                                                     "schema": {"type": "integer"}}],
                                     "responses": {"200": {"description": "ok"}}}},
            "/health": {"get": {"security": [], "responses": {"200": {"description": "ok"}}}},
            "/optional": {"get": {"security": [{}, {"b": []}], "responses": {"200": {"description": "ok"}}}},
        },
    }
    p = tmp_path / "openapi.json"
    p.write_text(json.dumps(doc))
    api = fake(lambda r: httpx.Response(200, headers=NOSNIFF))
    res = authz.run(load_spec(str(p)), cfg_of(), tmp_path)
    urls = [str(r.url) for r in api.requests]
    assert urls.count("http://real.test/api/things/00000000-0000-0000-0000-000000000001?v=1") == 2
    assert urls.count("http://real.test/api/health") == 1  # public: one passive check
    assert urls.count("http://real.test/api/optional") == 1  # optional auth counts as public
    assert {f.endpoint for f in res.findings if f.severity == "critical"} == {"GET /things/{id}"}


# ---------- public operations ----------

def test_public_get_is_checked_with_user_a_headers(fake, tmp_path):
    api = fake(secure)
    cfg = cfg_of(tmp_path)
    res = authz.run(spec_of(op(path="/health", secured=False)), cfg, tmp_path)
    [r] = api.requests
    assert r.headers["authorization"] == "Bearer token-a"
    assert res.findings == [] and res.note.startswith("1 requests sent")
    [e] = entries(cfg)
    assert e["scenario"].startswith("Public API: response checked")
    assert (e["verdict"], e["explanation"], e["details"]) == ("pass", "No problems in the response.",
                                                             {"passive_issues": []})


@pytest.mark.parametrize("method", ["head", "options"])
def test_public_head_and_options_are_safe(fake, tmp_path, method):
    api = fake(secure)
    authz.run(spec_of(op(method, "/health", secured=False)), cfg_of(), tmp_path)
    assert [r.method for r in api.requests] == [method.upper()]


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_public_write_endpoints_are_skipped(fake, tmp_path, method):
    api = fake(insecure)
    cfg = cfg_of(tmp_path)
    res = authz.run(spec_of(op(method, "/x", secured=False)), cfg, tmp_path)
    assert api.requests == [] and res.findings == []
    assert cfg.got[-1]["msg"] == "Skipped: public write endpoint"
    assert cfg.got[-1]["op"] == f"{method.upper()} /x"
    assert entries(cfg) == []


def test_no_mutating_authz_keeps_only_safe_methods(fake, tmp_path):
    api = fake(insecure)
    ops = [op("get", "/g"), op("post", "/p"), op("delete", "/d"), op("head", "/h"), op("options", "/o")]
    res = authz.run(spec_of(*ops), cfg_of(no_mutating_authz=True), tmp_path)
    assert {r.method for r in api.requests} == {"GET", "HEAD", "OPTIONS"}
    assert {f.endpoint for f in res.findings if f.severity == "critical"} == {"GET /g", "HEAD /h", "OPTIONS /o"}


def test_exclude_paths_are_never_requested(fake, tmp_path):
    api = fake(insecure)
    ops = [op(path="/admin/delete-all"), op(path="/admin/stats"), op(path="/logout"), op(path="/items")]
    cfg = cfg_of(exclude_paths=[r"^/admin/delete", "logout"])
    res = authz.run(spec_of(*ops), cfg, tmp_path)
    assert set(api.paths()) == {"/admin/stats", "/items"}
    assert {f.endpoint for f in res.findings} <= {"GET /admin/stats", "GET /items"}
    assert {e["total"] for e in cfg.got} == {2}


def test_selected_operations_only(fake, tmp_path):
    raw = {"openapi": "3.0.1", "paths": {"/a": {"get": {}}, "/b": {"get": {}}}}
    full = Spec(raw, BASE, "openapi3", BASE, [op(path="/a"), op(path="/b")])
    api = fake(insecure)
    authz.run(filter_operations(full, ["GET /b"]), cfg_of(), tmp_path)
    assert set(api.paths()) == {"/b"}


def test_empty_spec(fake, tmp_path):
    api = fake(insecure)
    res = authz.run(spec_of(), cfg_of(), tmp_path)
    assert res.status == "ok" and res.findings == [] and api.requests == []
    assert res.note.startswith("0 requests sent")


# ---------- passive checks ----------

def test_missing_nosniff_reported_once_as_low(fake, tmp_path):
    fake(lambda r: httpx.Response(401))
    res = authz.run(spec_of(op(path="/a"), op(path="/b"), op(path="/c", secured=False)), cfg_of(), tmp_path)
    [f] = res.findings
    assert (f.severity, f.title, f.endpoint) == ("low", "Missing security header: x-content-type-options", "GET /a")
    assert "API-wide" in f.detail


def test_nosniff_header_name_is_case_insensitive(fake, tmp_path):
    fake(lambda r: httpx.Response(401, headers={"X-Content-Type-Options": "nosniff"}))
    assert authz.run(spec_of(op()), cfg_of(), tmp_path).findings == []


LEAKS = [
    "Traceback (most recent call last):\n  File \"app.py\", line 1",
    "java.lang.NullPointerException\n\tat com.example.Orders.get(Orders.java:42)",
    "System.NullReferenceException: Object reference not set",
    "Stack trace: ...",
    "SQLSTATE[42S02]: Base table or view not found",
    "ORA-00942: table or view does not exist",
    "SequelizeDatabaseError: relation \"users\" does not exist",
    "TypeError: x is undefined\n    at Object.<anonymous> (/app/index.js:3:1)",
]


@pytest.mark.parametrize("body", LEAKS)
def test_stack_trace_leak_in_error_response_is_medium(fake, tmp_path, body):
    fake(lambda r: httpx.Response(500, text=body, headers=NOSNIFF))
    res = authz.run(spec_of(op(path="/a"), op(path="/b", secured=False)), cfg_of(), tmp_path)
    [f] = res.findings  # reported once, on the first response that leaked
    assert (f.severity, f.title, f.endpoint) == ("medium", "Error response leaks stack trace / internals", "GET /a")
    assert f.detail == body[:400]


@pytest.mark.parametrize("status,body", [
    (200, "Traceback (most recent call last):"),  # only error responses count
    (500, "Internal Server Error"),
    (500, "x" * 5000 + "Traceback (most recent call last):"),  # beyond the scanned prefix
    (404, '{"detail": "Not found at /orders/1"}'),
])
def test_no_leak_false_positives(fake, tmp_path, status, body):
    fake(lambda r: httpx.Response(status, text=body, headers=NOSNIFF))
    res = authz.run(spec_of(op(secured=False)), cfg_of(), tmp_path)
    assert "Error response leaks stack trace / internals" not in titles(res)


def test_leak_detail_is_truncated(fake, tmp_path):
    body = "Traceback (most recent call last):" + "y" * 1000
    fake(lambda r: httpx.Response(500, text=body, headers=NOSNIFF))
    [f] = authz.run(spec_of(op()), cfg_of(), tmp_path).findings
    assert len(f.detail) == 400


@pytest.mark.parametrize("acao,acac,flagged", [("*", "true", True), ("*", None, False), ("*", "false", False),
                                               ("https://app.test", "true", False), (None, "true", False)])
def test_wildcard_cors_with_credentials_is_high(fake, tmp_path, acao, acac, flagged):
    h = dict(NOSNIFF)
    if acao:
        h["access-control-allow-origin"] = acao
    if acac:
        h["access-control-allow-credentials"] = acac
    fake(lambda r: httpx.Response(401, headers=h))
    res = authz.run(spec_of(op(path="/a"), op(path="/b")), cfg_of(), tmp_path)
    cors = [f for f in res.findings if f.title == "CORS allows any origin with credentials"]
    assert len(cors) == (1 if flagged else 0)
    if flagged:
        assert (cors[0].severity, cors[0].endpoint) == ("high", "GET /a")


def test_all_passive_problems_at_once(fake, tmp_path):
    h = {"access-control-allow-origin": "*", "access-control-allow-credentials": "true"}
    fake(lambda r: httpx.Response(500, text="Traceback (most recent call last):", headers=h))
    cfg = cfg_of(tmp_path)
    res = authz.run(spec_of(op(path="/pub", secured=False)), cfg, tmp_path)
    assert sorted((f.severity, f.title) for f in res.findings) == [
        ("high", "CORS allows any origin with credentials"),
        ("low", "Missing security header: x-content-type-options"),
        ("medium", "Error response leaks stack trace / internals"),
    ]
    [e] = entries(cfg)
    assert e["verdict"] == "fail"
    assert e["details"]["passive_issues"] == ["Error response leaks stack trace / internals",
                                              "Missing security header: x-content-type-options",
                                              "CORS allows any origin with credentials"]
    assert e["explanation"] == "; ".join(e["details"]["passive_issues"]) + "."


def test_passive_issues_helper_matches_findings():
    r = httpx.Response(200, headers=NOSNIFF)
    assert authz._passive_issues(r) == []
    r = httpx.Response(403, text="SQLSTATE[HY000]")
    assert authz._passive_issues(r) == ["Error response leaks stack trace / internals",
                                        "Missing security header: x-content-type-options"]


# ---------- test log ----------

def test_test_log_for_refused_and_served_probes(fake, tmp_path):
    fake(lambda r: httpx.Response(401 if "authorization" in r.headers else 200, headers=NOSNIFF))
    cfg = cfg_of(tmp_path)
    authz.run(spec_of(op(path="/admin/stats")), cfg, tmp_path)
    none, bad = entries(cfg)
    for e in (none, bad):
        assert (e["stage"], e["operation"], e["expected"]) == ("authz", "GET /admin/stats", "Refused with 401 or 403")
        assert e["request"]["url"] == "http://api.test/admin/stats" and e["request"]["method"] == "GET"
    assert none["scenario"] == "Protected API called with no credentials"
    assert none["verdict"] == "fail" and none["response"]["status"] == 200
    assert none["explanation"].startswith("Served the request (HTTP 200) with no credentials")
    assert none["details"] == {"credentials": "no credentials", "passive_issues": [], "error_200": ""}
    assert bad["scenario"] == "Protected API called with invalid credentials"
    assert bad["verdict"] == "pass" and bad["explanation"] == "Refused with HTTP 401, as it should."
    assert bad["request"]["headers"]["authorization"] == "Bearer ***"  # masked in the log


def test_no_test_log_is_fine(fake, tmp_path):
    fake(lambda r: (_ for _ in ()).throw(httpx.ConnectError("refused")) if r.url.path == "/down"
         else httpx.Response(200, headers=NOSNIFF))
    cfg = cfg_of(bola=[BOLA_ORDER], headers_b={"Authorization": "Bearer token-b"})
    cfg.bola.append({"path": "/down"})
    res = authz.run(spec_of(op(path="/down"), op(path="/ok")), cfg, tmp_path)
    assert res.status == "ok"
    assert "Request failed" in titles(res) and "BOLA request failed" in titles(res)


# ---------- transport errors ----------

def _raise(exc):
    def handler(request):
        raise exc
    return handler


@pytest.mark.parametrize("exc", [httpx.ConnectError("Connection refused"), httpx.ReadTimeout("timed out"),
                                 httpx.RemoteProtocolError("Server disconnected")])
def test_transport_errors_are_reported_not_raised(fake, tmp_path, exc):
    fake(_raise(exc))
    cfg = cfg_of(tmp_path)
    res = authz.run(spec_of(op(path="/a"), op(path="/b", secured=False)), cfg, tmp_path)
    assert res.status == "ok"
    assert [(f.severity, f.title, f.endpoint, f.detail) for f in res.findings] == [
        ("info", "Request failed", "GET /a", str(exc)), ("info", "Request failed", "GET /b", str(exc))]
    assert res.note.startswith("0 requests sent")
    e = entries(cfg)
    assert [(x["verdict"], x["operation"], x["scenario"]) for x in e] == [
        ("error", "GET /a", "Auth check request"), ("error", "GET /b", "Auth check request")]
    assert e[0]["request"] == {"method": "GET", "url": "http://api.test/a", "headers": {}, "body": None}
    assert e[0]["details"] == {"error": str(exc)}


def test_one_failing_endpoint_does_not_stop_the_others(fake, tmp_path):
    def handler(r):
        if r.url.path == "/down":
            raise httpx.ConnectError("refused")
        return httpx.Response(200, headers=NOSNIFF)
    api = fake(handler)
    res = authz.run(spec_of(op(path="/down"), op(path="/up")), cfg_of(), tmp_path)
    assert api.paths() == ["/down", "/up", "/up"]  # second probe on /down skipped after the error
    assert [f.title for f in res.findings if f.endpoint == "GET /up"] == [
        "Secured endpoint accepted no credentials (HTTP 200)", "Secured endpoint accepted invalid credentials (HTTP 200)"]


def test_error_after_first_probe_keeps_the_first_result(fake, tmp_path):
    calls = []

    def handler(r):
        calls.append(r)
        if len(calls) == 2:
            raise httpx.ReadTimeout("slow")
        return httpx.Response(200, headers=NOSNIFF)
    fake(handler)
    res = authz.run(spec_of(op()), cfg_of(), tmp_path)
    assert titles(res) == ["Secured endpoint accepted no credentials (HTTP 200)", "Request failed"]
    assert res.note.startswith("1 requests sent")


# ---------- cancellation ----------

def test_cancel_before_start_sends_nothing(fake, tmp_path):
    api = fake(insecure)
    cfg = cfg_of(cancel=threading.Event())
    cfg.cancel.set()
    with pytest.raises(Cancelled):
        authz.run(spec_of(op()), cfg, tmp_path)
    assert api.requests == []


def test_cancel_mid_stage_stops_before_next_operation(fake, tmp_path):
    cancel = threading.Event()

    def handler(r):
        cancel.set()  # the user presses Stop while the first operation is being checked
        return httpx.Response(401, headers=NOSNIFF)
    api = fake(handler)
    with pytest.raises(Cancelled):
        authz.run(spec_of(op(path="/a"), op(path="/b"), op(path="/c")), cfg_of(cancel=cancel), tmp_path)
    assert api.paths() == ["/a", "/a"]


def test_cancel_during_bola(fake, tmp_path):
    cancel = threading.Event()

    def handler(r):
        if r.url.path.startswith("/users/"):
            cancel.set()
        return secure(r)
    api = fake(handler)
    cfg = cfg_of(cancel=cancel, headers_b={"Authorization": "Bearer token-b"},
                 bola=[BOLA_ORDER, {"path": "/users/1/profile"}])
    with pytest.raises(Cancelled):
        authz.run(spec_of(), cfg, tmp_path)
    assert api.paths() == ["/users/1/orders/10", "/users/1/orders/10"]  # second scenario never started


# ---------- progress ----------

def test_progress_events(fake, tmp_path):
    fake(lambda r: httpx.Response(200 if r.url.path == "/open" else 401, headers=NOSNIFF))
    cfg = cfg_of(headers_b={"Authorization": "Bearer token-b"}, bola=[{"path": "/open"}])
    authz.run(spec_of(op(path="/open"), op(path="/pub", secured=False), op("post", "/w", secured=False)), cfg,
              tmp_path)
    got = [(g["stage"], g["msg"], g["op"], g["done"], g["total"], g["level"]) for g in cfg.got]
    assert got == [
        ("authz", "Sending no credentials; expecting 401/403", "GET /open", 0, 4, "info"),
        ("authz", "Accepted no credentials (HTTP 200)", "GET /open", 0, 4, "bad"),
        ("authz", "Sending invalid credentials; expecting 401/403", "GET /open", 0, 4, "info"),
        ("authz", "Accepted invalid credentials (HTTP 200)", "GET /open", 0, 4, "bad"),
        ("authz", "Public endpoint: checking headers and error leaks", "GET /pub", 1, 4, "info"),
        ("authz", "Skipped: public write endpoint", "POST /w", 2, 4, "info"),
        ("authz", "BOLA: user A reads its resource, then user B tries the same ", "GET /open", 3, 4, "info"),
        ("authz", "BOLA: user B got user A's data (HTTP 200)", "GET /open", 4, 4, "bad"),
    ]


def test_no_progress_listener_is_fine(fake, tmp_path):
    fake(insecure)
    cfg = Config(headers={"Authorization": "Bearer token-a"}, headers_b={"Authorization": "Bearer token-b"},
                 bola=[BOLA_ORDER])
    res = authz.run(spec_of(op()), cfg, tmp_path)
    assert len(res.findings) == 3


# ---------- BOLA ----------

def bola_cfg(tmp_path=None, *scenarios, **kw):
    kw.setdefault("headers_b", {"Authorization": "Bearer token-b"})
    return cfg_of(tmp_path, bola=list(scenarios), **kw)


def test_bola_without_user_b_is_skipped(fake, tmp_path):
    api = fake(insecure)
    res = authz.run(spec_of(), bola_cfg(None, BOLA_ORDER, headers_b={}), tmp_path)
    [f] = res.findings
    assert (f.severity, f.title, f.endpoint) == ("info", "BOLA scenarios skipped", "")
    assert "--header-b" in f.detail
    assert api.requests == []
    assert res.note == "0 requests sent; 1 BOLA scenario(s) configured"


def test_bola_user_b_from_login_counts(fake, tmp_path):
    class Provider:
        def __init__(self, token):
            self.token = token

        def headers(self):
            return {"Authorization": f"Bearer {self.token}"}
    api = fake(insecure)
    cfg = bola_cfg(None, BOLA_ORDER, headers={}, headers_b={})
    cfg.auth_a, cfg.auth_b = Provider("token-a"), Provider("token-b")
    res = authz.run(spec_of(), cfg, tmp_path)
    assert [r.headers["authorization"] for r in api.requests] == ["Bearer token-a", "Bearer token-b"]
    assert titles(res) == ["BOLA: user B accessed user A's resource"]


def test_bola_found_on_vulnerable_api(fake, tmp_path):
    api = fake(insecure)
    cfg = bola_cfg(tmp_path, BOLA_ORDER)
    res = authz.run(spec_of(), cfg, tmp_path)
    [f] = res.findings
    assert (f.stage, f.severity, f.title) == ("authz", "critical", "BOLA: user B accessed user A's resource")
    assert f.endpoint == "GET /users/{uid}/orders/{oid} {'uid': '1', 'oid': '10'}"
    assert f.detail == "User B got HTTP 200; expected 401/403/404."
    a, b = api.requests
    assert str(a.url) == str(b.url) == "http://api.test/users/1/orders/10"
    assert (a.headers["authorization"], b.headers["authorization"]) == ("Bearer token-a", "Bearer token-b")
    step1, step2 = entries(cfg)
    assert step1["scenario"].startswith("Cross-user check, step 1") and step1["verdict"] == "pass"
    assert step1["details"] == {"scenario_params": {"uid": "1", "oid": "10"}, "user": "A"}
    assert step1["operation"] == "GET /users/{uid}/orders/{oid}"
    assert step2["scenario"].startswith("Cross-user check, step 2") and step2["verdict"] == "fail"
    assert step2["details"]["user"] == "B"
    assert step2["explanation"].startswith("User B got user A's data (HTTP 200)")
    assert res.note == "0 requests sent; 1 BOLA scenario(s) configured"


@pytest.mark.parametrize("status", [401, 403, 404])
def test_bola_blocked_on_secure_api(fake, tmp_path, status):
    fake(lambda r: httpx.Response(200 if r.headers["authorization"] == "Bearer token-a" else status))
    cfg = bola_cfg(tmp_path, BOLA_ORDER)
    res = authz.run(spec_of(), cfg, tmp_path)
    assert res.findings == []
    assert cfg.got[-1]["msg"] == f"BOLA: user B was blocked (HTTP {status})" and cfg.got[-1]["level"] == "ok"
    assert entries(cfg)[1]["verdict"] == "pass"
    assert entries(cfg)[1]["explanation"] == f"User B was refused (HTTP {status}), as it should."


def test_bola_secure_api_handler_end_to_end(fake, tmp_path):
    fake(secure)
    res = authz.run(spec_of(op(path="/users/{uid}/orders/{oid}", path_params={"uid": "1", "oid": "1"})),
                    bola_cfg(None, BOLA_ORDER), tmp_path)
    assert res.findings == []  # no false positives against a correctly secured API


@pytest.mark.parametrize("status", [401, 403, 404, 500])
def test_bola_owner_refused_is_inconclusive(fake, tmp_path, status):
    api = fake(lambda r: httpx.Response(status))
    cfg = bola_cfg(tmp_path, BOLA_ORDER)
    [f] = authz.run(spec_of(), cfg, tmp_path).findings
    assert (f.severity, f.title) == ("info", "BOLA scenario inconclusive")
    assert f.detail == f"Owner (user A) got HTTP {status}; fix the scenario's IDs."
    assert len(api.requests) == 1  # user B is never tried
    [e] = entries(cfg)
    assert e["verdict"] == "error" and "couldn't run" in e["explanation"]


def test_bola_method_body_defaults_and_query(fake, tmp_path):
    api = fake(insecure)
    scen = [{"method": "put", "path": "/orders/{id}", "params": {"id": 5}, "body": {"total": 1}},
            {"path": "/orders/{id}?expand=items", "params": {"id": "x"}},
            {"path": "/me"}]
    res = authz.run(spec_of(), bola_cfg(None, *scen), tmp_path)
    r = api.requests
    assert [(x.method, str(x.url)) for x in r] == [
        ("PUT", "http://api.test/orders/5"), ("PUT", "http://api.test/orders/5"),
        ("GET", "http://api.test/orders/x?expand=items"), ("GET", "http://api.test/orders/x?expand=items"),
        ("GET", "http://api.test/me"), ("GET", "http://api.test/me")]
    assert json.loads(r[0].content) == json.loads(r[1].content) == {"total": 1}
    assert r[2].content == b""
    assert [f.endpoint for f in res.findings] == ["PUT /orders/{id} {'id': '5'}",
                                                  "GET /orders/{id}?expand=items {'id': 'x'}", "GET /me {}"]


def test_bola_progress_op_strips_query(fake, tmp_path):
    fake(insecure)
    cfg = bola_cfg(None, {"path": "/orders/{id}?expand=items", "params": {"id": 1}})
    authz.run(spec_of(), cfg, tmp_path)
    assert {g["op"] for g in cfg.got} == {"GET /orders/{id}"}


@pytest.mark.parametrize("fail_on", ["a", "b"])
def test_bola_transport_error_reported_and_next_scenario_runs(fake, tmp_path, fail_on):
    def handler(r):
        if r.url.path == "/first" and r.headers["authorization"] == f"Bearer token-{fail_on}":
            raise httpx.ConnectError("refused")
        return httpx.Response(200)
    api = fake(handler)
    cfg = bola_cfg(tmp_path, {"path": "/first"}, {"path": "/second"})
    res = authz.run(spec_of(), cfg, tmp_path)
    assert [(f.severity, f.title, f.endpoint) for f in res.findings] == [
        ("info", "BOLA request failed", "GET /first {}"),
        ("critical", "BOLA: user B accessed user A's resource", "GET /second {}")]
    assert res.findings[0].detail == "refused"
    assert api.paths()[-2:] == ["/second", "/second"]
    err = [e for e in entries(cfg) if e["verdict"] == "error"]
    assert [(e["scenario"], e["operation"], e["request"]["url"]) for e in err] == [
        ("BOLA request", "GET /first", "http://api.test/first")]


def test_bola_mixed_scenarios(fake, tmp_path):
    def handler(r):
        user = TOKENS[r.headers["authorization"]]
        if r.url.path == "/leaky":
            return httpx.Response(200)
        if r.url.path == "/missing":
            return httpx.Response(404)
        return httpx.Response(200 if user == 1 else 403)
    fake(handler)
    cfg = bola_cfg(None, {"path": "/leaky"}, {"path": "/safe"}, {"path": "/missing"})
    res = authz.run(spec_of(op(path="/x", secured=False)), cfg, tmp_path)
    assert [(f.severity, f.title) for f in res.findings] == [
        ("low", "Missing security header: x-content-type-options"),
        ("critical", "BOLA: user B accessed user A's resource"),
        ("info", "BOLA scenario inconclusive")]
    assert res.note == "1 requests sent; 3 BOLA scenario(s) configured"
    assert [g["done"] for g in cfg.got if g["msg"].startswith("BOLA: user B")] == [2, 3]


def test_bola_helper_without_scenarios():
    assert authz._bola(None, Config(), BASE) == []


# ---------- real stage against the demo API ----------

def _load_demo():
    path = Path(__file__).resolve().parent.parent / "examples" / "demo_api.py"
    spec = importlib.util.spec_from_file_location("demo_api_authz_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def demo_api():
    uvicorn = pytest.importorskip("uvicorn")
    mod = _load_demo()
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    server = uvicorn.Server(uvicorn.Config(mod.app, host="127.0.0.1", port=port, log_level="warning"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    end = time.time() + 20
    while not server.started:
        if time.time() > end or not t.is_alive():
            raise RuntimeError("demo API did not start")
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    t.join(10)


@pytest.mark.slow
@pytest.mark.e2e
def test_real_authz_finds_demo_flaws(demo_api, tmp_path):
    spec = load_spec(demo_api + "/openapi.json")
    cfg = bola_cfg(tmp_path, BOLA_ORDER, base_url=demo_api)
    res = authz.run(spec, cfg, tmp_path)
    got = {(f.severity, f.title, f.endpoint) for f in res.findings}
    assert ("critical", "Secured endpoint accepted no credentials (HTTP 200)", "GET /admin/stats") in got
    assert ("critical", "Secured endpoint accepted invalid credentials (HTTP 200)", "GET /admin/stats") in got
    assert ("critical", "BOLA: user B accessed user A's resource",
            "GET /users/{uid}/orders/{oid} {'uid': '1', 'oid': '10'}") in got
    assert ("low", "Missing security header: x-content-type-options", "GET /health") in got
    # the order endpoint does check the token: no false positive there
    assert not any(f.severity == "critical" and f.endpoint == "GET /users/{uid}/orders/{oid}" for f in res.findings)
    assert res.status == "ok"
    verdicts = {(e["operation"], e["scenario"], e["verdict"]) for e in entries(cfg)}
    assert ("GET /users/{uid}/orders/{oid}", "Protected API called with no credentials", "pass") in verdicts
    assert ("GET /admin/stats", "Protected API called with no credentials", "fail") in verdicts


@pytest.mark.slow
@pytest.mark.e2e
def test_real_authz_bola_on_own_data_and_bad_ids(demo_api, tmp_path):
    spec = load_spec(demo_api + "/openapi.json")
    cfg = bola_cfg(None, {"path": "/users/{uid}/orders/{oid}", "params": {"uid": 1, "oid": 999}},
                   base_url=demo_api, no_mutating_authz=True, exclude_paths=["admin"])
    res = authz.run(spec, cfg, tmp_path)
    assert "BOLA scenario inconclusive" in titles(res)
    assert not any(f.severity == "critical" for f in res.findings)


@pytest.mark.slow
@pytest.mark.e2e
def test_real_authz_unreachable_server(tmp_path):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens here
    res = authz.run(spec_of(op(), base=f"http://127.0.0.1:{port}"), cfg_of(timeout=2), tmp_path)
    assert [(f.severity, f.title) for f in res.findings] == [("info", "Request failed")]
