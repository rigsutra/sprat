"""Web API, route by route: happy paths, validation, ids from the URL, persistence, runs, test log, downloads.

Everything runs against an in-process fake API (httpx.MockTransport) and a temporary data dir. Most run
tests replace the pipeline with a controllable fake so state transitions are deterministic; a few use the
real pipeline (authz stage only) end to end.
"""
import base64
import copy
import csv
import io
import json
import os
import threading
import time
import zipfile
from pathlib import Path
from urllib.parse import quote

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient

from sprat.config import ALL_STAGES, load_config
from sprat.testlog import TestLog
from sprat.web import app as web

SPEC_DOC = {
    "openapi": "3.0.1", "info": {"title": "Shop", "version": "2.1"},
    "servers": [{"url": "http://fake.test"}],
    "components": {"securitySchemes": {"b": {"type": "http", "scheme": "bearer"}}},
    "paths": {
        "/a": {"get": {"summary": "List A", "tags": ["t1"], "operationId": "listA",
                       "responses": {"200": {"description": "ok"}}}},
        "/b": {"get": {"security": [{"b": []}], "deprecated": True, "responses": {"200": {"description": "ok"}}}},
        "/echo": {"get": {"responses": {"200": {"description": "ok"}}}},
        "/items/{id}": {"get": {"security": [{"b": []}], "responses": {"200": {"description": "ok"}}}},
    },
}
LABELS = ["GET /a", "GET /b", "GET /echo", "GET /items/{id}"]
API_JWT = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJzZXJ2ZXItaXNzdWVkIn0.c2lnbmF0dXJlLXZhbHVl"
API = {}


def _jwt(claims):
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{b({'alg': 'none'})}.{b(claims)}.sig"


def handler(request: httpx.Request) -> httpx.Response:
    p, host = request.url.path, request.url.host
    API["calls"].append(f"{request.method} {host}{p}")
    if host == "nospec.test":
        return httpx.Response(404, text="nothing here")
    if p == "/openapi.json":
        return httpx.Response(200, json=API["spec"])
    if p == "/v2/openapi.json":
        doc = copy.deepcopy(API["spec"])
        doc["paths"] = {"/only-v2": {"get": {"responses": {"200": {"description": "ok"}}}}}
        return httpx.Response(200, json=doc)
    if p == "/private/openapi.json":
        if request.headers.get("x-key") != "spec-key-123456":
            return httpx.Response(401, json={"message": "no key"})
        return httpx.Response(200, json=API["spec"])
    if p == "/flaky/openapi.json":
        API["flaky"] = API.get("flaky", 0) + 1
        return httpx.Response(200, json=API["spec"]) if API["flaky"] == 1 else httpx.Response(500)
    if p == "/notaspec":
        return httpx.Response(200, text="just text")
    if p == "/auth/login":
        body = json.loads(request.content)
        if body.get("password") != "pw-123456":
            return httpx.Response(401, json={"message": "Invalid email or password"})
        if body.get("email") == "plain@x.test":
            return httpx.Response(200, json={"token": "opaque-token-value-1234567890"})
        tok = _jwt({"sub": body["email"], "email": body["email"], "roles": ["qa"], "iat": int(time.time()),
                    "exp": int(time.time()) + 900, "secret_claim": "not shown"})
        return httpx.Response(200, json={"data": {"accessToken": tok}})
    if p == "/echo":  # a leaky API that reflects credentials and hands out its own JWT
        return httpx.Response(200, json={"seen": dict(request.headers), "issued": API_JWT},
                              headers={"x-content-type-options": "nosniff"})
    return httpx.Response(200, json={}, headers={"x-content-type-options": "nosniff"})


def _worker_threads():
    return [t for t in threading.enumerate() if getattr(t, "_target", None) is web._worker]


@pytest.fixture
def data(tmp_path):
    return tmp_path / "data"


@pytest.fixture
def client(tmp_path, data, monkeypatch):
    API.clear()
    API.update(spec=copy.deepcopy(SPEC_DOC), calls=[])
    real = httpx.Client

    def fake_request(method, url, **kw):  # the login call uses httpx.request
        with real(transport=httpx.MockTransport(handler)) as c:
            kw.pop("follow_redirects", None)
            return c.request(method, url, **kw)
    monkeypatch.setattr(httpx, "request", fake_request)

    def fake_client(*a, **kw):
        kw["transport"] = httpx.MockTransport(handler)
        return real(*a, **kw)
    monkeypatch.setattr(httpx, "Client", fake_client)
    monkeypatch.delenv("SPRAT_SECRET_KEY", raising=False)
    web.configure(data)
    web._runs.clear(); web._cancels.clear(); web._secrets.clear()
    yield TestClient(web.app)
    for t in _worker_threads():
        t.join(15)
    web._runs.clear(); web._cancels.clear(); web._secrets.clear()


class Pipe:
    """Stand-in for run_pipeline: logs a few entries, then waits for `gate` (or the cancel event)."""

    def __init__(self):
        self.gate = threading.Event()
        self.gate.set()
        self.started = threading.Event()
        self.cfgs, self.progress, self.entries = [], [], []
        self.findings, self.status = {}, {}
        self.error = None
        self.ignore_cancel = False

    def __call__(self, cfg, emit):
        self.cfgs.append(cfg)
        out = Path(cfg.out_dir)
        out.mkdir(parents=True, exist_ok=True)
        labels = cfg.operations or ["GET /a", "GET /b"]
        emit({"type": "spec", "version": "openapi3", "operations": len(labels), "base_url": "http://fake.test",
              "labels": labels})
        tl = TestLog(out / "test-log.ndjson", list(cfg.headers.values()) + list(cfg.headers_b.values())
                     + list(cfg.variables.values()))
        for e in self.entries:
            tl.add(**e)
        emit({"type": "stage_start", "stage": cfg.stages[0]})
        for p in self.progress:
            cfg.on_progress(dict(p))
        self.started.set()
        while not self.gate.wait(0.01):
            if cfg.cancel.is_set():
                if self.ignore_cancel:
                    break
                emit({"type": "stage_end", "stage": cfg.stages[0], "status": "cancelled", "findings": 0,
                      "note": "Stopped by user", "duration": 0})
                emit({"type": "cancelled"})
                self._report(out, cfg)
                return
        if self.error:
            raise self.error
        for s in cfg.stages:
            emit({"type": "stage_end", "stage": s, "status": self.status.get(s, "ok"),
                  "findings": len(self.findings.get(s, [])), "note": "", "duration": 0.1})
        self._report(out, cfg)
        emit({"type": "done"})

    def _report(self, out, cfg):
        (out / "report.json").write_text(json.dumps({"spec": cfg.spec, "base_url": "http://fake.test", "stages": [
            {"name": s, "status": self.status.get(s, "ok"), "note": "", "findings": self.findings.get(s, []),
             "duration": 0.1} for s in cfg.stages]}), encoding="utf-8")


@pytest.fixture
def pipe(client, monkeypatch):
    p = Pipe()
    monkeypatch.setattr(web, "run_pipeline", p)
    yield p
    p.gate.set()
    for t in _worker_threads():
        t.join(15)


HEADERS = "Authorization: Bearer literal-token-123456"


def _create(client, **extra):
    body = {"name": "Shop", "spec": "http://fake.test/openapi.json", "stages": ["authz"], "headers": HEADERS} | extra
    r = client.post("/api/projects", json=body)
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _start(client, pid, **body):
    r = client.post(f"/api/projects/{pid}/runs", json=body)
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _until(fn, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(0.02)
    raise AssertionError("condition not reached")


def _wait(client, rid):
    return _until(lambda: (lambda r: r if r["status"] not in ("running", "stopping") else None)(
        client.get(f"/api/runs/{rid}").json()))


def _restart(data):
    """What a server restart leaves: only what's on disk."""
    web._runs.clear(); web._cancels.clear(); web._secrets.clear()
    web.configure(data)


def _mkrun(data, rid, pid, status="done", tested=None, stages=None, entries=(), name="Shop", **meta):
    d = data / "runs" / rid
    d.mkdir(parents=True, exist_ok=True)
    m = {"id": rid, "project_id": pid, "project_name": name, "status": status, "started": 1700000000.0,
         "finished": 1700000100.0, "error": None, "operations": [], "tested": tested, "stages_requested": ["authz"],
         "headers": {"Authorization": "***"}, "headers_b": {}} | meta
    (d / "run.json").write_text(json.dumps(m), encoding="utf-8")
    if stages is not None:
        (d / "report.json").write_text(json.dumps({"spec": "s", "base_url": "http://fake.test", "stages": stages}),
                                       encoding="utf-8")
    if entries:
        tl = TestLog(d / "test-log.ndjson")
        for e in entries:
            tl.add(**e)
    return d


def _stage(name, findings=(), status="ok"):
    return {"name": name, "status": status, "note": "", "duration": 0.1,
            "findings": [{"severity": s, "title": "t", "operation": o, "detail": "", "stage": name, "endpoint": ""}
                         for s, o in findings]}


# ---------------- static / env ----------------

def test_index_favicon_and_static(client):
    r = client.get("/")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html") and "<html" in r.text.lower()
    assert "/static/app.js" in r.text
    f = client.get("/favicon.ico")
    assert f.status_code == 200 and f.headers["content-type"] == "image/svg+xml" and b"<svg" in f.content
    for name in ("app.js", "style.css", "favicon.svg", "index.html"):
        s = client.get(f"/static/{name}")
        assert s.status_code == 200 and s.headers["cache-control"] == "no-cache", name


@pytest.mark.parametrize("name", ["nope.js", "..%5Capp.py", "..%5C..%5Cconfig.py", "%2e%2e", "%2e%2e%5Capp.py"])
def test_static_refuses_unknown_and_traversal(client, name):
    assert client.get(f"/static/{name}").status_code == 404


def test_static_refuses_absolute_path(client, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("private", encoding="utf-8")
    r = client.get("/static/" + quote(str(outside), safe=""))
    assert r.status_code == 404 and "private" not in r.text


@pytest.mark.parametrize("npx,docker,rc,want", [
    (None, None, 0, {"lint": False, "zap": False}),
    ("npx", "docker", 0, {"lint": True, "zap": True}),
    ("npx", "docker", 1, {"lint": True, "zap": False}),  # Docker installed but not running
])
def test_env_reports_tool_availability(client, monkeypatch, npx, docker, rc, want):
    monkeypatch.setattr(web.shutil, "which", lambda n: {"npx": npx, "docker": docker}[n])
    monkeypatch.setattr(web.subprocess, "run", lambda *a, **k: type("R", (), {"returncode": rc})())
    e = client.get("/api/env").json()
    assert e["stages"] == ALL_STAGES and e["available"] == want
    assert (e["reasons"]["lint"] == "") == want["lint"] and (e["reasons"]["zap"] == "") == want["zap"]
    if not want["zap"]:
        assert "Docker" in e["reasons"]["zap"]


# ---------------- vars / secrets ----------------

def test_vars_status_sources(client, monkeypatch):
    pid = _create(client)
    client.put(f"/api/projects/{pid}/secrets/SAVED_ONE", json={"value": "v-123456"})
    monkeypatch.setenv("SPRAT_FROM_ENV", "x")
    monkeypatch.delenv("SPRAT_NOWHERE", raising=False)
    out = client.get("/api/vars", params={"names": " SAVED_ONE, SPRAT_FROM_ENV,SPRAT_NOWHERE, bad-name ,,",
                                          "project": pid}).json()
    by = {o["name"]: o for o in out}
    assert list(by) == ["SAVED_ONE", "SPRAT_FROM_ENV", "SPRAT_NOWHERE", "bad-name"]
    assert by["SAVED_ONE"]["source"] == "project" and by["SAVED_ONE"]["updated"] > 0
    assert by["SPRAT_FROM_ENV"] == {"name": "SPRAT_FROM_ENV", "source": "environment", "updated": None}
    assert by["SPRAT_NOWHERE"]["source"] is None
    assert by["bad-name"]["source"] is None and "letters, digits" in by["bad-name"]["error"]
    assert "v-123456" not in json.dumps(out)
    # without a project, saved secrets don't count
    assert client.get("/api/vars", params={"names": "SAVED_ONE"}).json()[0]["source"] is None


def test_vars_status_is_capped_and_handles_empty(client):
    assert client.get("/api/vars").json() == []
    names = ",".join(f"N{i}" for i in range(80))
    assert len(client.get("/api/vars", params={"names": names}).json()) == 50
    assert client.get("/api/vars", params={"names": "X", "project": "../../etc"}).json()[0]["source"] in (None,
                                                                                                         "environment")


def test_secret_endpoints_never_echo_values(client, data):
    pid = _create(client)
    secret = "s3cr3t-Value-Ünïcode-789"
    assert client.put(f"/api/projects/{pid}/secrets/MY_PW", json={"value": secret}).json() == {"ok": True}
    names = client.get(f"/api/projects/{pid}/secrets").json()
    assert [n["name"] for n in names] == ["MY_PW"] and set(names[0]) == {"name", "updated"}
    responses = [client.get(f"/api/projects/{pid}/secrets"), client.get(f"/api/projects/{pid}"),
                 client.get("/api/projects"), client.get(f"/api/projects/{pid}/yaml"),
                 client.get("/api/vars", params={"names": "MY_PW", "project": pid})]
    for r in responses:
        assert secret not in r.text
    assert client.get(f"/api/projects/{pid}").json()["secrets"][0]["name"] == "MY_PW"
    for f in data.rglob("*"):  # encrypted at rest
        if f.is_file():
            assert secret.encode() not in f.read_bytes(), f
    assert client.put(f"/api/projects/{pid}/secrets/MY_PW", json={"value": "replaced-value"}).status_code == 200
    assert len(client.get(f"/api/projects/{pid}/secrets").json()) == 1
    assert client.delete(f"/api/projects/{pid}/secrets/MY_PW").json() == {"ok": True}
    assert client.get(f"/api/projects/{pid}/secrets").json() == []
    assert client.delete(f"/api/projects/{pid}/secrets/NEVER_SET").status_code == 200  # idempotent


@pytest.mark.parametrize("name,body,status", [
    ("bad-name", {"value": "x"}, 400),
    ("1STARTS_WITH_DIGIT", {"value": "x"}, 400),
    ("..%5C..%5Csecrets", {"value": "x"}, 400),
    ("OK_NAME", {"value": ""}, 400),
    ("OK_NAME", {}, 422),
    ("OK_NAME", {"value": 5}, 422),
    ("A" * 65, {"value": "x"}, 400),
])
def test_secret_validation(client, name, body, status):
    pid = _create(client)
    assert client.put(f"/api/projects/{pid}/secrets/{name}", json=body).status_code == status
    assert client.get(f"/api/projects/{pid}/secrets").json() == []


@pytest.mark.parametrize("pid", ["nope", "..", "%2e%2e", "..%5C..%5Cx", "UPPER", "a_b"])
def test_secret_routes_unknown_project(client, pid):
    assert client.get(f"/api/projects/{pid}/secrets").status_code == 404
    assert client.put(f"/api/projects/{pid}/secrets/X_1", json={"value": "v"}).status_code == 404
    assert client.delete(f"/api/projects/{pid}/secrets/X_1").status_code == 404


def test_secrets_saved_and_deleted_with_project_settings(client):
    pid = _create(client, secrets={"PW_ONE": "first-value", "EMPTY_ONE": ""})
    assert [s["name"] for s in client.get(f"/api/projects/{pid}/secrets").json()] == ["PW_ONE"]
    body = {"name": "Shop", "spec": "http://fake.test/openapi.json", "stages": ["authz"], "headers": HEADERS,
            "secrets": {"PW_TWO": "second"}, "delete_secrets": ["PW_ONE", "NOT_THERE"]}
    assert client.put(f"/api/projects/{pid}", json=body).status_code == 200
    assert [s["name"] for s in client.get(f"/api/projects/{pid}/secrets").json()] == ["PW_TWO"]
    saved = json.loads((web.projects_dir() / f"{pid}.json").read_text(encoding="utf-8"))
    assert "secrets" not in saved and "delete_secrets" not in saved
    bad = body | {"secrets": {"bad name": "v"}}
    assert client.put(f"/api/projects/{pid}", json=bad).status_code == 400


def test_create_with_invalid_secret_name_leaves_no_project(client):
    r = client.post("/api/projects", json={"name": "Shop", "spec": "http://fake.test/openapi.json",
                                           "secrets": {"bad name": "value"}})
    assert r.status_code == 400
    assert client.get("/api/projects").json() == []


# ---------------- login test ----------------

LOGIN = {"url": "http://fake.test/auth/login", "body": '{"email": "qa@x.test", "password": "${LOGIN_PW}"}',
         "token_path": "data.accessToken"}


def test_login_test_with_unsaved_secret(client):
    r = client.post("/api/login/test", json={"login": LOGIN, "secrets": {"LOGIN_PW": "pw-123456"}})
    assert r.status_code == 200, r.text
    t = r.json()
    assert t["ok"] and t["header"] == "Authorization" and t["expiry_source"] == "JWT exp claim"
    assert t["token_preview"].endswith("…") and len(t["token_preview"]) == 9
    assert 800 < t["expires_in"] <= 900 and t["refresh_at"] == t["expires_at"] - web.REFRESH_MARGIN
    assert t["jwt"]["sub"] == "qa@x.test" and t["jwt"]["roles"] == ["qa"]
    assert set(t["jwt"]) == {"sub", "email", "roles", "iat", "exp"}  # other claims aren't echoed
    assert "accessToken" not in r.text and r.text.count(".") < 10
    assert client.get("/api/projects").json() == []  # nothing stored


def test_login_test_uses_saved_project_secret(client):
    pid = _create(client)
    client.put(f"/api/projects/{pid}/secrets/LOGIN_PW", json={"value": "pw-123456"})
    assert client.post("/api/login/test", json={"login": LOGIN, "project_id": pid}).json()["ok"]
    # an unsaved value typed in the form wins over the saved one
    r = client.post("/api/login/test", json={"login": LOGIN, "project_id": pid, "secrets": {"LOGIN_PW": "wrong"}})
    assert r.status_code == 400 and "Invalid email or password" in r.text


@pytest.mark.parametrize("login,extra,status,text", [
    ({"url": ""}, {}, 400, "Enter the login URL first"),
    ({"url": "   "}, {}, 400, "Enter the login URL first"),
    (LOGIN | {"token_type": "magic"}, {}, 400, "unknown token type"),
    (LOGIN | {"expiry": "never"}, {}, 400, "unknown token type or expiry mode"),
    (LOGIN | {"token_path": "  "}, {}, 400, "say where the token is"),
    (LOGIN | {"body": '{"email": "qa@x.test", "password": "hunter2"}'}, {}, 400, "typed directly"),
    (LOGIN, {}, 400, "LOGIN_PW has no value"),
    (LOGIN, {"secrets": {"LOGIN_PW": "nope"}}, 400, "Invalid email or password"),
    (LOGIN | {"token_path": "data.missing"}, {"secrets": {"LOGIN_PW": "pw-123456"}}, 400, "no `data.missing`"),
    (LOGIN, {"project_id": "nope"}, 404, ""),
    (LOGIN, {"project_id": "../../x"}, 404, ""),
])
def test_login_test_errors(client, monkeypatch, login, extra, status, text):
    monkeypatch.delenv("LOGIN_PW", raising=False)
    r = client.post("/api/login/test", json={"login": login} | extra)
    assert r.status_code == status and text in r.text


def test_login_test_requires_login_object(client):
    assert client.post("/api/login/test", json={}).status_code == 422
    assert client.post("/api/login/test", json={"login": "http://x"}).status_code == 422


@pytest.mark.parametrize("cfg,header", [
    ({"token_type": "header", "header_name": "X-API-Key"}, "X-API-Key"),
    ({"token_type": "cookie", "cookie_name": "sid"}, "Cookie"),
    ({"token_type": "bearer"}, "Authorization"),
])
def test_login_test_token_types_and_fixed_expiry(client, cfg, header):
    login = LOGIN | {"body": '{"email": "plain@x.test", "password": "${LOGIN_PW}"}', "token_path": "token",
                     "expiry": "fixed", "fixed_minutes": 5} | cfg
    t = client.post("/api/login/test", json={"login": login, "secrets": {"LOGIN_PW": "pw-123456"}}).json()
    assert t["header"] == header and t["expiry_source"] == "fixed 5 min" and t["jwt"] == {}
    assert t["token_preview"] == "opaque-t…" and 290 < t["expires_in"] <= 300


def test_login_with_wrong_field_types_is_a_400(client):
    c = TestClient(web.app, raise_server_exceptions=False)
    assert c.post("/api/login/test", json={"login": {"url": 123}}).status_code == 400
    assert c.post("/api/login/test", json={"login": LOGIN | {"token_path": 7}}).status_code == 400


def test_secret_that_cannot_be_decrypted_is_a_clear_400(client, data, monkeypatch):
    pid = _create(client)
    client.put(f"/api/projects/{pid}/secrets/LOGIN_PW", json={"value": "pw-123456"})
    monkeypatch.setenv("SPRAT_SECRET_KEY", "a different passphrase")
    web.configure(data)  # new key: the stored value can't be decrypted
    r = client.post("/api/login/test", json={"login": LOGIN, "project_id": pid})
    assert r.status_code == 400 and "can't be decrypted" in r.text
    r = client.post(f"/api/projects/{pid}/runs", json={})
    assert r.status_code == 400 and "can't be decrypted" in r.text
    assert client.post(f"/api/projects/{pid}/refresh").status_code == 400


# ---------------- discover ----------------

def test_discover_lists_operations_with_frontend_fields(client):
    res = client.post("/api/discover", json={"url": "fake.test/openapi.json"}).json()  # scheme added
    assert res["message"] == "" and len(res["specs"]) == 1
    s = res["specs"][0]
    assert s["url"] == "http://fake.test/openapi.json" and s["base_url"] == "http://fake.test"
    assert s["title"] == "Shop" and s["api_version"] == "2.1" and s["spec_version"] == "openapi3"
    ops = {o["label"]: o for o in s["ops"]}
    assert list(ops) == LABELS
    assert ops["GET /a"] == {"method": "get", "path": "/a", "label": "GET /a", "secured": False, "has_body": False,
                             "path_params": [], "summary": "List A", "tags": ["t1"], "operation_id": "listA",
                             "deprecated": False}
    assert ops["GET /b"]["secured"] and ops["GET /b"]["deprecated"]
    assert ops["GET /items/{id}"]["path_params"] == ["id"]


def test_discover_nothing_found_explains(client):
    res = client.post("/api/discover", json={"url": "http://nospec.test/app"}).json()
    assert res["specs"] == [] and res["tried"] > 5 and "No Swagger/OpenAPI document found" in res["message"]


def test_discover_reports_spec_that_fails_to_load(client):
    res = client.post("/api/discover", json={"url": "http://fake.test/flaky/openapi.json"}).json()
    s = res["specs"][0]
    assert s["ops"] == [] and "500" in s["error"]


def test_discover_sends_headers(client, monkeypatch):
    monkeypatch.setenv("SPRAT_SPEC_KEY", "spec-key-123456")
    res = client.post("/api/discover", json={"url": "http://fake.test/private/openapi.json",
                                             "headers": "X-Key: ${SPRAT_SPEC_KEY}"}).json()
    assert res["specs"][0]["url"] == "http://fake.test/private/openapi.json" and len(res["specs"][0]["ops"]) == 4


@pytest.mark.parametrize("headers,text", [("X-Key: ${SPRAT_UNSET_VAR}", "SPRAT_UNSET_VAR"),
                                          ("no colon here", "Name: value")])
def test_discover_header_errors(client, monkeypatch, headers, text):
    monkeypatch.delenv("SPRAT_UNSET_VAR", raising=False)
    r = client.post("/api/discover", json={"url": "http://fake.test", "headers": headers})
    assert r.status_code == 400 and text in r.text


def test_discover_validation(client):
    assert client.post("/api/discover", json={}).status_code == 422
    assert client.post("/api/discover", json={"url": ["x"]}).status_code == 422


# ---------------- projects ----------------

def test_create_minimal_project_and_defaults(client, data):
    r = client.post("/api/projects", json={"name": "Minimal", "spec": "http://fake.test/openapi.json"})
    assert r.status_code == 200 and r.json() == {"id": "minimal"}
    p = client.get("/api/projects/minimal").json()
    assert p["stages"] == ALL_STAGES and p["max_examples"] == 50 and p["fail_on"] == "high"
    assert p["description"] == "" and p["base_url"] == "" and p["bola"] == [] and p["exclude_paths"] == []
    assert p["login_a"] is None and p["login_b"] is None and p["running"] is None and p["secrets"] == []
    assert p["spec_info"] == {"title": "Shop", "api_version": "2.1", "version": "openapi3",
                              "base_url": "http://fake.test", "from_page": False}
    assert [o["label"] for o in p["operations"]] == LABELS and all(o["excluded"] is False for o in p["operations"])
    assert p["op_status"] == {} and p["created"] <= p["updated"] <= p["refreshed"] + 1
    assert (data / "projects" / "minimal.json").is_file()


def test_slug_collisions_and_fallback(client):
    a = _create(client, name="My Shop API!")
    b = _create(client, name="my shop api")
    c = _create(client, name="!!!")
    d = _create(client, name="Ünïcödé " + "x" * 60)
    assert a == "my-shop-api" and b.startswith("my-shop-api-") and len(b) == len(a) + 5
    assert c == "project" and len(d) <= 40 and d.startswith("n-c-d-")
    assert sorted(p["id"] for p in client.get("/api/projects").json()) == sorted([a, b, c, d])


@pytest.mark.parametrize("change,status,text", [
    ({"name": "   "}, 400, "Name is required"),
    ({"name": None}, 422, ""),
    ({"spec": None}, 422, ""),
    ({"stages": "authz"}, 422, ""),
    ({"stages": ["authz", "pentest"]}, 400, "Unknown stage"),
    ({"max_examples": "lots"}, 422, ""),
    ({"no_mutating_authz": "maybe"}, 422, ""),
    ({"exclude_paths": "^/a$"}, 422, ""),
    ({"bola": [{"method": "GET"}]}, 422, ""),
    ({"headers": "Authorization Bearer x"}, 400, "Name: value"),
    ({"headers_b": "\n\njust-a-token\n"}, 400, "Name: value"),
    ({"spec": "http://fake.test/notaspec"}, 400, "Could not load spec"),
    ({"spec": "http://nospec.test/openapi.json"}, 400, "Could not load spec"),
    ({"spec": "C:/definitely/not/here.json"}, 400, "Could not load spec"),
    ({"login_a": {"url": "http://fake.test/auth/login", "token_path": ""}}, 400, "User A: say where"),
    ({"login_b": LOGIN | {"token_type": "x"}}, 400, "User B: unknown token type"),
    ({"secrets": {"OK": 1}}, 422, ""),
])
def test_create_validation_creates_nothing(client, change, status, text):
    body = {"name": "Shop", "spec": "http://fake.test/openapi.json"} | change
    r = client.post("/api/projects", json=body)
    assert r.status_code == status and text in r.text
    assert client.get("/api/projects").json() == []


def test_create_needs_a_json_body(client):
    assert client.post("/api/projects", content=b"not json", headers={"content-type": "application/json"}) \
        .status_code == 422
    assert client.post("/api/projects").status_code == 422


def test_spec_behind_a_key_is_loaded_with_an_unsaved_secret(client, data):
    pid = _create(client, spec="http://fake.test/private/openapi.json", headers="X-Key: ${SPEC_KEY}",
                  secrets={"SPEC_KEY": "spec-key-123456"})
    p = client.get(f"/api/projects/{pid}").json()
    assert len(p["operations"]) == 4 and p["headers"] == "X-Key: ${SPEC_KEY}"
    assert b"spec-key-123456" not in (data / "projects" / f"{pid}.json").read_bytes()
    assert client.post(f"/api/projects/{pid}/refresh").json() == {"operations": 4}  # saved secret used now


def test_spec_header_with_unset_variable_still_tries_without_it(client, monkeypatch):
    monkeypatch.delenv("SPRAT_UNSET_VAR", raising=False)
    pid = _create(client, headers="Authorization: Bearer ${SPRAT_UNSET_VAR}")
    assert len(client.get(f"/api/projects/{pid}").json()["operations"]) == 4
    r = client.post(f"/api/projects/{pid}/runs", json={})  # but a run needs it
    assert r.status_code == 400 and "SPRAT_UNSET_VAR has no value" in r.text


def test_literal_header_lines_live_in_memory_only(client, data):
    pid = _create(client, headers="Authorization: Bearer literal-token-123456\nX-Env: ${SPRAT_ENV}",
                  headers_b="Authorization: Bearer token-of-b-654321")
    saved = (data / "projects" / f"{pid}.json").read_text(encoding="utf-8")
    assert "literal-token" not in saved and "token-of-b" not in saved and "${SPRAT_ENV}" in saved
    p = client.get(f"/api/projects/{pid}").json()
    assert p["headers"] == "X-Env: ${SPRAT_ENV}\nAuthorization: Bearer literal-token-123456"
    assert p["headers_b"] == "Authorization: Bearer token-of-b-654321"
    _restart(data)
    p = client.get(f"/api/projects/{pid}").json()
    assert p["headers"] == "X-Env: ${SPRAT_ENV}" and p["headers_b"] == ""


def test_blank_bola_and_exclude_entries_are_dropped(client):
    pid = _create(client, bola=[{"method": "GET", "path": "/items/{id}", "params": {"id": "7"}}, {"path": ""}],
                  exclude_paths=["^/echo$", "   ", ""])
    p = client.get(f"/api/projects/{pid}").json()
    assert p["bola"] == [{"method": "GET", "path": "/items/{id}", "params": {"id": "7"}}]
    assert p["exclude_paths"] == ["^/echo$"]
    assert [o["label"] for o in p["operations"] if o["excluded"]] == ["GET /echo"]
    assert client.get("/api/projects").json()[0]["excluded"] == 1


def test_invalid_exclude_regex_does_not_break_reads(client, data):
    pid = _create(client, exclude_paths=["^/a$"])
    f = data / "projects" / f"{pid}.json"  # saved by an older version, before patterns were checked on save
    f.write_text(json.dumps(json.loads(f.read_text(encoding="utf-8")) | {"exclude_paths": ["(", "^/a$"]}),
                 encoding="utf-8")
    assert [o["label"] for o in client.get(f"/api/projects/{pid}").json()["operations"] if o["excluded"]] == ["GET /a"]
    assert client.get("/api/projects").json()[0]["excluded"] == 1


def test_invalid_exclude_regex_is_rejected_on_save(client):
    r = client.post("/api/projects", json={"name": "Shop", "spec": "http://fake.test/openapi.json",
                                           "exclude_paths": ["(unclosed"]})
    assert r.status_code == 400


@pytest.mark.parametrize("pid", ["nope", "..", "%2e%2e", "..%5C..%5Cevil", "%2E%2E%5Cevil", "Evil", "a.b", "a_b",
                                 "C%3A%5Cevil"])
def test_project_routes_reject_unknown_and_unsafe_ids(client, tmp_path, pid):
    body = {"name": "evil", "spec": "http://fake.test/openapi.json"}
    assert client.get(f"/api/projects/{pid}").status_code == 404
    assert client.put(f"/api/projects/{pid}", json=body).status_code == 404
    assert client.delete(f"/api/projects/{pid}").status_code == 404
    assert client.post(f"/api/projects/{pid}/refresh").status_code == 404
    assert client.get(f"/api/projects/{pid}/runs").status_code == 404
    assert client.post(f"/api/projects/{pid}/runs", json={}).status_code == 404
    assert client.get(f"/api/projects/{pid}/yaml").status_code == 404
    assert not [p for p in tmp_path.rglob("*evil*")]  # nothing written anywhere


def test_update_project(client, data):
    pid = _create(client, description="old")
    spec_calls = lambda: sum(1 for c in API["calls"] if c.endswith("/openapi.json"))
    before = spec_calls()
    body = {"name": "Shop renamed", "description": "new ✓", "spec": "http://fake.test/openapi.json",
            "stages": ["authz", "types"], "max_examples": 5, "fail_on": "medium", "headers": HEADERS}
    assert client.put(f"/api/projects/{pid}", json=body).json() == {"ok": True}
    assert spec_calls() == before  # same spec: not fetched again
    p = client.get(f"/api/projects/{pid}").json()
    assert (p["id"], p["name"], p["description"], p["stages"], p["max_examples"], p["fail_on"]) == \
        (pid, "Shop renamed", "new ✓", ["authz", "types"], 5, "medium")
    assert p["updated"] >= p["created"]
    assert client.put(f"/api/projects/{pid}", json=body | {"spec": "http://fake.test/v2/openapi.json"}).status_code == 200
    p = client.get(f"/api/projects/{pid}").json()
    assert [o["label"] for o in p["operations"]] == ["GET /only-v2"] and p["spec"].endswith("/v2/openapi.json")
    r = client.put(f"/api/projects/{pid}", json=body | {"stages": ["nope"]})
    assert r.status_code == 400
    assert client.get(f"/api/projects/{pid}").json()["stages"] == ["authz", "types"]  # unchanged on disk
    r = client.put(f"/api/projects/{pid}", json=body | {"spec": "http://fake.test/notaspec"})
    assert r.status_code == 400 and "Could not load spec" in r.text
    assert client.get(f"/api/projects/{pid}").json()["spec"].endswith("/v2/openapi.json")
    assert client.patch(f"/api/projects/{pid}", json={"name": "x"}).status_code == 405
    assert client.put(f"/api/projects/{pid}", json={"name": "x"}).status_code == 422


def test_update_reloads_operations_when_none_cached(client, data):
    pid = _create(client)
    f = data / "projects" / f"{pid}.json"
    p = json.loads(f.read_text(encoding="utf-8"))
    p["operations"] = []
    f.write_text(json.dumps(p), encoding="utf-8")
    client.put(f"/api/projects/{pid}", json={"name": "Shop", "spec": "http://fake.test/openapi.json"})
    assert len(client.get(f"/api/projects/{pid}").json()["operations"]) == 4


def test_update_with_empty_name_is_refused(client):
    pid = _create(client)
    r = client.put(f"/api/projects/{pid}", json={"name": "  ", "spec": "http://fake.test/openapi.json"})
    assert r.status_code == 400


def test_refresh_picks_up_spec_changes(client):
    pid = _create(client)
    API["spec"]["paths"]["/new"] = {"post": {"requestBody": {"content": {}}, "responses": {"200": {"description": "ok"}}}}
    assert client.post(f"/api/projects/{pid}/refresh").json() == {"operations": 5}
    ops = {o["label"]: o for o in client.get(f"/api/projects/{pid}").json()["operations"]}
    assert ops["POST /new"]["has_body"] is True
    API["spec"] = {"not": "a spec"}
    r = client.post(f"/api/projects/{pid}/refresh")
    assert r.status_code == 400 and "Could not load spec" in r.text
    assert len(client.get(f"/api/projects/{pid}").json()["operations"]) == 5  # kept


def test_delete_project_removes_its_runs_and_secrets_only(client, data):
    a, b = _create(client, name="A"), _create(client, name="B")
    client.put(f"/api/projects/{a}/secrets/S_A", json={"value": "value-a"})
    client.put(f"/api/projects/{b}/secrets/S_B", json={"value": "value-b"})
    _mkrun(data, "20240101-000000-aaaaaa", a)
    _mkrun(data, "20240101-000001-aaaaab", a)
    _mkrun(data, "20240101-000002-bbbbbb", b)
    assert client.delete(f"/api/projects/{a}").json() == {"deleted_runs": 2}
    assert sorted(x.name for x in (data / "runs").iterdir()) == ["20240101-000002-bbbbbb"]
    assert not (data / "projects" / f"{a}.json").exists()
    assert client.get(f"/api/projects/{a}").status_code == 404
    assert [s["name"] for s in client.get(f"/api/projects/{b}/secrets").json()] == ["S_B"]
    assert "S_A" not in (data / "secrets.json").read_text(encoding="utf-8")
    assert client.delete(f"/api/projects/{a}").status_code == 404
    # a new project with the same name doesn't inherit anything
    a2 = _create(client, name="A")
    assert a2 == a and client.get(f"/api/projects/{a2}/secrets").json() == []
    assert client.get(f"/api/projects/{a2}/runs").json() == []


def test_list_projects_with_last_run(client, data):
    pid = _create(client)
    other = _create(client, name="Other")
    assert {p["id"]: p["last_run"] for p in client.get("/api/projects").json()} == {pid: None, other: None}
    _mkrun(data, "20240101-000000-aaaaaa", pid, stages=[_stage("authz", [("high", "GET /b"), ("high", "GET /a"),
                                                                            ("low", "")])])
    _mkrun(data, "20240102-000000-bbbbbb", pid, status="cancelled", operations=["GET /a"],
           stages=[_stage("authz", [("critical", "GET /a")])])
    _mkrun(data, "20240103-000000-cccccc", other, status="running")  # left over from a crash
    (data / "runs" / "stray-file.txt").write_text("x", encoding="utf-8")
    ps = {p["id"]: p for p in client.get("/api/projects").json()}
    assert set(ps[pid]) == {"id", "name", "description", "spec", "spec_info", "operations", "excluded", "running",
                            "last_run"}
    assert ps[pid]["operations"] == 4 and ps[pid]["running"] is None
    assert ps[pid]["last_run"] == {"id": "20240102-000000-bbbbbb", "status": "cancelled", "started": 1700000000.0,
                                   "counts": {"critical": 1}, "partial": True}
    assert ps[other]["last_run"]["status"] == "interrupted" and ps[other]["last_run"]["counts"] is None
    runs = client.get(f"/api/projects/{pid}/runs").json()
    assert [r["id"] for r in runs] == ["20240102-000000-bbbbbb", "20240101-000000-aaaaaa"]  # newest first
    assert set(runs[0]) == {"id", "status", "started", "finished", "operations", "error", "stages", "counts"}
    assert runs[0]["stages"] == ["authz"]
    assert runs[1]["counts"] == {"high": 2, "low": 1}


def test_op_status_comes_from_newest_finished_run_per_api(client, data):
    pid = _create(client)
    _mkrun(data, "20231231-000000-000000", pid, tested=["GET /echo"])  # no report: ignored
    _mkrun(data, "20240101-000000-aaaaaa", pid, tested=["GET /a", "GET /b"],
           stages=[_stage("authz", [("medium", "GET /a"), ("high", "GET /b"), ("low", "GET /a")])])
    _mkrun(data, "20240102-000000-bbbbbb", pid, status="cancelled", tested=["GET /b", "GET /gone"],
           stages=[_stage("authz", [("low", "GET /b"), ("critical", "GET /b"), ("high", "GET /a")]),
                   _stage("zap", [("high", "GET /b")], status="cancelled")])
    _mkrun(data, "20240103-000000-cccccc", pid, status="error", tested=["GET /a"], stages=[_stage("authz")])
    _mkrun(data, "20240104-000000-dddddd", pid, status="done", tested=None, stages=[_stage("authz")])
    _mkrun(data, "20240105-000000-eeeeee", "other-project", tested=["GET /a"], stages=[_stage("authz")])
    st = client.get(f"/api/projects/{pid}").json()["op_status"]
    assert st == {
        "GET /b": {"run_id": "20240102-000000-bbbbbb", "started": 1700000000.0, "partial": True,
                   "counts": {"low": 1, "critical": 1}, "max": "critical",
                   "stages": {"authz": {"run_id": "20240102-000000-bbbbbb", "started": 1700000000.0,
                                        "counts": {"low": 1, "critical": 1}}}},
        "GET /a": {"run_id": "20240101-000000-aaaaaa", "started": 1700000000.0, "partial": False,
                   "counts": {"medium": 1, "low": 1}, "max": "medium",
                   "stages": {"authz": {"run_id": "20240101-000000-aaaaaa", "started": 1700000000.0,
                                        "counts": {"medium": 1, "low": 1}}}},
    }


def test_op_status_with_clean_run_and_early_stop(client, data):
    pid = _create(client)
    _mkrun(data, "20240101-000000-aaaaaa", pid, tested=["GET /a"], stages=[_stage("authz", [("high", "GET /a")])])
    _mkrun(data, "20240102-000000-bbbbbb", pid, tested=LABELS, stages=[_stage("authz")])
    st = client.get(f"/api/projects/{pid}").json()["op_status"]
    assert set(st) == set(LABELS) and all(s["max"] is None and s["counts"] == {} for s in st.values())


def test_op_status_merges_stages_from_different_runs(client, data):
    """A single-stage run updates that stage only; the other stages keep their newest earlier result."""
    pid = _create(client, stages=["lint", "authz", "zap"])
    _mkrun(data, "20240101-000000-aaaaaa", pid, tested=["GET /a"], started=1700000000.0,
           stages=[_stage("lint", [("low", "GET /a")]), _stage("authz", [("high", "GET /a")]),
                   _stage("zap", [("medium", "GET /a")])])
    _mkrun(data, "20240102-000000-bbbbbb", pid, tested=["GET /a"], started=1700000100.0,
           stages=[_stage("lint")])                                   # lint-only rerun: lint is now clean
    _mkrun(data, "20240103-000000-cccccc", pid, tested=["GET /a"], started=1700000200.0,
           stages=[_stage("zap", status="skipped")])                  # skipped zap doesn't replace the real one
    a = client.get(f"/api/projects/{pid}").json()["op_status"]["GET /a"]
    assert {k: v["run_id"] for k, v in a["stages"].items()} == {
        "lint": "20240102-000000-bbbbbb", "authz": "20240101-000000-aaaaaa", "zap": "20240101-000000-aaaaaa"}
    assert a["counts"] == {"high": 1, "medium": 1} and a["max"] == "high"
    assert a["run_id"] == "20240102-000000-bbbbbb" and a["partial"] is False


def test_op_status_partial_when_a_project_stage_never_ran(client, data):
    pid = _create(client, stages=["lint", "authz"])
    _mkrun(data, "20240101-000000-aaaaaa", pid, tested=["GET /a"], stages=[_stage("lint")])
    a = client.get(f"/api/projects/{pid}").json()["op_status"]["GET /a"]
    assert list(a["stages"]) == ["lint"] and a["partial"] is True and a["max"] is None


def test_run_with_chosen_stages(client, pipe):
    pid = _create(client, stages=["authz"])
    rid = _start(client, pid, stages=["zap", "lint", "zap"])
    _wait(client, rid)
    assert pipe.cfgs[-1].stages == ["lint", "zap"]                    # pipeline order, no duplicates
    assert client.get(f"/api/runs/{rid}").json()["stages_requested"] == ["lint", "zap"]
    assert client.get(f"/api/projects/{pid}").json()["stages"] == ["authz"]  # project default unchanged
    for bad, msg in (([], "at least one"), (["nope"], "Unknown stage")):
        r = client.post(f"/api/projects/{pid}/runs", json={"stages": bad})
        assert r.status_code == 400 and msg in r.text


def test_lint_only_run_needs_no_token(client, pipe):
    pid = _create(client, headers="")
    assert client.post(f"/api/projects/{pid}/runs", json={"stages": ["authz"]}).status_code == 428
    assert _wait(client, _start(client, pid, stages=["lint"]))["status"] == "done"
    _wait(client, _start(client, pid, force=True))                     # without stages: the project's own
    assert pipe.cfgs[-1].stages == ["authz"]


def test_yaml_export(client, monkeypatch):
    pid = _create(client, headers="Authorization: Bearer literal-token-123456\nX-Env: ${SPRAT_ENV}",
                  headers_b="X-B: literal-b-token-1", login_b=LOGIN, exclude_paths=["^/echo$"],
                  bola=[{"path": "/items/{id}", "params": {"id": "1"}}], max_examples=7, fail_on="critical")
    r = client.get(f"/api/projects/{pid}/yaml")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    assert r.text.startswith("# sprat config for project 'Shop'\n")
    assert "literal-token" not in r.text and "literal-b-token" not in r.text
    d = yaml.safe_load(r.text)
    assert d["spec"] == "http://fake.test/openapi.json" and d["out_dir"] == f"reports/{pid}"
    assert d["headers"] == {"X-Env": "${SPRAT_ENV}", "Authorization": "<set me>"}
    assert d["headers_b"] == {"X-B": "<set me>"}
    assert d["stages"] == ["authz"] and d["max_examples"] == 7 and d["fail_on"] == "critical"
    assert d["exclude_paths"] == ["^/echo$"] and d["bola"][0]["path"] == "/items/{id}"
    assert "login_a" not in d and d["login_b"]["body"] == LOGIN["body"]  # ${VAR} kept, never a value
    for k in ("timeout", "zap_image", "types_max_fields", "operations", "cancel", "on_progress", "testlog",
              "title", "auth_a", "auth_b"):
        assert k not in d, k


def test_yaml_export_loads_in_the_cli(client, tmp_path, monkeypatch):
    monkeypatch.setenv("SPRAT_ENV", "x")
    pid = _create(client, headers="X-Env: ${SPRAT_ENV}")
    f = tmp_path / "exported.yaml"
    f.write_text(client.get(f"/api/projects/{pid}/yaml").text, encoding="utf-8")
    cfg = load_config(str(f))
    assert cfg.spec == "http://fake.test/openapi.json" and cfg.headers == {"X-Env": "x"}


# ---------------- runs: starting ----------------

def test_run_needs_a_token_for_secured_apis(client, pipe):
    pid = _create(client, headers="")
    r = client.post(f"/api/projects/{pid}/runs", json={})
    assert r.status_code == 428
    detail = json.loads(r.json()["detail"])
    assert detail["code"] == "NO_TOKEN" and "2 of the 4 APIs" in detail["message"]
    r = client.post(f"/api/projects/{pid}/runs", json={"operations": ["GET /b"]})
    assert r.status_code == 428 and "1 of the 1 APIs" in r.text
    _wait(client, _start(client, pid, operations=["GET /a"]))  # public only: no token needed
    rid = _start(client, pid, force=True)
    assert _wait(client, rid)["status"] == "done"


def test_run_selection_validation(client, pipe):
    pid = _create(client, exclude_paths=["^/echo$"])
    r = client.post(f"/api/projects/{pid}/runs", json={"operations": ["GET /a", "GET /nope", "POST /a"]})
    assert r.status_code == 400 and "GET /nope" in r.text and "POST /a" in r.text and "Refresh" in r.text
    r = client.post(f"/api/projects/{pid}/runs", json={"operations": ["GET /echo"]})
    assert r.status_code == 400 and "excluded" in r.text
    assert client.post(f"/api/projects/{pid}/runs", json={"operations": "GET /a"}).status_code == 422
    assert client.post(f"/api/projects/{pid}/runs", json={"force": "sometimes"}).status_code == 422
    assert client.get(f"/api/projects/{pid}/runs").json() == []  # nothing started
    rid = _start(client, pid, operations=["GET /a", "GET /echo"])  # excluded ones are dropped
    assert pipe.cfgs[-1].operations == ["GET /a"]
    assert _wait(client, rid)["operations"] == ["GET /a"]


def test_run_refused_when_every_api_is_excluded(client, pipe):
    pid = _create(client, exclude_paths=["."])
    r = client.post(f"/api/projects/{pid}/runs", json={})
    assert r.status_code == 400 and "Every API is excluded" in r.text


def test_run_settings_reach_the_pipeline_and_secrets_stay_masked(client, pipe, data, monkeypatch):
    monkeypatch.setenv("SPRAT_ENV", "env-value-abcdef")
    pid = _create(client, headers="Authorization: Bearer literal-token-123456\nX-Env: ${SPRAT_ENV}",
                  headers_b="Authorization: Bearer token-of-b-654321", stages=["authz", "types"], max_examples=9,
                  fail_on="low", no_mutating_authz=True, base_url="http://override.test", exclude_paths=["^/echo$"],
                  bola=[{"method": "get", "path": "/b?x=1"}, {"method": "GET", "path": "/a"}],
                  secrets={"PROJECT_SECRET": "project-secret-xyz"})
    pipe.gate.clear()
    rid = _start(client, pid, operations=["GET /b", "GET /echo"])
    pipe.started.wait(5)
    cfg = pipe.cfgs[-1]
    assert cfg.headers == {"Authorization": "Bearer literal-token-123456", "X-Env": "env-value-abcdef"}
    assert cfg.headers_b == {"Authorization": "Bearer token-of-b-654321"}
    assert (cfg.spec, cfg.base_url, cfg.stages, cfg.max_examples, cfg.fail_on, cfg.no_mutating_authz, cfg.title) == \
        ("http://fake.test/openapi.json", "http://override.test", ["authz", "types"], 9, "low", True, "Shop")
    assert cfg.operations == ["GET /b"] and cfg.exclude_paths == ["^/echo$"]
    assert cfg.bola == [{"method": "get", "path": "/b?x=1", "params": {}}]  # only scenarios of selected APIs
    assert cfg.variables == {"PROJECT_SECRET": "project-secret-xyz"}
    assert Path(cfg.out_dir) == data / "runs" / rid and cfg.auth_a is None
    run = client.get(f"/api/runs/{rid}").json()
    assert run["headers"] == {"Authorization": "***", "X-Env": "***"} and run["headers_b"] == {"Authorization": "***"}
    on_disk = (data / "runs" / rid / "run.json").read_text(encoding="utf-8")
    for s in ("literal-token", "env-value", "token-of-b", "project-secret"):
        assert s not in on_disk and s not in json.dumps(run)
    pipe.gate.set()
    assert _wait(client, rid)["status"] == "done"


def test_run_lifecycle_and_response_shape(client, pipe, data):
    pid = _create(client, stages=["authz", "types", "lint"])
    pipe.status = {"types": "error", "lint": "skipped"}
    pipe.findings = {"authz": [{"severity": "high", "title": "t", "operation": "GET /b", "detail": ""}]}
    pipe.gate.clear()
    rid = _start(client, pid)
    pipe.started.wait(5)
    run = client.get(f"/api/runs/{rid}").json()
    assert {"id", "project_id", "project_name", "status", "started", "finished", "error", "spec", "base_url",
            "operations", "tested", "stages_requested", "stages", "fail_on", "headers", "headers_b", "spec_info",
            "activity", "feed", "exclude_paths", "bola", "report", "files"} <= set(run)
    assert run["status"] == "running" and run["finished"] is None and run["report"] is None
    assert run["project_id"] == pid and run["project_name"] == "Shop" and run["operations"] == []
    assert run["stages"]["authz"]["status"] == "running" and run["stages"]["types"] == {"status": "pending"}
    assert run["spec_info"] == {"version": "openapi3", "operations": 2, "base_url": "http://fake.test"}
    assert run["tested"] == ["GET /a", "GET /b"] and run["activity"]["msg"] == "Starting"
    assert run["files"] == ["test-log.ndjson"]  # run.json is not listed
    p = client.get(f"/api/projects/{pid}").json()
    assert p["running"] == rid
    assert client.get("/api/projects").json()[0]["running"] == rid
    pipe.gate.set()
    run = _wait(client, rid)
    assert run["status"] == "done" and run["finished"] >= run["started"] and run["error"] is None
    assert run["stages"]["authz"] == {"status": "ok", "findings": 1, "note": "", "duration": 0.1}
    assert run["stages"]["types"]["status"] == "error" and run["stages"]["lint"]["status"] == "skipped"
    levels = {f["stage"]: f["level"] for f in run["feed"] if f["msg"].startswith("Finished")}
    assert levels == {"authz": "ok", "types": "bad", "lint": "warn"}
    assert run["report"]["stages"][0]["findings"][0]["severity"] == "high"
    assert run["files"] == ["report.json", "test-log.ndjson"]
    assert json.loads((data / "runs" / rid / "run.json").read_text(encoding="utf-8"))["status"] == "done"
    assert "events" not in json.loads((data / "runs" / rid / "run.json").read_text(encoding="utf-8"))
    assert client.get(f"/api/projects/{pid}").json()["running"] is None


def test_feed_skips_per_field_chatter_and_is_capped(client, pipe):
    pid = _create(client)
    msg = lambda i, stage="authz", m=None: {"stage": stage, "msg": m or f"m{i}", "op": "GET /a", "done": i,
                                            "total": 500, "level": "info"}
    pipe.progress = [msg(i) for i in range(450)] + [msg(0, "authz", "Field kept: authz isn't filtered"),
                                                    msg(0, "types", "Field qty: sent \"1\"")]
    pipe.gate.clear()
    rid = _start(client, pid)
    pipe.started.wait(5)
    state = web._runs[rid]
    assert len(state["feed"]) == web.FEED_MAX
    assert not any(f["msg"].startswith("Field qty") for f in state["feed"])
    assert state["feed"][-1]["msg"] == "Field kept: authz isn't filtered"
    assert state["activity"]["msg"].startswith("Field qty") and state["activity"]["t"] > 0  # still shown as "Now"
    run = client.get(f"/api/runs/{rid}").json()
    assert len(run["feed"]) == 150 and run["feed"][-2]["msg"] == "m449"
    pipe.gate.set()
    _wait(client, rid)


def test_one_run_per_project_but_projects_run_in_parallel(client, pipe, data):
    a, b = _create(client, name="A"), _create(client, name="B")
    pipe.gate.clear()
    ra = _start(client, a)
    rb = _start(client, b)
    r = client.post(f"/api/projects/{a}/runs", json={})
    assert r.status_code == 409 and ra in r.text
    assert client.delete(f"/api/projects/{a}").status_code == 409
    assert (data / "projects" / f"{a}.json").is_file()
    assert {p["id"]: p["running"] for p in client.get("/api/projects").json()} == {a: ra, b: rb}
    assert client.post(f"/api/runs/{ra}/cancel").json() == {"ok": True}
    assert client.get(f"/api/runs/{ra}").json()["status"] in ("stopping", "cancelled")
    assert _wait(client, ra)["status"] == "cancelled"
    assert client.get(f"/api/runs/{rb}").json()["status"] == "running"  # B unaffected
    pipe.gate.set()
    assert _wait(client, rb)["status"] == "done"
    rc = _start(client, a)  # A can run again
    assert _wait(client, rc)["status"] == "done"


def test_cancel(client, pipe):
    pid = _create(client)
    pipe.gate.clear()
    rid = _start(client, pid)
    assert client.post(f"/api/runs/{rid}/cancel").status_code == 200
    run = _wait(client, rid)
    assert run["status"] == "cancelled" and run["stages"]["authz"]["status"] == "cancelled"
    assert client.post(f"/api/runs/{rid}/cancel").status_code == 409
    assert rid not in web._cancels
    # a stopped run still has its partial results
    assert run["report"] is not None and client.get(f"/api/runs/{rid}/log").json()["available"]


def test_cancel_when_the_pipeline_just_returns(client, pipe):
    pid = _create(client)
    pipe.gate.clear()
    pipe.ignore_cancel = True
    rid = _start(client, pid)
    client.post(f"/api/runs/{rid}/cancel")
    assert _wait(client, rid)["status"] == "cancelled"


@pytest.mark.parametrize("rid", ["20240101-000000-abcdef", "nope", "..", "%2e%2e"])
def test_cancel_unknown_run_is_refused(client, rid):
    r = client.post(f"/api/runs/{rid}/cancel")
    assert 400 <= r.status_code < 500


def test_cancel_unknown_run_is_404(client):
    assert client.post("/api/runs/20240101-000000-abcdef/cancel").status_code == 404


def test_cancel_finished_run_from_disk_is_409(client, data):
    _mkrun(data, "20240101-000000-aaaaaa", "shop")
    assert client.post("/api/runs/20240101-000000-aaaaaa/cancel").status_code == 409


def test_pipeline_error_is_reported(client, pipe):
    pid = _create(client)
    pipe.error = RuntimeError("spec exploded")
    run = _wait(client, _start(client, pid))
    assert run["status"] == "error" and run["error"] == "RuntimeError: spec exploded"
    assert run["finished"] is not None
    pipe.gate.clear()
    rid = _start(client, pid)  # an error while stopping counts as stopped
    pipe.ignore_cancel = True
    client.post(f"/api/runs/{rid}/cancel")
    assert _wait(client, rid)["status"] == "cancelled"


def test_automatic_login_runs(client, pipe, monkeypatch):
    monkeypatch.setenv("LOGIN_PW", "pw-123456")
    pid = _create(client, headers="", headers_b="", login_a=LOGIN,
                  login_b=LOGIN | {"body": '{"email": "b@x.test", "password": "${LOGIN_PW}"}'})
    p = client.get(f"/api/projects/{pid}").json()
    assert p["login_a"]["token_path"] == "data.accessToken" and p["login_a"]["token_type"] == "bearer"
    rid = _start(client, pid)  # no 428: logging in provides the token
    run = _wait(client, rid)
    assert run["headers"] == {"login": "automatic"} and run["headers_b"] == {"login": "automatic"}
    cfg = pipe.cfgs[-1]
    assert cfg.auth_a.token and cfg.auth_b.token and cfg.auth_a.token != cfg.auth_b.token
    assert cfg.login_a["url"] == LOGIN["url"]
    assert cfg.auth_a.token not in json.dumps(run)
    monkeypatch.setenv("LOGIN_PW", "wrong")
    r = client.post(f"/api/projects/{pid}/runs", json={})
    assert r.status_code == 400 and "Login failed, so nothing was tested" in r.text and "user A" in r.text


def test_login_b_failure_blocks_the_run(client, pipe, monkeypatch):
    monkeypatch.setenv("LOGIN_PW", "pw-123456")
    pid = _create(client, login_b=LOGIN | {"url": "http://fake.test/auth/login",
                                           "body": '{"email": "b@x.test", "password": "${LOGIN_B_PW}"}'})
    monkeypatch.delenv("LOGIN_B_PW", raising=False)
    r = client.post(f"/api/projects/{pid}/runs", json={})
    assert r.status_code == 400 and "user B" in r.text and "LOGIN_B_PW" in r.text


# ---------------- runs: persistence ----------------

def test_runs_survive_a_restart(client, pipe, data):
    pid = _create(client)
    pipe.entries = [{"stage": "authz", "scenario": "s", "operation": "GET /a", "verdict": "pass"}]
    pipe.findings = {"authz": [{"severity": "medium", "title": "t", "operation": "GET /a", "detail": ""}]}
    rid = _start(client, pid, operations=["GET /a"])
    before = _wait(client, rid)
    _restart(data)
    after = client.get(f"/api/runs/{rid}").json()
    for k in ("status", "started", "finished", "tested", "stages", "report", "files", "headers", "operations"):
        assert after[k] == before[k], k
    assert after["feed"] == before["feed"]
    assert client.get("/api/projects").json()[0]["last_run"]["counts"] == {"medium": 1}
    assert client.get(f"/api/projects/{pid}").json()["op_status"]["GET /a"]["max"] == "medium"
    assert client.get(f"/api/runs/{rid}/log").json()["total"] == 1
    assert client.get(f"/api/runs/{rid}/download/ndjson").status_code == 200


def test_run_interrupted_by_a_restart(client, pipe, data):
    pid = _create(client)
    pipe.gate.clear()
    rid = _start(client, pid)
    pipe.started.wait(5)
    _restart(data)
    run = client.get(f"/api/runs/{rid}").json()
    assert run["status"] == "interrupted"
    assert client.get(f"/api/projects/{pid}").json()["running"] is None
    assert client.post(f"/api/runs/{rid}/cancel").status_code == 409
    pipe.gate.set()  # the orphaned worker finishes and records its real end
    _until(lambda: json.loads((data / "runs" / rid / "run.json").read_text(encoding="utf-8"))["status"] == "done")
    rid2 = _start(client, pid, force=True)  # allowed again (force: the literal token died with the restart)
    assert _wait(client, rid2)["status"] == "done"


def test_configure_switches_data_dir(client, tmp_path, data):
    pid = _create(client)
    client.put(f"/api/projects/{pid}/secrets/S_ONE", json={"value": "value-one"})
    other = tmp_path / "other"
    web.configure(other)
    assert client.get("/api/projects").json() == []
    assert client.get("/api/vars", params={"names": "S_ONE", "project": pid}).json()[0]["source"] is None
    web.configure(data)
    assert [p["id"] for p in client.get("/api/projects").json()] == [pid]
    assert client.get(f"/api/projects/{pid}/secrets").json()[0]["name"] == "S_ONE"
    assert web.DATA == data.resolve() and web.runs_dir() == data.resolve() / "runs"


@pytest.mark.parametrize("rid", ["20240101-000000-abcdef", "..", "%2e%2e", "a.b", "..%5Cprojects"])
def test_unknown_or_unsafe_run_ids(client, rid):
    assert client.get(f"/api/runs/{rid}").status_code == 404
    assert client.get(f"/api/runs/{rid}/log").status_code == 404
    assert client.get(f"/api/runs/{rid}/log/1").status_code == 404
    assert client.get(f"/api/runs/{rid}/download/ndjson").status_code == 404
    assert client.get(f"/api/runs/{rid}/download/html").status_code == 404


def test_run_json_without_its_dir_contents(client, data):
    d = _mkrun(data, "20240101-000000-aaaaaa", "shop")
    (d / ".hidden").write_text("x", encoding="utf-8")
    (d / "sub").mkdir()
    run = client.get("/api/runs/20240101-000000-aaaaaa").json()
    assert run["files"] == [] and run["report"] is None and run["feed"] == []


# ---------------- test log ----------------

def _log_entries():
    return [
        dict(stage="authz", scenario="No token", operation="GET /a", verdict="pass", expected="Refused",
             explanation="x" * 400, request={"method": "GET", "url": "http://fake.test/a"},
             response={"status": 401, "elapsed_ms": 5.5}),
        dict(stage="authz", scenario="Fake token", operation="GET /b", verdict="fail",
             request={"method": "GET", "url": "http://fake.test/b"}, response={"status": 200},
             details={"failures": ["f" * 300, "second"]}),
        dict(stage="conformance", scenario="Random data", operation="GET /b", verdict="fail",
             details={"problem": "Schema mismatch"}),
        dict(stage="conformance", scenario="Passive", operation="", verdict="info",
             details={"passive_issues": ["Missing HSTS", "Server header"]}),
        dict(stage="types", scenario="qty as string", operation="GET /a", verdict="error", details={"error": "timeout"}),
        dict(stage="types", scenario="Valid request first", operation="GET /a", verdict="pass",
             request={"method": "POST", "url": "http://fake.test/a", "body": {"name": "Zoë Ünique"}}),
        dict(stage="zap", scenario="Scan summary", operation="", verdict="info"),
    ]


@pytest.fixture
def logrun(client, data):
    _mkrun(data, "20240101-000000-aaaaaa", "shop", entries=_log_entries())
    return "20240101-000000-aaaaaa"


def _log(client, rid, **params):
    r = client.get(f"/api/runs/{rid}/log", params=params)
    assert r.status_code == 200, r.text
    return r.json()


def test_log_unfiltered(client, logrun):
    log = _log(client, logrun)
    assert log["available"] and log["total"] == 7 and [i["seq"] for i in log["items"]] == list(range(1, 8))
    assert log["verdicts"] == {"pass": 2, "fail": 2, "info": 2, "error": 1}
    assert log["stages"] == {"authz": 2, "conformance": 2, "types": 2, "zap": 1}
    assert log["operations"] == ["GET /a", "GET /b"]
    first = log["items"][0]
    assert set(first) == {"seq", "ts", "stage", "operation", "scenario", "expected", "verdict", "explanation",
                          "method", "url", "status", "elapsed_ms", "problem", "severity", "cause", "spec_issue"}
    fails = [i for i in log["items"] if i["verdict"] == "fail"]
    assert fails and all(i["severity"] and i["cause"] for i in fails)
    assert all(i["severity"] is None for i in log["items"] if i["verdict"] != "fail")
    assert (first["method"], first["url"], first["status"], first["elapsed_ms"]) == ("GET", "http://fake.test/a", 401,
                                                                                    5.5)
    assert len(first["explanation"]) == 300 and first["problem"] == "" and first["expected"] == "Refused"
    problems = [i["problem"] for i in log["items"]]
    assert problems[1] == "f" * 200 and problems[2] == "Schema mismatch"
    assert problems[3] == "Missing HSTS; Server header" and problems[4] == "timeout" and problems[6] == ""
    assert log["items"][6]["method"] == "" and log["items"][6]["status"] is None


@pytest.mark.parametrize("params,seqs,stages", [
    ({"stage": "types"}, [5, 6], {"authz": 2, "conformance": 2, "types": 2, "zap": 1}),  # stage tabs keep counts
    ({"op": "GET /b"}, [2, 3], {"authz": 1, "conformance": 1}),
    ({"op": "-"}, [4, 7], {"conformance": 1, "zap": 1}),
    ({"op": "GET /nope"}, [], {}),
    ({"verdict": "fail"}, [2, 3], {"authz": 1, "conformance": 1}),
    ({"verdict": "error"}, [5], {"types": 1}),
    ({"q": "ZOË ünique"}, [6], {"types": 1}),
    ({"q": "missing hsts"}, [4], {"conformance": 1}),
    ({"q": "fake.test/b"}, [2], {"authz": 1}),
    ({"q": "no such text"}, [], {}),
    ({"stage": "authz", "verdict": "fail", "op": "GET /b"}, [2], {"authz": 1, "conformance": 1}),
    ({"stage": "zap", "op": "GET /a"}, [], {"authz": 1, "types": 2}),
])
def test_log_filters(client, logrun, params, seqs, stages):
    log = _log(client, logrun, **params)
    assert [i["seq"] for i in log["items"]] == seqs and log["total"] == len(seqs)
    assert log["stages"] == stages
    assert sum(log["verdicts"].values()) == len(seqs)


def test_log_operations_list_follows_filters(client, logrun):
    assert _log(client, logrun, stage="types")["operations"] == ["GET /a"]
    assert _log(client, logrun, op="-")["operations"] == []


def test_log_pagination(client, logrun):
    pages = [_log(client, logrun, offset=o, limit=3) for o in (0, 3, 6, 9)]
    assert [[i["seq"] for i in p["items"]] for p in pages] == [[1, 2, 3], [4, 5, 6], [7], []]
    assert all(p["total"] == 7 and p["verdicts"] == pages[0]["verdicts"] for p in pages)
    assert _log(client, logrun, limit=0)["items"] == []
    assert [i["seq"] for i in _log(client, logrun, verdict="fail", offset=1, limit=5)["items"]] == [3]
    assert client.get(f"/api/runs/{logrun}/log", params={"offset": "x"}).status_code == 422
    assert client.get(f"/api/runs/{logrun}/log", params={"limit": "1.5"}).status_code == 422


def test_log_of_run_without_test_log(client, data):
    _mkrun(data, "20240101-000000-aaaaaa", "shop")
    log = _log(client, "20240101-000000-aaaaaa")
    assert log == {"total": 0, "items": [], "verdicts": {}, "stages": {}, "operations": [], "available": False}


def test_log_entry(client, logrun):
    e = client.get(f"/api/runs/{logrun}/log/6").json()
    assert e["seq"] == 6 and json.loads(e["request"]["body"]) == {"name": "Zoë Ünique"}
    assert set(e) == {"seq", "ts", "stage", "operation", "scenario", "expected", "verdict", "explanation", "request",
                      "response", "details", "triage"}
    assert client.get(f"/api/runs/{logrun}/log/99").status_code == 404
    assert client.get(f"/api/runs/{logrun}/log/-1").status_code == 404
    assert client.get(f"/api/runs/{logrun}/log/abc").status_code == 422


def test_log_survives_corrupt_lines(client, data, logrun):
    with open(data / "runs" / logrun / "test-log.ndjson", "a", encoding="utf-8") as f:
        f.write("{broken\n\n")
    assert _log(client, logrun)["total"] == 7


# ---------------- downloads ----------------

def _project_with_run(client, data, status="done", **meta):
    pid = _create(client, name="Café API!")
    d = _mkrun(data, "20240101-000000-aaaaaa", pid, status=status, name="Café API!", entries=_log_entries(),
               stages=[_stage("authz", [("high", "GET /b")])], tested=LABELS, **meta)
    (d / "spec.json").write_text(json.dumps(SPEC_DOC), encoding="utf-8")
    return pid, d, "20240101-000000-aaaaaa"


def test_download_ndjson_and_csv(client, data):
    _, d, rid = _project_with_run(client, data)
    base = f"sprat-caf-api-{rid}"
    r = client.get(f"/api/runs/{rid}/download/ndjson")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/x-ndjson")
    assert f'filename="{base}-test-log.ndjson"' in r.headers["content-disposition"]
    assert [json.loads(l)["seq"] for l in r.text.splitlines()] == list(range(1, 8))
    r = client.get(f"/api/runs/{rid}/download/csv")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert f'filename="{base}-test-log.csv"' in r.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(r.content.decode("utf-8-sig"))))
    assert len(rows) == 7 and rows[5]["request_body"] == '{"name": "Zoë Ünique"}'
    assert rows[3]["operation"] == "" and rows[1]["explanation"] == "f" * 300 + " | second"


def test_csv_is_rebuilt_only_when_stale(client, data):
    _, d, rid = _project_with_run(client, data)
    csv_path = d / "test-log.csv"
    csv_path.write_bytes(b"cached\n")
    later = (d / "test-log.ndjson").stat().st_mtime + 10
    os.utime(csv_path, (later, later))
    assert client.get(f"/api/runs/{rid}/download/csv").text == "cached\n"
    os.utime(csv_path, (later - 100, later - 100))  # older than the log: regenerated
    assert client.get(f"/api/runs/{rid}/download/csv").text.lstrip("\ufeff").startswith("seq,time,stage")


def test_download_html_and_view(client, data):
    _, d, rid = _project_with_run(client, data)
    assert not (d / "test-report.html").exists()
    r = client.get(f"/api/runs/{rid}/download/html")  # rebuilt for older runs
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    assert f'filename="sprat-caf-api-{rid}-report.html"' in r.headers["content-disposition"]
    assert "API test report — Café API!" in r.text
    assert (d / "coverage.json").is_file() and (d / "coverage.csv").is_file()
    v = client.get(f"/api/runs/{rid}/download/view")
    assert v.status_code == 200 and "attachment" not in v.headers.get("content-disposition", "")
    assert v.text == r.text


def test_download_zip_has_everything(client, data):
    _, d, rid = _project_with_run(client, data)
    (d / "zap").mkdir()
    (d / "zap" / "zap.log").write_text("nested ✓", encoding="utf-8")
    r = client.get(f"/api/runs/{rid}/download/zip")
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    assert r.headers["content-disposition"] == f'attachment; filename="sprat-caf-api-{rid}.zip"'
    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = set(z.namelist())
    base = f"sprat-caf-api-{rid}/"
    assert all(n.startswith(base) for n in names)
    assert {base + n for n in ("run.json", "report.json", "spec.json", "test-log.ndjson",
                               "test-report.html", "coverage.csv", "coverage.json", "README.txt", "zap/zap.log")} <= names
    assert z.read(base + "README.txt").decode() == web.ZIP_README
    assert z.read(base + "zap/zap.log").decode() == "nested ✓"


@pytest.mark.parametrize("kind", ["pdf", "report.json", "..%5Crun.json", "HTML", "%2e%2e"])
def test_download_unknown_kind(client, data, kind):
    _, _, rid = _project_with_run(client, data)
    assert client.get(f"/api/runs/{rid}/download/{kind}").status_code == 404


def test_download_html_needs_a_spec_to_rebuild(client, data):
    d = _mkrun(data, "20240101-000000-aaaaaa", "shop", entries=_log_entries())
    r = client.get("/api/runs/20240101-000000-aaaaaa/download/html")
    assert r.status_code == 404 and "written when the run finishes" in r.text
    assert client.get("/api/runs/20240101-000000-aaaaaa/download/view").status_code == 404
    assert client.get("/api/runs/20240101-000000-aaaaaa/download/csv").status_code == 200
    assert not (d / "test-report.html").exists()


def test_download_while_running(client, pipe, data):
    pid = _create(client)
    pipe.gate.clear()
    rid = _start(client, pid)
    pipe.started.wait(5)
    assert client.get(f"/api/runs/{rid}/download/html").status_code == 404  # not rebuilt mid-run
    r = client.get(f"/api/runs/{rid}/download/csv")  # live CSV from the log so far
    assert r.status_code == 200 and r.content.decode("utf-8-sig").startswith("seq,")
    (data / "runs" / rid / "test-log.ndjson").unlink()
    r = client.get(f"/api/runs/{rid}/download/ndjson")
    assert r.status_code == 404 and "no test log" in r.text
    pipe.gate.set()
    _wait(client, rid)


def test_legacy_run_is_rebuilt_from_schemathesis_events(client, data):
    pid = _create(client)
    d = _mkrun(data, "20240101-000000-aaaaaa", pid, stages_requested=["conformance", "authz"],
               operations=["GET /a"], stages=[_stage("conformance"), _stage("authz", [("high", "GET /a")])])
    (d / "spec-full.json").write_text(json.dumps(SPEC_DOC), encoding="utf-8")
    event = {"ScenarioFinished": {"phase": "fuzzing", "recorder": {
        "cases": {"c1": {"value": {"id": "c1", "method": "GET", "path": "/a", "meta": {}}}},
        "interactions": {"c1": {"request": {"method": "GET", "uri": "http://fake.test/a", "headers": {}},
                                "response": {"status_code": 200, "content": None}}},
        "checks": {"c1": [{"name": "not_a_server_error", "status": "success"}]}}}}
    (d / "schemathesis-events.ndjson").write_text(json.dumps(event) + "\n", encoding="utf-8")
    r = client.get("/api/runs/20240101-000000-aaaaaa/download/html")
    assert r.status_code == 200
    assert (d / "test-log.ndjson").is_file() and (d / "test-log.csv").is_file()
    cov = json.loads((d / "coverage.json").read_text(encoding="utf-8"))
    assert cov["warnings"][0].startswith("This run was made by an older sprat version")
    assert [a["operation"] for a in cov["apis"]] == ["GET /a"]  # only the selected API
    tests = {t["test"]: t["status"] for t in cov["apis"][0]["tests"]}
    assert tests == {"Behaviour vs Swagger": "tested", "Access control": "not_recorded"}
    assert client.get("/api/runs/20240101-000000-aaaaaa/log").json()["total"] == 1


def test_legacy_run_without_events_or_project(client, data):
    d = _mkrun(data, "20240101-000000-aaaaaa", "deleted-project")
    (d / "spec.json").write_text(json.dumps(SPEC_DOC), encoding="utf-8")
    r = client.get("/api/runs/20240101-000000-aaaaaa/download/zip")
    assert r.status_code == 200
    names = {n.split("/", 1)[1] for n in zipfile.ZipFile(io.BytesIO(r.content)).namelist()}
    assert {"test-log.ndjson", "test-log.csv", "test-report.html", "coverage.json"} <= names
    cov = json.loads((d / "coverage.json").read_text(encoding="utf-8"))
    assert len(cov["apis"]) == 4  # no report.json: every stage counts as not recorded
    # rebuilt once: a second download doesn't redo it
    mtime = (d / "test-report.html").stat().st_mtime
    client.get("/api/runs/20240101-000000-aaaaaa/download/html")
    assert (d / "test-report.html").stat().st_mtime == mtime


def test_run_without_project_name_gets_generic_filename(client, data):
    _mkrun(data, "20240101-000000-aaaaaa", "x", name=None, entries=_log_entries())
    r = client.get("/api/runs/20240101-000000-aaaaaa/download/ndjson")
    assert 'filename="sprat-run-20240101-000000-aaaaaa-test-log.ndjson"' in r.headers["content-disposition"]
    _mkrun(data, "20240101-000000-bbbbbb", "x", name="!!!", entries=_log_entries())
    r = client.get("/api/runs/20240101-000000-bbbbbb/download/ndjson")
    assert "sprat-run-20240101-000000-bbbbbb" in r.headers["content-disposition"]


# ---------------- raw files ----------------

def test_run_files(client, data):
    d = _mkrun(data, "20240101-000000-aaaaaa", "shop", stages=[])
    (d / "types.log").write_bytes("line ✓\n".encode() + b"\xff\n")
    (d / "schemathesis-junit.xml").write_text("<x/>", encoding="utf-8")
    r = client.get("/api/runs/20240101-000000-aaaaaa/files/types.log")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain") and "line ✓" in r.text
    assert "\ufffd" in r.text  # undecodable bytes replaced, not a 500
    assert client.get("/api/runs/20240101-000000-aaaaaa/files/schemathesis-junit.xml").text == "<x/>"
    j = client.get("/api/runs/20240101-000000-aaaaaa/files/report.json")
    assert j.status_code == 200 and j.json()["stages"] == []
    assert client.get("/api/runs/20240101-000000-aaaaaa/files/nope.log").status_code == 404
    assert client.get("/api/runs/20240101-000000-aaaaaa/files/sub").status_code == 404


@pytest.mark.parametrize("rid,name", [
    ("20240101-000000-aaaaaa", "..%5C..%5Csecrets.json"),
    ("20240101-000000-aaaaaa", "..%5C..%5C.secret.key"),
    ("20240101-000000-aaaaaa", "%2e%2e%5C%2e%2e%5Cprojects%5Cshop.json"),
    ("%2e%2e", "secrets.json"),
    ("..", "secrets.json"),
    ("%2e%2e%5C..", "outside.txt"),
    ("nope", "run.json"),
])
def test_run_files_refuse_traversal(client, data, tmp_path, rid, name):
    pid = _create(client)  # writes projects/shop.json
    client.put(f"/api/projects/{pid}/secrets/S_X", json={"value": "secret-value-1"})  # secrets.json + .secret.key
    _mkrun(data, "20240101-000000-aaaaaa", pid)
    (tmp_path / "outside.txt").write_text("outside", encoding="utf-8")
    assert (data / "secrets.json").is_file()
    r = client.get(f"/api/runs/{rid}/files/{name}")
    assert r.status_code == 404 and r.json() == {"detail": "Not Found"}


def test_run_files_refuse_absolute_path(client, data, tmp_path):
    _mkrun(data, "20240101-000000-aaaaaa", "shop")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    r = client.get("/api/runs/20240101-000000-aaaaaa/files/" + quote(str(outside), safe=""))
    assert r.status_code == 404


@pytest.mark.parametrize("host,url,warns", [("127.0.0.1", "http://localhost:8001", False),
                                            ("0.0.0.0", "http://localhost:8001", True),
                                            ("10.1.2.3", "http://10.1.2.3:8001", True)])
def test_serve_configures_and_warns_on_public_bind(client, data, tmp_path, monkeypatch, capsys, host, url, warns):
    import sys
    import types
    calls = []
    monkeypatch.setitem(sys.modules, "uvicorn", types.SimpleNamespace(run=lambda app, **kw: calls.append(kw)))
    web.serve(host, 8001, str(tmp_path / "served"))
    out = capsys.readouterr().out
    assert calls == [{"host": host, "port": 8001, "log_level": "warning"}]
    assert web.DATA == (tmp_path / "served").resolve() and f"sprat UI: {url}" in out
    assert ("WARNING" in out) == warns
    web.configure(data)


# ---------------- end to end with the real pipeline ----------------

def test_secrets_are_masked_in_every_output(client, data, monkeypatch):
    """A leaky API echoes every credential back; none may appear in anything sprat stores or serves."""
    store_secret, literal, env_secret = "tok-SECRET-abcdef123", "literal-KEY-987654", "env-SECRET-555555"
    monkeypatch.setenv("SPRAT_ENV_SECRET", env_secret)
    pid = _create(client, headers=f"Authorization: Bearer ${{API_TOKEN}}\nX-Api-Key: {literal}\n"
                                  "X-Env: ${SPRAT_ENV_SECRET}",
                  secrets={"API_TOKEN": store_secret}, stages=["authz"])
    rid = _start(client, pid)
    run = _wait(client, rid)
    assert run["status"] == "done", run.get("error")
    log = client.get(f"/api/runs/{rid}/log", params={"op": "GET /echo"}).json()
    assert log["total"] >= 1
    echo = client.get(f"/api/runs/{rid}/log/{log['items'][0]['seq']}").json()
    assert echo["request"]["headers"]["authorization"] == "Bearer ***"
    body = json.loads(echo["response"]["body"])
    assert body["seen"]["authorization"] in ("***", "Bearer ***") and body["seen"]["x-api-key"] == "***"
    assert body["seen"]["x-env"] == "***" and body["issued"] == "***jwt***"
    served = [client.get(f"/api/runs/{rid}").content, client.get(f"/api/runs/{rid}/log").content]
    served += [client.get(f"/api/runs/{rid}/log/{i['seq']}").content
               for i in client.get(f"/api/runs/{rid}/log", params={"limit": 1000}).json()["items"]]
    for kind in ("ndjson", "csv", "html", "view"):
        served.append(client.get(f"/api/runs/{rid}/download/{kind}").content)
    z = zipfile.ZipFile(io.BytesIO(client.get(f"/api/runs/{rid}/download/zip").content))
    served += [z.read(n) for n in z.namelist()]
    served += [client.get(f"/api/runs/{rid}/files/{f}").content for f in run["files"]]
    served += [client.get(f"/api/projects/{pid}/yaml").content, client.get("/api/projects").content,
               client.get(f"/api/projects/{pid}/runs").content]
    on_disk = [f.read_bytes() for f in data.rglob("*") if f.is_file()]
    for blob in served + on_disk:
        for s in (store_secret, literal, env_secret, API_JWT):
            assert s.encode() not in blob, s
    # the settings form shows the literal (it lives in server memory) but never the saved secret
    p = client.get(f"/api/projects/{pid}").text
    assert literal in p and store_secret not in p


def test_real_run_restarts_and_reruns(client, data):
    pid = _create(client, stages=["authz"])
    rid = _start(client, pid, operations=["GET /a", "GET /b"])
    run = _wait(client, rid)
    assert run["status"] == "done" and run["tested"] == ["GET /a", "GET /b"]
    _restart(data)
    again = client.get(f"/api/runs/{rid}").json()
    assert again["status"] == "done" and again["report"] == run["report"]
    assert "test-report.html" in again["files"] and "test-log.csv" in again["files"]
    assert client.get(f"/api/runs/{rid}/download/html").status_code == 200
    # the literal token is gone after the restart, so secured APIs need it again
    assert client.post(f"/api/projects/{pid}/runs", json={"operations": ["GET /b"]}).status_code == 428


def test_spec_url_with_surrounding_spaces_still_runs(client):
    pid = _create(client, spec="  http://fake.test/openapi.json  ")
    run = _wait(client, _start(client, pid, operations=["GET /a"]))
    assert run["status"] == "done", run["error"]


def test_guide_downloads_match_docs_and_unknown_is_404():
    from pathlib import Path
    from fastapi.testclient import TestClient
    from sprat.web.app import GUIDE_FILES, app
    c = TestClient(app)
    docs = Path(__file__).resolve().parent.parent / "docs"
    for name in GUIDE_FILES:
        r = c.get(f"/guides/{name}")
        assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
        assert r.content == (docs / name).read_bytes(), f"sprat/web/guides/{name} is out of date: copy it from docs/"
    assert c.get("/guides/README.md").status_code == 404
    assert c.get("/guides/..%2Fapp.py").status_code == 404


def test_lenient_setting_reaches_the_run(client, pipe):
    pid = _create(client, lenient_spec=True)
    assert client.get(f"/api/projects/{pid}").json()["lenient_spec"] is True
    rid = _start(client, pid)
    _wait(client, rid)
    assert pipe.cfgs[-1].lenient_spec is True and client.get(f"/api/runs/{rid}").json()["lenient_spec"] is True
    assert yaml.safe_load(client.get(f"/api/projects/{pid}/yaml").text)["lenient_spec"] is True


def test_run_shows_access_issues_and_finding_fixes(client, data):
    pid = _create(client)
    _mkrun(data, "20240101-000000-aaaaaa", pid, tested=["GET /a"],
           stages=[_stage("conformance", [("high", "GET /a")])])
    d = data / "runs" / "20240101-000000-aaaaaa"
    (d / "coverage.json").write_text(json.dumps({"apis": [
        {"operation": "GET /a", "access": {"status": "blocked", "refused": 3, "reached": 0, "reason": "Not tested: x"}},
        {"operation": "GET /b", "access": {"status": "ok", "refused": 0, "reached": 2, "reason": ""}}]}),
        encoding="utf-8")
    run = client.get("/api/runs/20240101-000000-aaaaaa").json()
    assert run["access"] == [{"operation": "GET /a", "status": "blocked", "refused": 3, "reached": 0,
                              "reason": "Not tested: x"}]
    f = run["report"]["stages"][0]["findings"][0]
    assert f["cause"] == "other" and f["fix"]


def test_saved_examples_round_trip_and_reach_the_run(client, pipe, data):
    pid = _create(client)
    url = f"/api/projects/{pid}/example"
    assert client.get(url, params={"op": "GET /items/{id}"}).json() == {"saved": None, "last": None}
    r = client.put(url, json={"op": "GET /items/{id}", "path": {"id": "42"}, "query": {"q": "x"}})
    assert r.status_code == 200
    assert client.get(url, params={"op": "GET /items/{id}"}).json()["saved"] == {"path": {"id": "42"}, "query": {"q": "x"}}
    for bad, msg in (({"op": "GET /nope", "body": {}}, "not in this project"),
                     ({"op": "GET /items/{id}", "path": {"zzz": "1"}}, "no path parameter zzz"),
                     ({"op": "GET /a"}, "Nothing to save")):
        r = client.put(url, json=bad)
        assert r.status_code == 400 and msg in r.text
    assert client.get(f"/api/projects/{pid}").json()["examples"] == {"GET /items/{id}": {"path": {"id": "42"},
                                                                                        "query": {"q": "x"}}}
    rid = _start(client, pid)
    _wait(client, rid)
    assert pipe.cfgs[-1].examples == {"GET /items/{id}": {"path": {"id": "42"}, "query": {"q": "x"}}}
    assert yaml.safe_load(client.get(f"/api/projects/{pid}/yaml").text)["examples"]["GET /items/{id}"]["path"] == {"id": "42"}
    assert client.delete(url, params={"op": "GET /items/{id}"}).status_code == 200
    assert client.delete(url, params={"op": "GET /items/{id}"}).status_code == 404


def test_example_shows_what_the_last_run_sent(client, data):
    pid = _create(client)
    _mkrun(data, "20240101-000000-aaaaaa", pid, tested=["GET /a"], stages=[_stage("types")],
           entries=[dict(stage="types", scenario="Valid request first (every field the correct type)",
                         operation="GET /a", verdict="error",
                         request={"method": "GET", "url": "http://fake.test/a", "body": '{"site": "nope"}'},
                         response={"status": 200, "body": '{"status": "Failed", "message": "Site not found"}'})])
    last = client.get(f"/api/projects/{pid}/example", params={"op": "GET /a"}).json()["last"]
    assert last["body"] == {"site": "nope"} and last["status"] == 200 and last["said"] == "Site not found"
    assert last["accepted"] is False and last["run_id"] == "20240101-000000-aaaaaa"
