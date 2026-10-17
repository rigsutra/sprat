"""Web API tests against an in-process fake API (no network)."""
import time

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sprat.web import app as web

SPEC = {
    "openapi": "3.0.1", "info": {"title": "Fake", "version": "1"},
    "servers": [{"url": "http://fake.test"}],
    "components": {"securitySchemes": {"b": {"type": "http", "scheme": "bearer"}}},
    "paths": {
        "/a": {"get": {"responses": {"200": {"description": "ok"}}}},
        "/b": {"get": {"security": [{"b": []}], "responses": {"200": {"description": "ok"}}}},
        "/slow": {"get": {"responses": {"200": {"description": "ok"}}}},
    },
}


LOGINS = []


def fake_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/openapi.json":
        return httpx.Response(200, json=SPEC)
    if request.url.path == "/auth/login":
        import base64, json as _j
        body = _j.loads(request.content)
        if body.get("password") != "pw-from-env":
            return httpx.Response(401, json={"message": "Invalid email or password"})
        LOGINS.append(body["email"])
        b = lambda d: base64.urlsafe_b64encode(_j.dumps(d).encode()).decode().rstrip("=")
        tok = f"{b({'alg': 'none'})}.{b({'sub': body['email'], 'exp': int(time.time()) + 900})}.sig"
        return httpx.Response(200, json={"success": True, "data": {"accessToken": tok}})
    if request.url.path.startswith("/slow"):
        time.sleep(0.3)
    return httpx.Response(200, json={}, headers={"x-content-type-options": "nosniff"})


@pytest.fixture
def client(tmp_path, monkeypatch):
    real = httpx.Client
    real_request = httpx.request

    def fake_request(method, url, **kw):  # the login call uses httpx.request
        with real(transport=httpx.MockTransport(fake_handler)) as c:
            kw.pop("follow_redirects", None)
            return c.request(method, url, **kw)
    monkeypatch.setattr(httpx, "request", fake_request)
    def fake_client(*a, **kw):
        kw["transport"] = httpx.MockTransport(fake_handler)
        return real(*a, **kw)
    monkeypatch.setattr(httpx, "Client", fake_client)
    web.configure(tmp_path)
    web._runs.clear(); web._cancels.clear(); web._secrets.clear()
    return TestClient(web.app)


def _create(client, **extra):
    body = {"name": "Fake API", "spec": "http://fake.test/openapi.json", "stages": ["authz"],
            "headers": "Authorization: Bearer literal-secret\nX-Env: ${SPRAT_TEST_VAR}"} | extra
    r = client.post("/api/projects", json=body)
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _wait(client, rid, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        r = client.get(f"/api/runs/{rid}").json()
        if r["status"] not in ("running", "stopping"):
            return r
        time.sleep(0.1)
    raise AssertionError("run did not finish")


def test_discover_finds_spec_from_root(client):
    res = client.post("/api/discover", json={"url": "http://fake.test"}).json()
    assert [s["url"] for s in res["specs"]] == ["http://fake.test/openapi.json"]
    assert {o["label"] for o in res["specs"][0]["ops"]} == {"GET /a", "GET /b", "GET /slow"}


def test_project_crud_and_secret_handling(client, tmp_path, monkeypatch):
    monkeypatch.setenv("SPRAT_TEST_VAR", "from-env")
    pid = _create(client)
    saved = (tmp_path / "projects" / f"{pid}.json").read_text()
    assert "literal-secret" not in saved and "${SPRAT_TEST_VAR}" in saved  # literal token never on disk
    p = client.get(f"/api/projects/{pid}").json()
    assert "literal-secret" in p["headers"] and len(p["operations"]) == 3
    assert [x["id"] for x in client.get("/api/projects").json()] == [pid]
    yaml_text = client.get(f"/api/projects/{pid}/yaml").text
    assert "<set me>" in yaml_text and "literal-secret" not in yaml_text
    assert client.delete(f"/api/projects/{pid}").status_code == 200
    assert client.get("/api/projects").json() == []


def test_run_selected_operations_and_per_api_status(client, monkeypatch):
    monkeypatch.setenv("SPRAT_TEST_VAR", "x")
    pid = _create(client)
    rid = client.post(f"/api/projects/{pid}/runs", json={"operations": ["GET /b"]}).json()["id"]
    run = _wait(client, rid)
    assert run["status"] == "done" and run["tested"] == ["GET /b"]
    crit = [f for s in run["report"]["stages"] for f in s["findings"] if f["severity"] == "critical"]
    assert crit and all(f["operation"] == "GET /b" for f in crit)  # /b is "secured" but serves anyone
    st = client.get(f"/api/projects/{pid}").json()["op_status"]
    assert st["GET /b"]["max"] == "critical" and "GET /a" not in st
    assert client.post(f"/api/projects/{pid}/runs", json={"operations": ["GET /nope"]}).status_code == 400


def test_live_activity_feed_and_excluded_apis(client, monkeypatch):
    monkeypatch.setenv("SPRAT_TEST_VAR", "x")
    pid = _create(client, exclude_paths=["^/slow$"])
    ops = {o["label"]: o["excluded"] for o in client.get(f"/api/projects/{pid}").json()["operations"]}
    assert ops == {"GET /a": False, "GET /b": False, "GET /slow": True}
    assert client.get("/api/projects").json()[0]["excluded"] == 1
    # selecting only excluded APIs is refused with a clear message
    r = client.post(f"/api/projects/{pid}/runs", json={"operations": ["GET /slow"]})
    assert r.status_code == 400 and "excluded" in r.text
    run = _wait(client, client.post(f"/api/projects/{pid}/runs", json={}).json()["id"])
    assert run["tested"] == ["GET /a", "GET /b"]
    feed = run["feed"]
    assert {f["op"] for f in feed if f["op"]} == {"GET /a", "GET /b"}  # excluded API never touched
    assert any(f["msg"].startswith("Finished") and f["stage"] == "authz" for f in feed)
    assert any(f["level"] == "bad" and f["op"] == "GET /b" for f in feed)  # /b accepts no credentials


def test_test_log_browse_filter_and_download(client, monkeypatch):
    import csv, io, json, zipfile
    monkeypatch.setenv("SPRAT_TEST_VAR", "env-secret-value")
    pid = _create(client)
    rid = _wait(client, client.post(f"/api/projects/{pid}/runs", json={}).json()["id"])["id"]
    log = client.get(f"/api/runs/{rid}/log").json()
    assert log["available"] and log["total"] >= 3 and log["stages"] == {"authz": log["total"]}
    fails = client.get(f"/api/runs/{rid}/log", params={"verdict": "fail", "op": "GET /b"}).json()
    no_cred = [i for i in fails["items"] if "no credentials" in i["scenario"]]
    assert no_cred and no_cred[0]["status"] == 200 and no_cred[0]["expected"].startswith("Refused")
    assert "anyone can call this API" in no_cred[0]["explanation"]
    full = client.get(f"/api/runs/{rid}/log/{no_cred[0]['seq']}").json()
    assert full["request"]["method"] == "GET" and full["response"]["status"] == 200
    # secrets are masked everywhere: header values and the env-provided value
    for kind in ("ndjson", "csv", "zip"):
        r = client.get(f"/api/runs/{rid}/download/{kind}")
        assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
        blob = r.content
        if kind == "zip":
            z = zipfile.ZipFile(io.BytesIO(blob))
            names = [n.split("/", 1)[1] for n in z.namelist()]
            assert {"test-log.ndjson", "test-log.csv", "report.json", "run.json", "README.txt"} <= set(names)
            blob = b"".join(z.read(n) for n in z.namelist())
        assert b"literal-secret" not in blob and b"env-secret-value" not in blob
    rows = list(csv.DictReader(io.StringIO(client.get(f"/api/runs/{rid}/download/csv").content.decode("utf-8-sig"))))
    assert len(rows) == log["total"] and {"scenario", "expected", "verdict", "status"} <= set(rows[0])
    public = [json.loads(l) for l in client.get(f"/api/runs/{rid}/download/ndjson").text.splitlines()
              if '"GET /a"' in l]
    assert public[0]["request"]["headers"]["authorization"] == "Bearer ***"


LOGIN = {"url": "http://fake.test/auth/login", "body": '{"email": "qa@x.test", "password": "${SPRAT_PW}"}',
         "token_path": "data.accessToken"}


def test_automatic_login(client, monkeypatch, tmp_path):
    import json as _j
    LOGINS.clear()
    monkeypatch.setenv("SPRAT_PW", "pw-from-env")
    # a literal password is refused, with a message saying how to do it instead
    bad = {**LOGIN, "body": '{"email": "qa@x.test", "password": "hunter2"}'}
    r = client.post("/api/projects", json={"name": "L", "spec": "http://fake.test/openapi.json", "login_a": bad})
    assert r.status_code == 400 and "typed directly" in r.text and "${NTT_PASSWORD}" in r.text
    # Test login: works, never returns the token
    t = client.post("/api/login/test", json={"login": LOGIN}).json()
    assert t["ok"] and t["expiry_source"] == "JWT exp claim" and t["token_preview"].endswith("…")
    assert len(t["token_preview"]) < 12
    # project with login: no NO_TOKEN prompt, run logs in by itself, /b gets the bearer token
    pid = client.post("/api/projects", json={"name": "L", "spec": "http://fake.test/openapi.json",
                                             "stages": ["authz"], "login_a": LOGIN}).json()["id"]
    saved = (tmp_path / "projects" / f"{pid}.json").read_text()
    assert "pw-from-env" not in saved and "${SPRAT_PW}" in saved
    run = _wait(client, client.post(f"/api/projects/{pid}/runs", json={}).json()["id"])
    assert run["status"] == "done" and LOGINS  # logged in
    assert any(f["stage"] == "auth" and "Logged in as user A" in f["msg"] for f in run["feed"])
    pub = [e for e in client.get(f"/api/runs/{pid and run['id']}/log", params={"op": "GET /a"}).json()["items"]]
    assert pub
    full = client.get(f"/api/runs/{run['id']}/log/{pub[0]['seq']}").json()
    assert full["request"]["headers"]["authorization"] == "Bearer ***"
    # wrong password: the run doesn't start, the error says why
    monkeypatch.setenv("SPRAT_PW", "wrong")
    r = client.post(f"/api/projects/{pid}/runs", json={})
    assert r.status_code == 400 and "Invalid email or password" in r.text and "nothing was tested" in r.text


def test_missing_env_var_is_a_clear_error(client, monkeypatch):
    monkeypatch.setenv("SPRAT_TEST_VAR", "x")
    pid = _create(client)
    monkeypatch.delenv("SPRAT_TEST_VAR")
    r = client.post(f"/api/projects/{pid}/runs", json={})
    assert r.status_code == 400 and "SPRAT_TEST_VAR" in r.text


def test_stop_cancels_run(client, monkeypatch):
    monkeypatch.setenv("SPRAT_TEST_VAR", "x")
    # many slow operations so the run is still going when we stop it
    SPEC["paths"].update({f"/slow{i}": {"get": {"responses": {"200": {"description": "ok"}}}} for i in range(40)})
    try:
        pid = _create(client, stages=["authz", "types"])
        rid = client.post(f"/api/projects/{pid}/runs", json={}).json()["id"]
        assert client.post(f"/api/projects/{pid}/runs", json={}).status_code == 409  # one at a time
        time.sleep(0.5)
        assert client.post(f"/api/runs/{rid}/cancel").status_code == 200
        run = _wait(client, rid)
        assert run["status"] == "cancelled"
        assert run["stages"]["authz"]["status"] == "cancelled"
        assert run["stages"]["types"]["status"] == "cancelled"
        assert client.post(f"/api/runs/{rid}/cancel").status_code == 409
    finally:
        for i in range(40):
            SPEC["paths"].pop(f"/slow{i}", None)
