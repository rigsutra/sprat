"""Security regressions of sprat itself: it holds passwords and tokens and talks to APIs that may be
hostile. Secrets must not end up on disk, on the console or in error messages; the web UI must stay
local and inside its data directory; content coming from the target API must not be able to inject
markup into the reports; and a login must not hand credentials to another host via a redirect.
"""
from __future__ import annotations

import base64
import contextlib
import csv
import html
import importlib.util
import io
import json
import os
import re
import socket
import sys
import threading
import time
from html.parser import HTMLParser
from pathlib import Path

import httpx
import pytest
import uvicorn
import yaml

from sprat import cli
from sprat.auth import LoginConfig, LoginError, TokenProvider, literal_secrets
from sprat.spec import load_spec

ROOT = Path(__file__).resolve().parents[1]
DEMO_FILE = ROOT / "examples" / "demo_api.py"

ALICE_PW, BOB_PW = "alice-pass", "bob-pass"  # demo credentials (examples/demo_api.py)
API_KEY = "k3y-SECRET-api-0042"              # an extra static secret header for user A
PW = "Tr0ub4dor&3-secret"                    # password used against the mock APIs


# ---------------- helpers ----------------

def all_files(root: Path) -> list[Path]:
    return [p for p in root.rglob("*") if p.is_file()]


def files_containing(root: Path, needles: list[str]) -> dict[str, list[str]]:
    hits: dict[str, list[str]] = {}
    for p in all_files(root):
        blob = p.read_bytes()
        for n in needles:
            if n.encode() in blob:
                hits.setdefault(str(p.relative_to(root)), []).append(n[:24])
    return hits


def b64(d: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")


def jwt(sub="u1", ttl=900) -> str:
    return f"{b64({'alg': 'none'})}.{b64({'sub': sub, 'exp': int(time.time()) + ttl})}.signature"


class FakeNet:
    """Routes every httpx.Client request (used by the stages, spec loading and login) to per-host
    handlers, and records what each host received."""

    def __init__(self):
        self.hosts: dict[str, callable] = {}
        self.seen: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        request.read()
        self.seen.append(request)
        handler = self.hosts.get(request.url.host)
        if handler is None:
            return httpx.Response(599, text="unknown host in test")
        return handler(request)

    def to(self, host: str) -> list[httpx.Request]:
        return [r for r in self.seen if r.url.host == host]


@pytest.fixture
def net(monkeypatch):
    fake = FakeNet()
    real = httpx.Client

    def client(*a, **kw):
        kw["transport"] = httpx.MockTransport(fake)
        return real(*a, **kw)
    monkeypatch.setattr(httpx, "Client", client)
    return fake


@pytest.fixture
def web_client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from sprat.web import app as web
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(web, "DATA", web.DATA)
    monkeypatch.setattr(web, "_store", None)
    monkeypatch.delenv("SPRAT_SECRET_KEY", raising=False)
    data = tmp_path / "data"
    web.configure(data)
    web._runs.clear(); web._cancels.clear(); web._secrets.clear()
    with TestClient(web.app) as client:  # one event loop for all requests (much faster on Windows)
        yield client, data, web
    web._runs.clear(); web._cancels.clear(); web._secrets.clear()


# ---------------- 1. secrets of a full run against the live demo ----------------

def _load_demo(name: str, ttl: int):
    old = os.environ.get("DEMO_TOKEN_TTL")
    os.environ["DEMO_TOKEN_TTL"] = str(ttl)
    try:
        spec = importlib.util.spec_from_file_location(name, DEMO_FILE)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
        return mod
    finally:
        if old is None:
            os.environ.pop("DEMO_TOKEN_TTL", None)
        else:
            os.environ["DEMO_TOKEN_TTL"] = old


@contextlib.contextmanager
def _serve(app):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=sock.getsockname()[1], log_level="warning"))
    t = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    t.start()
    end = time.time() + 15
    while not server.started:
        assert time.time() < end and t.is_alive(), "demo server did not start"
        time.sleep(0.05)
    try:
        yield f"http://127.0.0.1:{sock.getsockname()[1]}"
    finally:
        server.should_exit = True
        t.join(10)
        sock.close()


@pytest.fixture(scope="module")
def secret_run(tmp_path_factory):
    """One full CLI run (conformance, types, authz) with automatic login for users A and B, short-lived
    tokens (so several are issued) and a static API key; everything under one temp dir, which is also
    the CWD (Schemathesis' .schemathesis/ cache lands there)."""
    root = tmp_path_factory.mktemp("secret-run")
    mod = _load_demo("_sec_demo_api", ttl=6)  # renewed every ~3 s
    env_before = {k: os.environ.get(k) for k in ("DEMO_ALICE_PW", "DEMO_BOB_PW", "DEMO_API_KEY")}
    cwd = os.getcwd()
    os.environ.update(DEMO_ALICE_PW=ALICE_PW, DEMO_BOB_PW=BOB_PW, DEMO_API_KEY=API_KEY)
    os.chdir(root)
    out_buf, err_buf = io.StringIO(), io.StringIO()
    try:
        with _serve(mod.app) as base:
            (root / "schemathesis.toml").write_text("seed = 4321\n", encoding="utf-8")
            login = lambda user, var: {"url": f"{base}/auth/login", "token_path": "data.accessToken",
                                       "body": json.dumps({"email": f"{user}@demo.test", "password": "${%s}" % var})}
            cfg = {"spec": f"{base}/openapi.json", "headers": {"X-Api-Key": "${DEMO_API_KEY}"},
                   "login_a": login("alice", "DEMO_ALICE_PW"), "login_b": login("bob", "DEMO_BOB_PW"),
                   "max_examples": 3, "out_dir": str(root / "out"),
                   "bola": [{"method": "GET", "path": "/users/{uid}/orders/{oid}", "params": {"uid": 1, "oid": 10}}]}
            (root / "sprat.yaml").write_text(yaml.safe_dump(cfg), encoding="utf-8")
            with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
                rc = cli.main(["run", "--config", str(root / "sprat.yaml"), "--stages", "conformance,types,authz"])
    finally:
        os.chdir(cwd)
        for k, v in env_before.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    tokens = list(mod.ISSUED)
    return {"root": root, "out": root / "out", "rc": rc, "stdout": out_buf.getvalue(),
            "stderr": err_buf.getvalue(), "tokens": tokens, "logins": mod.LOGINS["count"]}


@pytest.mark.e2e
@pytest.mark.slow
def test_secret_run_really_used_the_secrets(secret_run):
    # guards the checks below against passing vacuously
    assert secret_run["rc"] == 1, secret_run["stderr"]
    assert secret_run["logins"] >= 3 and len(secret_run["tokens"]) == secret_run["logins"]
    report = json.loads((secret_run["out"] / "report.json").read_text(encoding="utf-8"))
    assert all(s["status"] == "ok" for s in report["stages"])
    assert any(f["title"].startswith("BOLA: user B") for s in report["stages"] for f in s["findings"])
    assert len(all_files(secret_run["root"])) > 10


@pytest.mark.e2e
@pytest.mark.slow
def test_passwords_never_written_to_any_file(secret_run):
    assert files_containing(secret_run["root"], [ALICE_PW, BOB_PW]) == {}


@pytest.mark.e2e
@pytest.mark.slow
def test_no_secret_printed_to_stdout_or_stderr(secret_run):
    printed = secret_run["stdout"] + secret_run["stderr"]
    assert "Logged in as user A" in printed  # the auth progress lines are printed...
    for s in [ALICE_PW, BOB_PW, API_KEY, *secret_run["tokens"]]:
        assert s not in printed  # ...without any secret


@pytest.mark.e2e
@pytest.mark.slow
def test_tokens_and_keys_masked_in_logs_and_reports(secret_run):
    out = secret_run["out"]
    for name in ("test-log.ndjson", "test-log.csv", "report.json", "report.html", "test-report.html",
                 "coverage.json", "coverage.csv", "types.log", "schemathesis.log"):
        blob = (out / name).read_bytes()
        for s in [API_KEY, *secret_run["tokens"]]:
            assert s.encode() not in blob, (name, s[:20])
    log = [json.loads(l) for l in (out / "test-log.ndjson").read_text(encoding="utf-8").split("\n") if l.strip()]
    sent = [e["request"]["headers"] for e in log if e["request"] and e["request"].get("headers")]
    assert any(h.get("authorization") == "Bearer ***" for h in sent)
    assert any(h.get("x-api-key") == "***" for h in sent)


@pytest.mark.e2e
@pytest.mark.slow
def test_tokens_and_keys_never_written_to_any_file(secret_run):
    assert files_containing(secret_run["root"], [API_KEY, *secret_run["tokens"]]) == {}


# ---------------- 2. failed logins ----------------

def _login_cfg(url="http://auth.test/login", **kw) -> LoginConfig:
    return LoginConfig(url=url, body='{"email": "qa@x.test", "password": "${SPRAT_SEC_PW}"}',
                       token_path="data.accessToken", **kw)


FAILED_LOGINS = {
    "401": lambda r: httpx.Response(401, json={"message": "Invalid email or password"}),
    "422-echo-in-input": lambda r: httpx.Response(422, json={"detail": [
        {"loc": ["body", "password"], "msg": "too weak", "input": json.loads(r.content)["password"]}]}),
    "500-text-echo": lambda r: httpx.Response(500, text=f"crash while checking {r.content.decode()}"),
    "200-without-token": lambda r: httpx.Response(200, json={"data": {"echo": json.loads(r.content)}}),
    "200-not-json": lambda r: httpx.Response(200, text=r.content.decode()),
    "unreachable": lambda r: (_ for _ in ()).throw(httpx.ConnectError("connection refused", request=r)),
}


@pytest.mark.parametrize("case", list(FAILED_LOGINS))
def test_failed_login_message_never_contains_the_password(case, net, monkeypatch):
    monkeypatch.setenv("SPRAT_SEC_PW", PW)
    net.hosts["auth.test"] = FAILED_LOGINS[case]
    with pytest.raises(LoginError) as e:
        TokenProvider(_login_cfg()).current_token()
    assert PW in net.to("auth.test")[0].content.decode()  # the password was sent...
    assert PW not in str(e.value) and PW not in repr(e.value)  # ...but isn't repeated to the user
    assert e.value.__cause__ is None or PW not in str(e.value.__cause__)


def test_failed_login_message_masks_password_echoed_in_server_message(net, monkeypatch):
    monkeypatch.setenv("SPRAT_SEC_PW", PW)
    net.hosts["auth.test"] = lambda r: httpx.Response(
        401, json={"message": f"Wrong password {json.loads(r.content)['password']}"})
    with pytest.raises(LoginError) as e:
        TokenProvider(_login_cfg()).current_token()
    assert PW not in str(e.value)


def test_failed_login_via_cli_prints_no_secret_and_writes_nothing(net, tmp_path, monkeypatch, capfd):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SPRAT_SEC_PW", PW)
    net.hosts["auth.test"] = FAILED_LOGINS["422-echo-in-input"]
    cfg = {"spec": "http://api.test/openapi.json", "out_dir": str(tmp_path / "out"),
           "login_a": {"url": "http://auth.test/login", "token_path": "data.accessToken",
                       "body": '{"email": "qa@x.test", "password": "${SPRAT_SEC_PW}"}'}}
    (tmp_path / "c.yaml").write_text(yaml.safe_dump(cfg), encoding="utf-8")
    assert cli.main(["run", "--config", str(tmp_path / "c.yaml"), "--stages", "authz"]) == 2
    o, e = capfd.readouterr()
    assert "user A: login failed with HTTP 422" in e
    assert PW not in o + e
    assert files_containing(tmp_path, [PW]) == {}
    assert not net.to("api.test")  # nothing was tested with a failed login


# ---------------- 3. literal passwords in login settings are refused ----------------

LITERAL = "hunter2-literal"
LITERAL_LOGINS = {
    "json password": {"body": json.dumps({"email": "a@x.test", "password": LITERAL})},
    "nested json pwd": {"body": json.dumps({"user": {"name": "a", "pwd": LITERAL}})},
    "json client_secret": {"body": json.dumps({"client_id": "c", "client_secret": LITERAL})},
    "json apiKey in list": {"body": json.dumps({"creds": [{"apiKey": LITERAL}]})},
    "form password": {"body": f"username=a&password={LITERAL}", "body_type": "form"},
    "raw form password": {"body": f"user=a&passwd={LITERAL}", "body_type": "raw"},
    "header x-api-key": {"headers": {"X-Api-Key": LITERAL}},
    "header authorization": {"headers": {"Authorization": f"Basic {LITERAL}"}},
}


@pytest.mark.parametrize("case", list(LITERAL_LOGINS))
def test_literal_secret_in_login_is_refused_and_not_stored(case, web_client):
    client, data, _ = web_client
    login = {"url": "http://auth.test/login", "token_path": "token", **LITERAL_LOGINS[case]}
    assert literal_secrets(LoginConfig.from_dict(login))
    r = client.post("/api/login/test", json={"login": login})
    assert r.status_code == 400 and "typed directly" in r.text and LITERAL not in r.text
    r = client.post("/api/projects", json={"name": "p", "spec": "http://api.test/openapi.json", "login_b": login})
    assert r.status_code == 400 and "User B" in r.text and LITERAL not in r.text
    assert not data.exists() or files_containing(data, [LITERAL]) == {}


def test_secret_references_are_accepted(web_client):
    for login in LITERAL_LOGINS.values():
        ref = {k: (v.replace(LITERAL, "${SOME_SECRET}") if isinstance(v, str) else
                   {hk: hv.replace(LITERAL, "${SOME_SECRET}") for hk, hv in v.items()})
               for k, v in login.items()}
        assert literal_secrets(LoginConfig.from_dict({"url": "http://auth.test/login", **ref})) == []


@pytest.mark.parametrize("url", [f"http://auth.test/login?password={LITERAL}", f"http://qa:{LITERAL}@auth.test/login"])
def test_literal_password_in_login_url_is_refused(url):
    assert literal_secrets(LoginConfig(url=url, body='{"email": "a@x.test"}'))


# ---------------- 4. the web UI stays local ----------------

def test_web_ui_binds_loopback_by_default(tmp_path, monkeypatch, capsys):
    from sprat.web import app as web
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(web, "DATA", web.DATA)
    monkeypatch.setattr(web, "_store", None)
    assert cli.build_parser().parse_args(["ui"]).host == "127.0.0.1"
    calls = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.append(kw))
    monkeypatch.setattr(socket.socket, "connect_ex", lambda self, addr: 1)  # port free, whatever runs here
    assert cli.main(["ui"]) == 0
    assert calls[-1]["host"] == "127.0.0.1" and calls[-1]["port"] == 8787
    assert "WARNING" not in capsys.readouterr().out
    assert web.DATA == (tmp_path / "reports").resolve()
    monkeypatch.setattr(socket.socket, "connect_ex", lambda self, addr: 0)  # something already listens
    with pytest.raises(SystemExit, match="Port 8787 is already in use.*--port 8788"):
        cli.main(["ui"])
    monkeypatch.setattr(socket.socket, "connect_ex", lambda self, addr: 1)
    cli.main(["ui", "--host", "0.0.0.0"])  # binding elsewhere is possible, but loudly
    assert calls[-1]["host"] == "0.0.0.0" and "WARNING: binding to 0.0.0.0" in capsys.readouterr().out


# ---------------- 5. ids from the URL can't escape the data dir ----------------

SPEC = {"openapi": "3.0.1", "info": {"title": "T", "version": "1"}, "servers": [{"url": "http://api.test"}],
        "paths": {"/a": {"get": {"responses": {"200": {"description": "ok"}}}}}}

TRAVERSALS = ["%2e%2e", "..%5c..%5coutside", "%2e%2e%5c%2e%2e%5coutside", "..%5coutside", "outside%00",
              "%2e%2e%2f%2e%2e%2foutside", "..%2f..%2foutside"]


@pytest.mark.slow
def test_project_and_run_ids_cannot_escape_the_data_dir(web_client, net):
    client, data, web = web_client
    net.hosts["api.test"] = lambda r: httpx.Response(200, json=SPEC)
    outside = data.parent / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("SENTINEL-outside", encoding="utf-8")
    (data.parent / "outside.json").write_text('{"id": "outside", "name": "SENTINEL-json"}', encoding="utf-8")
    # a hostile project name becomes a safe slug inside projects/
    pid = client.post("/api/projects", json={"name": "../../outside", "spec": "http://api.test/openapi.json",
                                             "secrets": {"S": "SENTINEL-secret"}}).json()["id"]
    assert re.fullmatch(r"[a-z0-9-]+", pid) and (data / "projects" / f"{pid}.json").is_file()
    rid = "20260101-000000-abcdef"
    (data / "runs" / rid).mkdir(parents=True)
    (data / "runs" / rid / "run.json").write_text(json.dumps(
        {"id": rid, "project_id": pid, "project_name": "outside", "status": "done", "started": time.time(),
         "finished": time.time(), "operations": [], "tested": []}))
    (data / "runs" / rid / "notes.txt").write_text("inside the run", encoding="utf-8")
    # the real ones are reachable (so the attacks below do reach the handlers)
    assert client.get(f"/api/projects/{pid}").status_code == 200
    assert client.get(f"/api/runs/{rid}").status_code == 200
    assert client.get(f"/api/runs/{rid}/files/notes.txt").text == "inside the run"

    attacks = []
    for bad in TRAVERSALS:
        attacks += [("GET", f"/api/projects/{bad}"), ("PUT", f"/api/projects/{bad}"),
                    ("DELETE", f"/api/projects/{bad}"), ("POST", f"/api/projects/{bad}/refresh"),
                    ("GET", f"/api/projects/{bad}/yaml"), ("GET", f"/api/projects/{bad}/secrets"),
                    ("PUT", f"/api/projects/{bad}/secrets/S"), ("DELETE", f"/api/projects/{bad}/secrets/S"),
                    ("POST", f"/api/projects/{bad}/runs"), ("GET", f"/api/projects/{bad}/runs"),
                    ("PUT", f"/api/projects/{pid}/secrets/{bad}"),
                    ("GET", f"/api/runs/{bad}"), ("POST", f"/api/runs/{bad}/cancel"), ("GET", f"/api/runs/{bad}/log"),
                    ("GET", f"/api/runs/{bad}/log/1"), ("GET", f"/api/runs/{bad}/files/secret.txt"),
                    ("GET", f"/api/runs/{bad}/files/secrets.json"), ("GET", f"/api/runs/{bad}/files/outside.json"),
                    ("GET", f"/api/runs/{rid}/files/{bad}%5csecret.txt"),
                    ("GET", f"/api/runs/{rid}/files/..%5c..%5csecrets.json"),
                    ("GET", f"/api/runs/{rid}/files/..%5c..%5c..%5coutside%5csecret.txt"),
                    ("GET", f"/static/{bad}%5capp.py"), ("GET", "/static/..%5capp.py"),
                    ("GET", f"/api/projects?x={bad}"), ("GET", f"/api/vars?names=S&project={bad}")]
        attacks += [("GET", f"/api/runs/{bad}/download/{k}") for k in ("html", "view", "csv", "ndjson", "zip")]
    body = {"name": "x", "spec": "http://api.test/openapi.json", "value": "v"}
    for method, url in attacks:
        r = client.request(method, url, json=body if method in ("PUT", "POST") else None)
        assert b"SENTINEL" not in r.content, (method, url, r.status_code)
        assert r.status_code != 200 or url.startswith(("/api/projects?", "/api/vars")), (method, url)
    # nothing outside was touched, the secret store still holds the project's secret
    assert (outside / "secret.txt").read_text(encoding="utf-8") == "SENTINEL-outside"
    assert (data.parent / "outside.json").is_file()
    assert sorted(p.name for p in data.parent.iterdir()) == ["data", "outside", "outside.json"]
    assert web.store().values(pid) == {"S": "SENTINEL-secret"}


def test_run_file_never_touches_paths_outside_the_data_dir(web_client, monkeypatch):
    from urllib.parse import quote
    client, data, _ = web_client
    outside = data.parent / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("SENTINEL-outside", encoding="utf-8")
    (data / "runs").mkdir(parents=True)
    touched = []
    real_is_file = Path.is_file
    monkeypatch.setattr(Path, "is_file", lambda self: touched.append(Path(self)) or real_is_file(self))
    r = client.get(f"/api/runs/{quote(str(outside), safe='')}/files/secret.txt")
    assert r.status_code == 404 and b"SENTINEL" not in r.content  # never served...
    root = data.resolve()
    assert [str(p) for p in touched if not p.resolve().is_relative_to(root)] == []  # ...nor even looked at


# ---------------- 6. hostile content from the target API ----------------

XSS = "<script>alert('x')</script>"
HOSTILE_SPEC = {
    "openapi": "3.0.1",
    "info": {"title": f"Evil {XSS}", "version": "1", "description": f"<img src=x onerror=alert(1)> {XSS}"},
    "servers": [{"url": "http://hostile.test"}],
    "components": {"securitySchemes": {"b": {"type": "http", "scheme": "bearer"}}},
    "paths": {
        "/admin": {"get": {"summary": f"admin {XSS}", "security": [{"b": []}],
                           "responses": {"200": {"description": XSS}}}},
        "/boom": {"get": {"summary": f"<b>bold</b>{XSS}", "responses": {"200": {"description": "ok"}}}},
        "/items": {"post": {"summary": XSS, "requestBody": {"content": {"application/json": {"schema": {
            "type": "object", "properties": {f"name{XSS}": {"type": "string"}, "n": {"type": "integer"}}}}}},
            "responses": {"200": {"description": "ok"}}}},
    },
}


def hostile_api(request: httpx.Request) -> httpx.Response:
    evil = {"X-Evil": XSS.replace("'", ""), "Content-Type": "text/html"}
    p = request.url.path
    if p == "/openapi.json":
        return httpx.Response(200, json=HOSTILE_SPEC)
    if p == "/boom":
        return httpx.Response(500, headers=evil,
                              text=f"Traceback (most recent call last): {XSS} </script><!--<script> =1+1")
    if p == "/items":
        return httpx.Response(200, headers=evil, text=f"=HYPERLINK(\"http://evil.test\",\"{XSS}\")")
    return httpx.Response(200, headers=evil, text=f"{XSS}</pre></details></td>")


class TagCollector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags, self.title, self._in_title, self.scripts = [], "", False, []
        self._script = None

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
        self._in_title = tag == "title"
        if tag == "script":
            self._script = ""

    def handle_endtag(self, tag):
        self._in_title = False
        if tag == "script" and self._script is not None:
            self.scripts.append(self._script)
            self._script = None

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        if self._script is not None:
            self._script += data


@pytest.fixture
def hostile_run(net, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    net.hosts["hostile.test"] = hostile_api
    out = tmp_path / "out"
    rc = cli.main(["run", "http://hostile.test/openapi.json", "--stages", "types,authz", "--out", str(out)])
    assert rc == 1
    return out


def test_findings_report_escapes_hostile_content(hostile_run):
    page = (hostile_run / "report.html").read_text(encoding="utf-8")
    # hostile text from the API's error body made it into the report, escaped
    assert html.escape(XSS) in page and "Traceback" in page
    assert "<script" not in page.lower() and "<img" not in page.lower() and "<!--" not in page
    p = TagCollector()
    p.feed(page)
    assert {t for t, _ in p.tags} <= {"meta", "title", "style", "h1", "h2", "p", "br", "code", "small", "span", "b",
                                      "table", "tr", "th", "td", "details", "summary", "pre"}


def test_test_report_keeps_hostile_content_inside_its_data_block(hostile_run):
    page = (hostile_run / "test-report.html").read_text(encoding="utf-8")
    p = TagCollector()
    p.feed(page)
    assert [t for t, _ in p.tags if t == "script"] == ["script", "script"]  # data + app code only
    assert not [t for t, _ in p.tags if t in ("img", "svg", "iframe", "b", "pre", "details")]
    data = json.loads(p.scripts[0])  # the data block is intact JSON...
    flat = json.dumps(data)
    assert json.dumps(XSS)[1:-1] in flat and "Traceback" in flat  # ...and holds the hostile text as data
    assert p.scripts[1].lstrip().startswith("const D = JSON.parse")


def test_test_report_data_block_has_no_html_comment_or_script_open(hostile_run):
    page = (hostile_run / "test-report.html").read_text(encoding="utf-8")
    start = page.index('<script type="application/json" id="data">')
    block = page[start:page.index("</script>", start)].split(">", 1)[1]
    assert "<!--" not in block and "<script" not in block.lower()


def test_csv_export_neutralises_formulas_from_target_responses(hostile_run):
    rows = list(csv.DictReader(io.StringIO((hostile_run / "test-log.csv").read_text(encoding="utf-8-sig"))))
    assert any("HYPERLINK" in r["response_body"] for r in rows)
    bad = [(r["seq"], k, v[:30]) for r in rows for k, v in r.items() if v and v[0] in "=+@"]
    assert bad == []


# ---------------- 7. redirects during login and spec loading ----------------

def _attacker(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"data": {"accessToken": jwt("attacker")}})


def _redirector(status: int, target: str):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            return httpx.Response(status, headers={"Location": target})
        return httpx.Response(200, json={"data": {"accessToken": jwt()}})
    return handler


def _leaked_to(net: FakeNet, host: str, secrets: list[str]) -> list[str]:
    out = []
    for r in net.to(host):
        blob = r.content.decode("utf-8", "replace") + str(r.url) + json.dumps(dict(r.headers))
        out += [s for s in secrets if s in blob]
    return out


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_login_redirect_to_other_host_gets_no_password(status, net, monkeypatch):
    monkeypatch.setenv("SPRAT_SEC_PW", PW)
    net.hosts["auth.test"] = _redirector(status, "http://evil.test/collect")
    net.hosts["evil.test"] = _attacker
    with pytest.raises(LoginError, match="redirected to evil.test.*isn't sent there"):
        TokenProvider(_login_cfg()).current_token()
    assert not net.to("evil.test")  # not even contacted


def test_login_redirect_to_other_host_drops_authorization_header(net, monkeypatch):
    monkeypatch.setenv("SPRAT_SEC_CREDS", "cWE6c2VjcmV0LWJhc2lj")
    net.hosts["auth.test"] = _redirector(302, "http://evil.test/collect")
    net.hosts["evil.test"] = _attacker
    cfg = _login_cfg(headers={"Authorization": "Basic ${SPRAT_SEC_CREDS}"})
    cfg.body = ""
    try:
        TokenProvider(cfg).current_token()
    except LoginError:
        pass
    assert net.to("auth.test")[0].headers["authorization"] == "Basic cWE6c2VjcmV0LWJhc2lj"
    assert _leaked_to(net, "evil.test", ["cWE6c2VjcmV0LWJhc2lj"]) == []


def test_login_redirect_to_other_host_gets_no_custom_secret_header(net, monkeypatch):
    monkeypatch.setenv("SPRAT_SEC_KEY", "key-SECRET-77")
    net.hosts["auth.test"] = _redirector(302, "http://evil.test/collect")
    net.hosts["evil.test"] = _attacker
    cfg = _login_cfg(headers={"X-Api-Key": "${SPRAT_SEC_KEY}"})
    cfg.body = ""
    try:
        TokenProvider(cfg).current_token()
    except LoginError:
        pass
    assert _leaked_to(net, "evil.test", ["key-SECRET-77"]) == []


def test_login_redirect_on_same_host_still_works(net, monkeypatch):
    monkeypatch.setenv("SPRAT_SEC_PW", PW)
    net.hosts["auth.test"] = _redirector(307, "/v2/login")
    p = TokenProvider(_login_cfg())
    assert p.current_token().endswith(".signature") and p.expiry_source == "JWT exp claim"
    assert [r.url.path for r in net.seen] == ["/login", "/v2/login"]
    assert all(PW in r.content.decode() for r in net.seen)


def _spec_redirect(net):
    net.hosts["api.test"] = lambda r: httpx.Response(302, headers={"Location": "http://evil.test/openapi.json"})
    net.hosts["evil.test"] = lambda r: httpx.Response(200, json=SPEC)


def test_spec_redirect_to_other_host_drops_authorization(net):
    _spec_redirect(net)
    load_spec("http://api.test/openapi.json", {"Authorization": "Bearer tok-SECRET-1"})
    assert net.to("evil.test") and _leaked_to(net, "evil.test", ["tok-SECRET-1"]) == []


def test_spec_redirect_to_other_host_gets_no_api_key(net):
    _spec_redirect(net)
    load_spec("http://api.test/openapi.json", {"X-Api-Key": "key-SECRET-2"})
    assert _leaked_to(net, "evil.test", ["key-SECRET-2"]) == []


def test_spec_redirect_on_same_host_keeps_the_api_key(net):
    net.hosts["api.test"] = lambda r: (httpx.Response(200, json=SPEC) if r.url.path == "/v2/openapi.json"
                                       else httpx.Response(302, headers={"Location": "/v2/openapi.json"}))
    load_spec("http://api.test/openapi.json", {"X-Api-Key": "key-SECRET-3"})
    assert [r.headers.get("x-api-key") for r in net.to("api.test")] == ["key-SECRET-3", "key-SECRET-3"]


@pytest.mark.parametrize("a, b, ok", [
    ("http://api.test/x", "http://api.test/y", True),
    ("http://API.test/x", "http://api.test/y", True),
    ("http://api.test/x", "https://api.test/y", True),        # upgrade
    ("http://api.test:80/x", "https://api.test:443/y", True),
    ("https://api.test/x", "http://api.test/y", False),       # downgrade: would go out in plain text
    ("http://api.test:8080/x", "https://api.test/y", False),
    ("http://api.test:8000/x", "http://api.test:8001/y", False),
    ("http://api.test/x", "http://evil.test/y", False),
    ("http://api.test/x", "http://api.test.evil.test/y", False),
    ("http://127.0.0.1:8000/x", "http://localhost:8000/y", False),
])
def test_same_site(a, b, ok):
    from sprat.discover import same_site
    assert same_site(a, b) is ok


def test_login_http_to_https_upgrade_is_followed(net, monkeypatch):
    monkeypatch.setenv("SPRAT_SEC_PW", PW)
    net.hosts["auth.test"] = lambda r: (httpx.Response(308, headers={"Location": "https://auth.test/login"})
                                        if r.url.scheme == "http" else _attacker(r))
    assert TokenProvider(_login_cfg()).current_token()
    assert [str(r.url) for r in net.seen] == ["http://auth.test/login", "https://auth.test/login"]


def test_raw_event_stream_is_never_served_or_exported(web_client):
    client, data, _ = web_client
    rid = "20260101-000000-abcdef"
    d = data / "runs" / rid
    d.mkdir(parents=True)
    (d / "run.json").write_text(json.dumps({"id": rid, "status": "done", "started": 1, "operations": []}))
    (d / "test-report.html").write_text("<p>report</p>", encoding="utf-8")
    (d / "schemathesis-events.ndjson").write_text('{"Authorization": "Bearer SENTINEL-raw"}\n', encoding="utf-8")
    assert client.get(f"/api/runs/{rid}/files/schemathesis-events.ndjson").status_code == 404
    z = client.get(f"/api/runs/{rid}/download/zip")
    assert z.status_code == 200 and b"SENTINEL-raw" not in z.content
    import zipfile
    assert not [n for n in zipfile.ZipFile(io.BytesIO(z.content)).namelist() if "events" in n]
