"""End to end: the real examples/demo_api.py served by uvicorn on a free local port, driven through
the CLI, a YAML config with automatic login, and the web UI API, the way a user would.

Each planted flaw of the demo (see the docstring of examples/demo_api.py) must be reported, with a
severity high enough to matter, on the operation it belongs to; the correctly implemented parts
must not be reported.
"""
from __future__ import annotations

import csv
import importlib.util
import io
import json
import os
import socket
import sys
import threading
import time
import zipfile
from pathlib import Path

import httpx
import pytest
import uvicorn
import yaml

from sprat import runner
from sprat.cli import main
from sprat.models import sev_rank

ROOT = Path(__file__).resolve().parents[1]
DEMO_FILE = ROOT / "examples" / "demo_api.py"
DEMO_LOGIN_YAML = ROOT / "examples" / "demo-login.yaml"

pytestmark = pytest.mark.e2e

ADMIN = "GET /admin/stats"
ORDER = "GET /users/{uid}/orders/{oid}"
ITEM = "GET /items/{item_id}"
CREATE = "POST /items"
HEALTH = "GET /health"
LIST = "GET /items"
PROFILE = "GET /users/{uid}/profile"
ME = "GET /users/me"
EXPORT = "GET /reports/export"
COUPON = "GET /coupons/{code}"
ALL_OPS = {ADMIN, ORDER, ITEM, CREATE, HEALTH, LIST, PROFILE, ME, EXPORT, COUPON}
SECURED = {ADMIN, ORDER, PROFILE, ME, EXPORT}
BOLA = [{"method": "GET", "path": "/users/{uid}/orders/{oid}", "params": {"uid": 1, "oid": 10}}]
PROFILE_BOLA = {"method": "GET", "path": "/users/{uid}/profile", "params": {"uid": 1}}  # checks ownership
FAST = "conformance,types,authz"  # the built-in Python stages (lint needs Node, zap needs Docker)


# ---------------- live demo server ----------------

def load_demo(module_name: str, ttl: int | None = None):
    """A fresh instance of examples/demo_api.py with its own state (login counter, issued tokens).
    DEMO_TOKEN_TTL is read at import time, so it is set only while the module is imported."""
    old = os.environ.get("DEMO_TOKEN_TTL")
    try:
        if ttl is not None:
            os.environ["DEMO_TOKEN_TTL"] = str(ttl)
        else:
            os.environ.pop("DEMO_TOKEN_TTL", None)
        spec = importlib.util.spec_from_file_location(module_name, DEMO_FILE)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = mod  # pydantic resolves the models' annotations through it
        spec.loader.exec_module(mod)
        return mod
    finally:
        if old is None:
            os.environ.pop("DEMO_TOKEN_TTL", None)
        else:
            os.environ["DEMO_TOKEN_TTL"] = old


class LiveServer:
    def __init__(self, app):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))  # free port, held until uvicorn takes the socket over
        self.port = self.sock.getsockname()[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="warning"))
        self.thread = threading.Thread(target=self.server.run, kwargs={"sockets": [self.sock]}, daemon=True)

    def __enter__(self):
        self.thread.start()
        end = time.time() + 15
        while not self.server.started:
            if time.time() > end or not self.thread.is_alive():
                raise RuntimeError("demo server did not start")
            time.sleep(0.05)
        return self

    def __exit__(self, *exc):
        self.server.should_exit = True
        self.thread.join(10)
        self.sock.close()

    def logins(self) -> int:
        return httpx.get(f"{self.base}/auth/stats", timeout=5).json()["logins"]


@pytest.fixture(scope="module")
def demo():
    mod = load_demo("_e2e_demo_api")
    with LiveServer(mod.app) as srv:
        srv.module = mod
        yield srv


@pytest.fixture(scope="module")
def demo_short_ttl():
    """Tokens live 6 s (5-6 s, as exp is whole seconds); sprat renews them halfway, every ~3 s."""
    mod = load_demo("_e2e_demo_api_short_ttl", ttl=6)
    with LiveServer(mod.app) as srv:
        srv.module = mod
        yield srv


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    """Schemathesis runs in the CWD (it creates .schemathesis/ and reads schemathesis.toml there):
    keep it in tmp_path, with a fixed seed so the generated cases are reproducible."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "schemathesis.toml").write_text("seed = 1234\n", encoding="utf-8")
    return tmp_path


# ---------------- helpers ----------------

def read_report(out: Path) -> dict:
    return json.loads((out / "report.json").read_text(encoding="utf-8"))


def findings(report: dict) -> list[dict]:
    return [f for s in report["stages"] for f in s["findings"]]


def find(report: dict, op: str, stage: str, title_part: str, min_sev: str = "info") -> list[dict]:
    return [f for f in findings(report) if f["operation"] == op and f["stage"] == stage
            and title_part.lower() in f["title"].lower() and sev_rank(f["severity"]) >= sev_rank(min_sev)]


def log_entries(out: Path) -> list[dict]:
    # split on newlines only: splitlines() also breaks on U+2028 etc., which fuzzed JSON strings contain
    text = (out / "test-log.ndjson").read_text(encoding="utf-8")
    return [json.loads(l) for l in text.split("\n") if l.strip()]


def expected_exit(report: dict, fail_on: str = "high") -> int:
    bad = any(sev_rank(f["severity"]) >= sev_rank(fail_on) for f in findings(report))
    return 1 if bad or any(s["status"] == "error" for s in report["stages"]) else 0


def assert_create_item_crash_found(report: dict, out: Path) -> None:
    """POST /items raises on a negative price -> HTTP 500. Schemathesis reports each crash once, either
    on the operation itself or on the request chain ("Stateful tests") that hit it first."""
    crash = [f for f in findings(report) if f["stage"] == "conformance" and f["title"] == "Server error"
             and sev_rank(f["severity"]) >= sev_rank("high")
             and (f["operation"] == CREATE or "-X POST" in f["detail"] and "/items" in f["detail"])]
    assert crash, [f["title"] for f in findings(report)]
    crashes = [e for e in log_entries(out) if e["operation"] == CREATE and (e["response"] or {}).get("status") == 500]
    assert crashes and all(e["verdict"] == "fail" for e in crashes)
    assert any('"price": -' in (e["request"]["body"] or "") for e in crashes)  # it is the negative price


def assert_no_false_positives(report: dict) -> None:
    # GET /health is implemented correctly: the only thing that may be said about it is the
    # API-wide missing X-Content-Type-Options header (low). Schemathesis' response-time check is
    # excluded: it measures the test machine, not the API.
    loud = [f for f in findings(report) if f["operation"] == HEALTH and sev_rank(f["severity"]) >= sev_rank("medium")
            and "response time" not in f["title"].lower()]
    assert loud == []
    # GET /users/{uid}/orders/{oid} does check authentication (its only flaw is the missing ownership check)
    assert not find(report, ORDER, "authz", "Secured endpoint accepted")
    assert not find(report, ORDER, "conformance", "without authentication")
    # the owner can read the order, so the BOLA scenario really ran
    assert not [f for f in findings(report) if "inconclusive" in f["title"]]


# ---------------- CLI ----------------

@pytest.mark.slow
def test_cli_run_finds_every_planted_flaw(demo, workdir, capsys):
    out = workdir / "out"
    cfg = workdir / "bola.yaml"
    cfg.write_text(yaml.safe_dump({"headers_b": {"Authorization": "Bearer token-b"}, "bola": BOLA + [PROFILE_BOLA]}),
                   encoding="utf-8")
    rc = main(["run", f"{demo.base}/openapi.json", "--config", str(cfg), "-H", "Authorization: Bearer token-a",
               "--stages", FAST, "--max-examples", "5", "--fail-on", "high", "--out", str(out)])
    stdout = capsys.readouterr().out
    report = read_report(out)

    assert [s["name"] for s in report["stages"]] == ["conformance", "types", "authz"]
    assert all(s["status"] == "ok" for s in report["stages"]), report["stages"]
    assert rc == 1 == expected_exit(report)
    for f in ("report.json", "report.html", "test-report.html", "test-log.ndjson", "test-log.csv",
              "coverage.json", "coverage.csv", "schemathesis-junit.xml", "types.log"):
        assert (out / f).is_file() and (out / f).stat().st_size > 0, f
    assert f"Report: {out / 'test-report.html'}" in stdout and "[authz] ok:" in stdout

    # 1. GET /admin/stats declares bearer security but never checks it
    assert find(report, ADMIN, "authz", "Secured endpoint accepted no credentials", "critical")
    assert find(report, ADMIN, "authz", "Secured endpoint accepted invalid credentials", "critical")
    assert find(report, ADMIN, "conformance", "without authentication", "high")
    # 2. BOLA: user B reads user A's order
    bola = find(report, ORDER, "authz", "BOLA: user B accessed user A's resource", "critical")
    assert bola and "'uid': '1'" in bola[0]["endpoint"] and "'oid': '10'" in bola[0]["endpoint"]
    # 3. POST /items crashes (500) on a negative price
    assert_create_item_crash_found(report, out)
    # 4. Item.in_stock / id / price: pydantic's lax mode accepts look-alike values
    in_stock = find(report, CREATE, "types", "Field `in_stock` (boolean) accepted wrong types", "medium")
    assert in_stock and all(v in in_stock[0]["title"] for v in ('string "true"', "integer 1", 'string "yes"'))
    assert find(report, CREATE, "types", 'Field `id` (integer) accepted wrong types: numeric string "1"', "medium")
    assert find(report, CREATE, "types", 'Field `price` (number) accepted wrong types: numeric string "1.5"', "medium")
    assert find(report, CREATE, "conformance", "schema-violating request", "medium")
    # 5. GET /users/me sends a Python traceback for a malformed token
    assert find(report, ME, "authz", "Error response leaks stack trace", "medium")
    # 6. GET /reports/export checks that a token is there, not that it's valid
    assert find(report, EXPORT, "authz", "Secured endpoint accepted invalid credentials", "critical")
    assert not find(report, EXPORT, "authz", "Secured endpoint accepted no credentials")
    # 7. GET /coupons/{code} answers unknown codes with 200 and no `discount`
    assert find(report, COUPON, "conformance", "Response violates schema", "medium")
    # GET /users/{uid}/profile checks ownership: B is refused, so no BOLA finding
    assert not find(report, PROFILE, "authz", "BOLA")
    assert_no_false_positives(report)

    # the reports agree with report.json
    html = (out / "test-report.html").read_text(encoding="utf-8")
    assert all(op in html for op in ALL_OPS)
    assert "BOLA: user B accessed user A&#x27;s resource" in (out / "report.html").read_text(encoding="utf-8")
    cov = json.loads((out / "coverage.json").read_text(encoding="utf-8"))
    verdicts = {a["operation"]: a["verdict"] for a in cov["apis"]}
    assert set(verdicts) == ALL_OPS
    assert verdicts[ADMIN] == verdicts[ORDER] == verdicts[CREATE] == "problems"
    rows = list(csv.DictReader(io.StringIO((out / "test-log.csv").read_text(encoding="utf-8-sig"))))
    assert len(rows) == len(log_entries(out)) and {r["stage"] for r in rows} == {"conformance", "types", "authz"}
    # the fixed tokens are masked in the test log
    assert "token-a" not in (out / "test-log.ndjson").read_text(encoding="utf-8")


@pytest.mark.slow
def test_cli_finds_response_schema_violation_with_spec_example(demo, workdir):
    """GET /items/7 returns price "free" where the spec says number. Random IDs rarely hit 7, so like
    a user would, give the parameter an `example` in a local copy of the spec and test just that API."""
    doc = httpx.get(f"{demo.base}/openapi.json").json()
    param = doc["paths"]["/items/{item_id}"]["get"]["parameters"][0]
    assert param["name"] == "item_id"
    param["example"] = 7
    spec = workdir / "demo-spec.json"
    spec.write_text(json.dumps(doc), encoding="utf-8")
    out = workdir / "out"
    rc = main(["run", str(spec), "--base-url", demo.base, "--stages", "conformance", "--op", ITEM,
               "--max-examples", "3", "--out", str(out)])
    report = read_report(out)
    assert rc == expected_exit(report)
    hits = find(report, ITEM, "conformance", "Response violates schema", "medium")
    assert hits and "free" in hits[0]["detail"]
    assert {f["operation"] for f in findings(report)} <= {ITEM}  # --op: nothing else was tested


def test_cli_exit_code_is_zero_when_nothing_reaches_fail_on(demo, workdir):
    out = workdir / "out"
    rc = main(["run", f"{demo.base}/openapi.json", "--stages", "authz", "--op", HEALTH, "--out", str(out)])
    report = read_report(out)
    assert [f["severity"] for f in findings(report)] == ["low"]  # missing X-Content-Type-Options only
    assert rc == 0 == expected_exit(report)
    rc = main(["run", f"{demo.base}/openapi.json", "--stages", "authz", "--op", HEALTH, "--fail-on", "low",
               "--out", str(workdir / "out2")])
    assert rc == 1


def test_cli_reports_missing_external_tools_as_skipped(demo, workdir, monkeypatch, capsys):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda *a, **k: None)  # no npx, no docker
    out = workdir / "out"
    rc = main(["run", f"{demo.base}/openapi.json", "--stages", "lint,authz,zap", "--out", str(out)])
    report = read_report(out)
    status = {s["name"]: (s["status"], s["note"]) for s in report["stages"]}
    assert status["lint"][0] == "skipped" and "npx" in status["lint"][1]
    assert status["zap"][0] == "skipped" and "Docker" in status["zap"][1]
    assert status["authz"][0] == "ok"
    assert rc == 1  # skipped tools aren't failures; the authz findings are
    stdout = capsys.readouterr().out
    assert "[lint] skipped" in stdout and "[zap] skipped" in stdout


# ---------------- config file with automatic login ----------------

def login_config(base: str, out: Path) -> dict:
    """examples/demo-login.yaml pointed at the test server."""
    cfg = yaml.safe_load(DEMO_LOGIN_YAML.read_text(encoding="utf-8"))
    text = json.dumps(cfg).replace("http://localhost:8000", base)
    cfg = json.loads(text)
    assert "${DEMO_ALICE_PW}" in cfg["login_a"]["body"] and "${DEMO_BOB_PW}" in cfg["login_b"]["body"]
    cfg["out_dir"] = str(out)
    cfg["max_examples"] = 5
    return cfg


@pytest.mark.slow
def test_config_file_with_automatic_login_and_token_refresh(demo_short_ttl, workdir, monkeypatch, capsys):
    srv = demo_short_ttl
    monkeypatch.setenv("DEMO_ALICE_PW", "alice-pass")
    monkeypatch.setenv("DEMO_BOB_PW", "bob-pass")
    out = workdir / "out"
    path = workdir / "demo-login.yaml"
    path.write_text(yaml.safe_dump(login_config(srv.base, out)), encoding="utf-8")
    assert httpx.get(f"{srv.base}/auth/stats").json()["ttl"] == 6
    # The run must outlive the first tokens whatever the machine's speed. User B's token is only used by
    # authz, so wait before that stage until B's first token is dead on the server: the cross-user
    # checks then only pass if sprat logged B in again in time.
    real_authz = runner.STAGE_FUNCS["authz"]

    def authz_after_first_token_expired(spec, cfg, out_dir):
        time.sleep(max(0.0, cfg.auth_b.expires_at + 0.2 - time.time()))
        return real_authz(spec, cfg, out_dir)

    monkeypatch.setitem(runner.STAGE_FUNCS, "authz", authz_after_first_token_expired)
    before = srv.logins()
    rc = main(["run", "--config", str(path), "--stages", FAST])
    stdout = capsys.readouterr().out
    report = read_report(out)

    assert all(s["status"] == "ok" for s in report["stages"]), report["stages"]
    assert rc == 1 == expected_exit(report)  # findings, not a login error (2)
    assert "Logged in as user A (login #1)" in stdout and "Logged in as user B (login #1)" in stdout
    # the run outlived the first tokens: sprat logged in again by itself
    assert "Logged in as user B (login #2)" in stdout
    assert srv.logins() - before >= 4  # A and B, Schemathesis' own login, B's renewal
    # ...and in time: no request was ever refused because its token had expired
    entries = log_entries(out)
    assert not [e for e in entries if "Token expired" in ((e["response"] or {}).get("body") or "")]
    # authenticated requests were really authenticated: the owner reads its order, B too (BOLA)
    assert find(report, ORDER, "authz", "BOLA: user B accessed user A's resource", "critical")
    steps = [e for e in entries if e["stage"] == "authz" and e["scenario"].startswith("Cross-user check")]
    assert [e["response"]["status"] for e in steps] == [200, 200]
    assert all(e["request"]["headers"]["authorization"] == "Bearer ***" for e in steps)
    assert find(report, ADMIN, "authz", "Secured endpoint accepted no credentials", "critical")
    assert find(report, CREATE, "types", "Field `in_stock` (boolean) accepted wrong types", "medium")
    assert_create_item_crash_found(report, out)
    assert_no_false_positives(report)


def test_config_file_login_with_wrong_password_fails_cleanly(demo, workdir, monkeypatch, capsys):
    monkeypatch.setenv("DEMO_ALICE_PW", "not-alice-pass")
    monkeypatch.setenv("DEMO_BOB_PW", "bob-pass")
    out = workdir / "out"
    path = workdir / "demo-login.yaml"
    path.write_text(yaml.safe_dump(login_config(demo.base, out)), encoding="utf-8")
    rc = main(["run", "--config", str(path), "--stages", "authz"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "user A: login failed with HTTP 401: Invalid email or password" in err
    assert not (out / "report.json").exists()  # nothing was tested


# ---------------- web UI API ----------------

@pytest.fixture
def web_client(workdir, monkeypatch):
    from fastapi.testclient import TestClient
    from sprat.web import app as web
    monkeypatch.setattr(web, "DATA", web.DATA)
    monkeypatch.setattr(web, "_store", None)
    monkeypatch.delenv("SPRAT_SECRET_KEY", raising=False)
    data = workdir / "data"
    web.configure(data)
    web._runs.clear(); web._cancels.clear(); web._secrets.clear()
    with TestClient(web.app) as client:
        yield client, data
    web._runs.clear(); web._cancels.clear(); web._secrets.clear()


def wait_run(client, rid: str, timeout: float = 150) -> dict:
    end = time.time() + timeout
    while time.time() < end:
        r = client.get(f"/api/runs/{rid}")
        assert r.status_code == 200
        run = r.json()
        if run["status"] not in ("running", "stopping"):
            return run
        time.sleep(0.3)
    raise AssertionError("run did not finish")


@pytest.mark.slow
def test_web_ui_project_run_against_live_demo(demo, web_client):
    client, data = web_client
    base = demo.base
    login = lambda user, var: {"url": f"{base}/auth/login", "token_path": "data.accessToken",
                               "body": json.dumps({"email": f"{user}@demo.test", "password": "${%s}" % var})}
    body = {"name": "Demo API", "spec": f"{base}/openapi.json", "stages": ["conformance", "types", "authz"],
            "max_examples": 5, "login_a": login("alice", "DEMO_ALICE_PW"), "login_b": login("bob", "DEMO_BOB_PW"),
            "bola": [{**BOLA[0], "params": {"uid": "1", "oid": "10"}}], "secrets": {"DEMO_ALICE_PW": "alice-pass", "DEMO_BOB_PW": "bob-pass"}}
    r = client.post("/api/projects", json=body)
    assert r.status_code == 200, r.text
    pid = r.json()["id"]
    p = client.get(f"/api/projects/{pid}").json()
    assert p["spec_info"]["title"] == "Demo API" and p["spec_info"]["base_url"] == base
    assert {o["label"] for o in p["operations"]} == ALL_OPS
    assert {o["label"] for o in p["operations"] if o["secured"]} == SECURED
    assert [s["name"] for s in p["secrets"]] == ["DEMO_ALICE_PW", "DEMO_BOB_PW"] and "alice-pass" not in r.text

    t = client.post("/api/login/test", json={"login": body["login_a"], "project_id": pid}).json()
    assert t["ok"] and t["expiry_source"] == "JWT exp claim" and t["jwt"]["sub"] == 1

    before = demo.logins()
    rid = client.post(f"/api/projects/{pid}/runs", json={}).json()["id"]
    run = wait_run(client, rid)
    assert run["status"] == "done", run.get("error")
    assert demo.logins() - before >= 3  # A and B by the server, A again inside Schemathesis
    assert set(run["tested"]) == ALL_OPS
    assert {k: v["status"] for k, v in run["stages"].items()} == {"conformance": "ok", "types": "ok", "authz": "ok"}
    assert run["headers"] == {"login": "automatic"} and run["headers_b"] == {"login": "automatic"}
    assert any(f["stage"] == "auth" and "Logged in as user A" in f["msg"] for f in run["feed"])
    report = run["report"]
    assert find(report, ADMIN, "authz", "Secured endpoint accepted no credentials", "critical")
    assert find(report, ORDER, "authz", "BOLA: user B accessed user A's resource", "critical")
    assert find(report, CREATE, "types", "Field `in_stock` (boolean) accepted wrong types", "medium")
    assert_no_false_positives(report)
    assert {"report.json", "test-report.html", "test-log.ndjson", "schemathesis.log"} <= set(run["files"])

    # per-API status on the project page
    st = client.get(f"/api/projects/{pid}").json()["op_status"]
    assert st[ADMIN]["max"] == "critical" and st[ORDER]["max"] == "critical"
    assert sev_rank(st[CREATE]["max"]) >= sev_rank("medium")
    assert sev_rank(st[HEALTH]["max"] or "info") <= sev_rank("low")
    assert all(s["run_id"] == rid for s in st.values())
    listed = client.get("/api/projects").json()[0]
    assert listed["last_run"]["id"] == rid and listed["last_run"]["counts"]["critical"] >= 3

    # test log: browse, filter, open one entry
    log = client.get(f"/api/runs/{rid}/log").json()
    assert log["available"] and set(log["stages"]) == {"conformance", "types", "authz"}
    fails = client.get(f"/api/runs/{rid}/log", params={"verdict": "fail", "op": ADMIN, "stage": "authz"}).json()
    assert fails["total"] == 2 and all(i["status"] == 200 for i in fails["items"])
    step2 = client.get(f"/api/runs/{rid}/log", params={"q": "user B tries"}).json()["items"]
    assert len(step2) == 1 and step2[0]["verdict"] == "fail" and step2[0]["operation"] == ORDER
    full = client.get(f"/api/runs/{rid}/log/{step2[0]['seq']}").json()
    assert full["request"]["headers"]["authorization"] == "Bearer ***"
    assert json.loads(full["response"]["body"])["user_id"] == 1  # B really got A's order

    # downloads
    for kind in ("html", "view", "csv", "ndjson", "zip"):
        d = client.get(f"/api/runs/{rid}/download/{kind}")
        assert d.status_code == 200, kind
        assert (kind == "view") != ("attachment" in d.headers.get("content-disposition", ""))
        blob = d.content
        if kind == "zip":
            z = zipfile.ZipFile(io.BytesIO(blob))
            names = {n.split("/", 1)[1] for n in z.namelist()}
            assert {"test-report.html", "report.json", "test-log.ndjson", "test-log.csv", "run.json",
                    "README.txt", "schemathesis-junit.xml"} <= names
            blob = b"".join(z.read(n) for n in z.namelist())
        assert b"alice-pass" not in blob and b"bob-pass" not in blob
    assert client.get(f"/api/runs/{rid}/files/schemathesis.log").status_code == 200
    yaml_text = client.get(f"/api/projects/{pid}/yaml").text
    assert "${DEMO_ALICE_PW}" in yaml_text and "alice-pass" not in yaml_text
    # the passwords are only in the encrypted secret store
    for f in data.rglob("*"):
        if f.is_file():
            assert b"alice-pass" not in f.read_bytes() and b"bob-pass" not in f.read_bytes(), f
