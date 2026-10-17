"""OWASP ZAP stage: docker detection, command line, report parsing, cancel, live progress.

Docker is faked (zap._docker_ok / zap.run_cmd); the `external` test runs the real image if it is
already pulled and the daemon is up.
"""
import http.server
import json
import shlex
import shutil
import subprocess
import threading
import time
from types import SimpleNamespace

import pytest

from sprat.config import Config
from sprat.models import Finding
from sprat.proc import Cancelled, Result
from sprat.spec import Operation, Spec
from sprat.stages import zap
from sprat.testlog import TestLog, iter_entries

SPEC_TEXT = '{"openapi": "3.0.3", "paths": {}}'


def _spec(base="http://localhost:8000", ops=None, text=SPEC_TEXT, full_text="", filtered=False):
    ops = ops if ops is not None else [Operation("get", "/items", False, False),
                                       Operation("get", "/items/{id}", False, False),
                                       Operation("post", "/items", False, True)]
    return Spec({}, base + "/openapi.json", "openapi3", base, ops, text, full_text, filtered)


def _alert(name="X-Content-Type-Options Header Missing", risk="1", instances=None, **kw):
    a = {"name": name, "riskcode": risk, "confidence": "2", "desc": "<p>The header is missing.</p>",
         "solution": "<p>Set the header.</p>", "reference": "<p>https://ref</p>", "cweid": "693", "wascid": "15",
         "instances": instances if instances is not None else [
             {"uri": "http://host.docker.internal:8000/items", "method": "GET", "param": "x-content-type-options",
              "attack": "", "evidence": "", "otherinfo": "note"}]}
    a.update(kw)
    return a


class FakeDocker:
    """Stands in for run_cmd: records the call and writes zap.json into the mounted dir."""

    def __init__(self, out):
        self.out, self.calls, self.report, self.raw = out, [], {"site": []}, None
        self.stdout, self.stderr, self.rc, self.ticks, self.cancel_it = "", "", 0, None, False

    def __call__(self, cmd, **kw):
        self.calls.append((cmd, kw))
        if self.ticks is not None:
            kw["on_tick"](self.ticks)
        if self.cancel_it:
            kw["on_cancel"]()
            raise Cancelled()
        if self.raw is not None:
            (self.out / "zap.json").write_text(self.raw, encoding="utf-8")
        elif self.report is not None:
            (self.out / "zap.json").write_text(json.dumps(self.report), encoding="utf-8")
        return Result(self.rc, self.stdout, self.stderr)

    @property
    def cmd(self):
        return self.calls[0][0]

    def opt(self, flag):
        return self.cmd[self.cmd.index(flag) + 1]


@pytest.fixture
def docker(tmp_path, monkeypatch):
    out = tmp_path / "out"
    out.mkdir()
    d = FakeDocker(out)
    d.rm = []
    monkeypatch.setattr(zap, "_docker_ok", lambda: True)
    monkeypatch.setattr(zap, "_docker_resources", lambda: (0, 0))  # unknown: fixed defaults
    monkeypatch.setattr(zap, "run_cmd", d)
    monkeypatch.setattr(zap.subprocess, "run", lambda c, **k: d.rm.append(c))
    # Partial report from ZAP's API: d.partial (a zap.json-style dict) is "saved" when set
    d.partial, d.saved = None, []

    def save(self, html=False):
        d.saved.append((html, len(d.rm)))
        if d.partial is not None:
            self.path.write_text(json.dumps(d.partial), encoding="utf-8")
    monkeypatch.setattr(zap._Snapshot, "save", save)
    return d


def _run(docker, spec=None, cfg=None):
    return zap.run(spec or _spec(), cfg or Config(), docker.out)


# ---------- docker detection ----------

def test_docker_ok_false_without_docker_binary(monkeypatch):
    ran = []
    monkeypatch.setattr(zap.shutil, "which", lambda n: None)
    monkeypatch.setattr(zap.subprocess, "run", lambda *a, **k: ran.append(a))
    assert zap._docker_ok() is False and ran == []


@pytest.mark.parametrize("rc, ok", [(0, True), (1, False), (125, False)])
def test_docker_ok_depends_on_docker_info(monkeypatch, rc, ok):
    ran = []
    monkeypatch.setattr(zap.shutil, "which", lambda n: r"C:\docker\docker.exe")
    monkeypatch.setattr(zap.subprocess, "run",
                        lambda c, **k: ran.append((c, k)) or SimpleNamespace(returncode=rc))
    assert zap._docker_ok() is ok
    assert ran[0][0] == ["docker", "info"] and ran[0][1]["capture_output"] is True


def test_no_docker_is_skipped_not_passed(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(zap, "_docker_ok", lambda: False)
    monkeypatch.setattr(zap, "run_cmd", lambda *a, **k: called.append(a))
    res = zap.run(_spec(), Config(), tmp_path)
    assert (res.name, res.status, res.findings) == ("zap", "skipped", [])
    assert res.note == "Docker not available or daemon not running"
    assert called == [] and list(tmp_path.iterdir()) == []


# ---------- URL rewriting ----------

@pytest.mark.parametrize("url, expected", [
    ("http://localhost:8000", "http://host.docker.internal:8000"),
    ("http://localhost:8000/api/v1?x=1#f", "http://host.docker.internal:8000/api/v1?x=1#f"),
    ("http://127.0.0.1:5000/", "http://host.docker.internal:5000/"),
    ("http://localhost", "http://host.docker.internal"),
    ("https://localhost/api", "https://host.docker.internal/api"),
    ("http://LOCALHOST:8000/Path", "http://host.docker.internal:8000/Path"),
    ("https://api.example.com/v1", "https://api.example.com/v1"),
    ("http://localhost.example.com:8000", "http://localhost.example.com:8000"),
    ("http://10.0.0.5:8000", "http://10.0.0.5:8000"),
    ("http://host.docker.internal:8000", "http://host.docker.internal:8000"),
    ("", ""),
])
def test_for_container(url, expected):
    assert zap._for_container(url) == expected


def test_for_container_rewrites_ipv6_loopback():
    assert zap._for_container("http://[::1]:8000/api") == "http://host.docker.internal:8000/api"


def test_for_container_keeps_credentials():
    assert zap._for_container("http://u:p@localhost:8000/") == "http://u:p@host.docker.internal:8000/"


# ---------- command line ----------

def test_command_line(docker, tmp_path):
    cfg = Config(cancel=threading.Event(), zap_image="example/zap:1.2")
    _run(docker, cfg=cfg)
    cmd, kw = docker.calls[0]
    name = cmd[cmd.index("--name") + 1]
    assert name.startswith("sprat-zap-") and len(name) == len("sprat-zap-") + 8
    port = cmd[cmd.index("-p") + 1]
    assert cmd == ["docker", "run", "--rm", "--name", name, "--add-host", "host.docker.internal:host-gateway",
                   "-v", f"{docker.out.resolve()}:/zap/wrk:rw", "-p", port, "example/zap:1.2", "zap-api-scan.py",
                   "-t", "spec.json", "-f", "openapi", "-O", "http://host.docker.internal:8000",
                   "-J", "zap.json", "-r", "zap.html", "-I", "-d", "-P", "8090", "-z",
                   "-config scanner.threadPerHost=16 -config scanner.maxRuleDurationInMins=2 "
                   "-config scanner.maxScanDurationInMins=50"]
    assert kw["cancel"] is cfg.cancel and kw["timeout"] == 80 * 60
    assert callable(kw["on_cancel"]) and callable(kw["on_tick"])


def test_default_image_and_unique_container_names(docker):
    _run(docker)
    _run(docker)
    names = [c[c.index("--name") + 1] for c, _ in docker.calls]
    assert names[0] != names[1]
    assert docker.cmd[docker.cmd.index("zap-api-scan.py") - 1] == "ghcr.io/zaproxy/zaproxy:stable"


def test_writes_the_reduced_spec_for_zap(docker):
    _run(docker, spec=_spec(text='{"reduced": 1}', full_text='{"full": 1}', filtered=True))
    assert (docker.out / "spec.json").read_text(encoding="utf-8") == '{"reduced": 1}'


def test_config_base_url_overrides_spec(docker):
    _run(docker, cfg=Config(base_url="https://staging.example.com/api"))
    assert docker.opt("-O") == "https://staging.example.com/api"


def test_no_headers_means_no_replacer_options(docker):
    _run(docker)
    assert "replacer" not in docker.opt("-z")


def test_scan_speed_and_time_limits_are_configurable(docker):
    _run(docker, cfg=Config(zap_threads=24, zap_rule_minutes=0, zap_max_minutes=0))
    z = shlex.split(docker.opt("-z"))
    assert z[:6] == ["-config", "scanner.threadPerHost=24", "-config", "scanner.maxRuleDurationInMins=0",
                     "-config", "scanner.maxScanDurationInMins=0"]
    assert docker.calls[0][1]["timeout"] == 24 * 3600  # no scan limit: only a safety net


@pytest.mark.parametrize("cpus, mem, threads, heap", [
    (4, 8192, 16, 4096), (1, 1024, 8, 0), (32, 65536, 48, 32768), (0, 0, 16, 0)])
def test_threads_and_memory_sized_from_docker(docker, monkeypatch, cpus, mem, threads, heap):
    monkeypatch.setattr(zap, "_docker_resources", lambda: (cpus, mem))
    got = []
    _run(docker, cfg=Config(on_progress=got.append))
    z = shlex.split(docker.opt("-z"))
    assert z[1] == f"scanner.threadPerHost={threads}"
    assert [t for t in z if t.startswith("-Xmx")] == ([f"-Xmx{heap}m"] if heap else [])
    assert got[0]["msg"].startswith(f"Starting the OWASP ZAP container ({threads} parallel requests")


def test_configured_threads_win_over_docker_sizing(docker, monkeypatch):
    monkeypatch.setattr(zap, "_docker_resources", lambda: (32, 65536))
    _run(docker, cfg=Config(zap_threads=5))
    assert "scanner.threadPerHost=5" in shlex.split(docker.opt("-z"))


def test_docker_resources_parses_docker_info(monkeypatch):
    monkeypatch.setattr(zap.subprocess, "run", lambda c, **k: SimpleNamespace(stdout="4 8146247680\n"))
    assert zap._docker_resources() == (4, 7768)


@pytest.mark.parametrize("run", [lambda c, **k: SimpleNamespace(stdout=""),
                                 lambda c, **k: (_ for _ in ()).throw(subprocess.TimeoutExpired(c, 30))])
def test_docker_resources_unknown(monkeypatch, run):
    monkeypatch.setattr(zap.subprocess, "run", run)
    assert zap._docker_resources() == (0, 0)


def test_headers_become_replacer_rules(docker):
    _run(docker, cfg=Config(headers={"X-Api-Key": "k123", "X-Tenant": "acme"}))
    z = docker.opt("-z")
    assert docker.cmd[-2] == "-z"
    tokens = shlex.split(z)[6:]  # zap_common.add_zap_options uses shlex.split; first 3 options are scanner.*
    pairs = dict(t.split("=", 1) for t in tokens if t != "-config")
    assert tokens.count("-config") == 12
    assert pairs == {
        "replacer.full_list(0).description": "h0", "replacer.full_list(0).enabled": "true",
        "replacer.full_list(0).matchtype": "REQ_HEADER", "replacer.full_list(0).matchstr": "X-Api-Key",
        "replacer.full_list(0).regex": "false", "replacer.full_list(0).replacement": "k123",
        "replacer.full_list(1).description": "h1", "replacer.full_list(1).enabled": "true",
        "replacer.full_list(1).matchtype": "REQ_HEADER", "replacer.full_list(1).matchstr": "X-Tenant",
        "replacer.full_list(1).regex": "false", "replacer.full_list(1).replacement": "acme"}


def test_header_value_with_space_survives_zap_option_parsing(docker):
    _run(docker, cfg=Config(headers={"Authorization": "Bearer abc.def"}))
    assert "replacer.full_list(0).replacement=Bearer abc.def" in shlex.split(docker.opt("-z"))


class FakeProvider:
    def __init__(self, token="tok", fail=False):
        self.token, self.fail, self.asked = token, fail, []

    def ensure_valid_for(self, seconds):
        self.asked.append(seconds)
        if self.fail:
            raise zap.LoginError("user A: login failed with HTTP 500.")

    def headers(self):
        return {"Authorization": f"Bearer-{self.token}"}


def test_login_token_is_passed_and_zap_api_published_locally(docker):
    got, prov = [], FakeProvider()
    _run(docker, cfg=Config(auth_a=prov, headers={"X-A": "1"}, on_progress=got.append))
    z = shlex.split(docker.opt("-z"))
    assert "replacer.full_list(0).matchstr=X-A" in z and "replacer.full_list(1).matchstr=Authorization" in z
    assert "replacer.full_list(1).replacement=Bearer-tok" in z
    host, port, inner = docker.opt("-p").split(":")
    assert host == "127.0.0.1" and int(port) > 0 and inner == str(zap.ZAP_PORT)
    assert docker.cmd.index("-p") < docker.cmd.index("ghcr.io/zaproxy/zaproxy:stable")
    assert docker.opt("-P") == str(zap.ZAP_PORT)
    assert not [g for g in got if g["level"] == "warn"]


def test_zap_api_is_published_locally_without_login_too(docker):
    _run(docker, cfg=Config(headers={"X-A": "1"}))  # for the partial reports
    assert docker.opt("-p").startswith("127.0.0.1:") and docker.opt("-P") == str(zap.ZAP_PORT)


@pytest.fixture
def zap_api():
    """A fake ZAP API on 127.0.0.1: records replacer calls."""
    calls = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            from urllib.parse import parse_qsl, urlsplit
            u = urlsplit(self.path)
            assert u.netloc == "zap"  # sent through ZAP as a proxy
            calls.append((u.path.rsplit("/", 2)[-2], dict(parse_qsl(u.query, keep_blank_values=True))))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"Result": "OK"}')

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield SimpleNamespace(port=srv.server_address[1], calls=calls)
    srv.shutdown()
    srv.server_close()


def _renewer(port, prov, headers=None, got=None):
    cfg = Config(auth_a=prov, headers=headers or {}, on_progress=(got if got is not None else []).append)
    return zap._TokenRenewer(cfg, port, zap.current_headers(cfg))


def test_renewer_swaps_the_rule_when_the_token_changes(zap_api):
    prov, got = FakeProvider("old"), []
    r = _renewer(zap_api.port, prov, {"X-A": "1"}, got)
    r.tick()
    assert zap_api.calls == [] and prov.asked == [zap.RENEW_AHEAD]  # same token: ZAP untouched
    prov.token, r.next_check = "new", 0
    r.tick()
    assert zap_api.calls == [
        ("addRule", {"description": "h1r1", "enabled": "true", "matchType": "REQ_HEADER", "matchRegex": "false",
                     "matchString": "Authorization", "replacement": "Bearer-new", "initiators": ""}),
        ("removeRule", {"description": "h1"})]
    assert got[-1]["msg"] == "Gave ZAP a renewed login token"
    prov.token, r.next_check = "newer", 0
    r.tick()
    assert zap_api.calls[2][1]["description"] == "h1r2" and zap_api.calls[3] == ("removeRule", {"description": "h1r1"})


def test_renewer_checks_at_most_every_interval(zap_api):
    prov = FakeProvider()
    r = _renewer(zap_api.port, prov)
    r.tick()
    r.tick()
    assert len(prov.asked) == 1


def test_renewer_retries_while_zap_api_is_down(zap_api):
    prov = FakeProvider("old")
    r = _renewer(zap._free_port(), prov)  # nothing listens there
    prov.token = "new"
    r.tick()
    assert r.sent["Authorization"] == "Bearer-old" and r.next_check <= time.time() + 2  # retries soon, not in 15 s
    r.proxy = f"http://127.0.0.1:{zap_api.port}"  # ZAP's API is up now
    r.next_check = 0
    r.tick()
    assert [c[0] for c in zap_api.calls] == ["addRule", "removeRule"] and r.stale == []


def test_renewer_login_failure_warns_once(zap_api):
    got, prov = [], FakeProvider(fail=True)
    r = _renewer(zap_api.port, FakeProvider(), got=got)
    r.cfg.auth_a = prov
    r.tick()
    r.next_check = 0
    r.tick()
    warn, = [g for g in got if g["level"] == "warn"]
    assert "Couldn't renew the token for ZAP" in warn["msg"] and "401" in warn["msg"]
    assert zap_api.calls == []


def test_progress_messages(docker):
    got = []
    docker.ticks = ["2026-10-02 10:35:35,757 Starting ZAP", "noise", "Active Scan progress %: 40"]
    _run(docker, cfg=Config(on_progress=got.append))
    assert [g["msg"] for g in got] == ["Starting the OWASP ZAP container (16 parallel requests)", "ZAP is starting up (usually 1–3 minutes)",
                                       "Active scan: attacking the APIs 40%"]


# ---------- cancel ----------

def test_cancel_removes_the_container_by_name(docker):
    docker.cancel_it = True
    with pytest.raises(Cancelled):
        _run(docker)
    name = docker.opt("--name")
    assert docker.rm == [["docker", "rm", "-f", name]]
    assert not (docker.out / "zap.log").exists()


def test_timeout_propagates(docker, monkeypatch):
    def boom(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, 3600)

    monkeypatch.setattr(zap, "run_cmd", boom)
    with pytest.raises(subprocess.TimeoutExpired):
        _run(docker)
    assert docker.rm and docker.rm[0][:3] == ["docker", "rm", "-f"]  # the container doesn't outlive the run


def test_cancel_keeps_the_alerts_found_so_far(docker):
    docker.cancel_it, docker.partial = True, {"site": [{"alerts": [_alert(risk="2")]}]}
    got = []
    res = _run(docker, cfg=Config(on_progress=got.append))
    assert res.status == "cancelled" and res.note.startswith("Stopped by user: partial results")
    assert [(f.severity, f.title) for f in res.findings] == [("medium", "X-Content-Type-Options Header Missing")]
    assert docker.saved == [(True, 0)] and len(docker.rm) == 1  # saved with HTML, before the container went
    assert "Saving what ZAP found so far" in [g["msg"] for g in got]
    assert not (docker.out / "zap.log").exists()


def test_timeout_keeps_the_alerts_found_so_far(docker, monkeypatch):
    def boom(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, 4800)

    monkeypatch.setattr(zap, "run_cmd", boom)
    docker.partial = {"site": [{"alerts": [_alert()]}]}
    res = _run(docker)
    assert res.status == "error" and res.note.startswith("Timed out after 80 min: partial results")
    assert len(res.findings) == 1 and len(docker.rm) == 1


def test_snapshot_saves_zap_reports_through_its_api(zap_api, tmp_path):
    s = zap._Snapshot(zap_api.port, tmp_path)
    s.tick()
    assert zap_api.calls == []  # not due yet
    s.next = 0
    s.tick()
    assert zap_api.calls[-1][0] == "jsonreport" and (tmp_path / "zap-partial.json").exists()
    assert s.next > time.time() + zap.SNAPSHOT_EVERY - 5
    s.save(html=True)
    assert [c[0] for c in zap_api.calls[-2:]] == ["jsonreport", "htmlreport"]
    assert (tmp_path / "zap-partial.html").exists() and not list(tmp_path.glob("*.tmp"))


def test_snapshot_is_best_effort_while_zap_is_down(tmp_path):
    zap._Snapshot(zap._free_port(), tmp_path).save(html=True)
    assert list(tmp_path.iterdir()) == []


# ---------- missing / broken report ----------

def test_missing_report_is_an_error_with_stderr_tail(docker):
    docker.report, docker.stdout, docker.stderr, docker.rc = None, "out text", "x" * 1000 + "ERROR Failed to start", 1
    res = _run(docker)
    assert res.status == "error" and len(res.note) == 600 and res.note.endswith("ERROR Failed to start")
    assert (docker.out / "zap.log").read_text(encoding="utf-8") == "out text\n" + docker.stderr


def test_missing_report_without_stderr_uses_stdout(docker):
    docker.report, docker.stdout = None, "Unable to find image 'x' locally"
    res = _run(docker)
    assert res.status == "error" and res.note == "Unable to find image 'x' locally"


@pytest.mark.parametrize("raw", ["", "{not json", "<html></html>"])
def test_broken_report_is_never_ok(docker, raw):
    docker.raw = raw
    try:
        res = _run(docker)
    except ValueError:
        return  # the runner turns a raised exception into status "error"
    assert res.status == "error"


@pytest.mark.parametrize("report", [{}, {"site": []}, {"site": [{"@name": "x"}]}, {"site": [{"alerts": []}]}])
def test_report_without_alerts_is_ok_and_empty(docker, report):
    docker.report = report
    res = _run(docker)
    assert (res.status, res.findings) == ("ok", [])


def test_non_zero_exit_with_report_still_parses(docker):
    docker.rc, docker.report = 2, {"site": [{"alerts": [_alert(risk="3")]}]}
    res = _run(docker)
    assert res.status == "ok" and [f.severity for f in res.findings] == ["high"]


# ---------- parsing ----------

@pytest.mark.parametrize("risk, sev", [("3", "high"), (3, "high"), ("2", "medium"), (2, "medium"), ("1", "low"),
                                       ("0", "info"), ("4", "info"), (None, "info"), ("high", "info")])
def test_risk_to_severity(docker, risk, sev):
    a = _alert(riskcode=risk)
    if risk is None:
        del a["riskcode"]
    docker.report = {"site": [{"alerts": [a]}]}
    assert [f.severity for f in _run(docker).findings] == [sev]


def test_alert_becomes_one_finding_per_alert(docker):
    two = [{"uri": "http://host.docker.internal:8000/items/7", "method": "GET"},
           {"uri": "http://host.docker.internal:8000/items", "method": "POST"}]
    docker.report = {"site": [{"alerts": [_alert("SQL Injection", "3", two, desc="d" * 1000)]},
                              {"alerts": [_alert()]}]}
    res = _run(docker)
    assert res.findings[0] == Finding("zap", "high", "SQL Injection", "GET http://host.docker.internal:8000/items/7",
                                      "2 instance(s). " + "d" * 300)
    assert res.findings[1] == Finding("zap", "low", "X-Content-Type-Options Header Missing",
                                      "GET http://host.docker.internal:8000/items",
                                      "1 instance(s). <p>The header is missing.</p>")
    assert len(res.findings) == 2


def test_alert_without_instances_or_name(docker):
    docker.report = {"site": [{"alerts": [{"riskcode": "2"}]}]}
    res = _run(docker)
    assert res.findings == [Finding("zap", "medium", "ZAP alert", "", "0 instance(s). ")]


def test_findings_map_to_operations_via_runner(docker):
    from sprat.runner import annotate
    docker.report = {"site": [{"alerts": [
        _alert("A", "2", [{"uri": "http://host.docker.internal:8000/items/42?x=1", "method": "GET"}]),
        _alert("B", "2", [{"uri": "http://host.docker.internal:8000/items", "method": "POST"}]),
        _alert("C", "2", [{"uri": "http://host.docker.internal:8000/robots.txt", "method": "GET"}])]}]}
    res = _run(docker)
    annotate(_spec(), "http://localhost:8000", [res])
    assert [f.operation for f in res.findings] == ["GET /items/{id}", "POST /items", ""]


# ---------- test log ----------

def _logged(docker, report, base="http://localhost:8000", **cfg_kw):
    tl = TestLog(docker.out.parent / "log" / "test-log.ndjson")
    docker.report = report
    res = zap.run(_spec(base=base), Config(testlog=tl, **cfg_kw), docker.out)
    return res, list(iter_entries(tl.path))


def test_each_instance_is_logged_with_its_operation(docker):
    inst = [{"uri": "http://host.docker.internal:8000/items/5", "method": "GET", "param": "id", "attack": "' OR 1=1",
             "evidence": "syntax error", "otherinfo": "o"},
            {"uri": "http://host.docker.internal:8000/items", "method": "post"}]
    docker.stderr = "2026 ... Total of 39 URLs\n"
    res, entries = _logged(docker, {"site": [{"alerts": [_alert("SQL Injection", "3", inst)]}]})
    a, b, summary = entries
    assert a["stage"] == "zap" and a["scenario"] == "Security check: SQL Injection"
    assert (a["operation"], b["operation"]) == ("GET /items/{id}", "POST /items")
    assert a["verdict"] == "fail" and a["expected"] == "Set the header."
    assert a["explanation"] == ("ZAP rated this high risk. The header is missing. Parameter: id. "
                                "Attack sent: ' OR 1=1.")
    assert b["explanation"] == "ZAP rated this high risk. The header is missing."
    assert a["request"]["method"] == "GET" and a["request"]["url"] == "http://host.docker.internal:8000/items/5"
    assert a["details"] == {"risk": "high", "confidence": "2", "param": "id", "attack": "' OR 1=1",
                            "evidence": "syntax error", "otherinfo": "o", "cwe": "693", "wasc": "15",
                            "description": "The header is missing.", "reference": "https://ref"}
    assert summary["scenario"] == "ZAP scan summary" and summary["verdict"] == "info"
    assert summary["details"]["message"].startswith("ZAP checked 39 URLs.")


def test_info_alert_is_logged_as_info_and_no_solution_means_no_issue(docker):
    _, entries = _logged(docker, {"site": [{"alerts": [_alert("Info", "0", solution="")]}]})
    assert entries[0]["verdict"] == "info" and entries[0]["expected"] == "No issue"


def test_long_texts_are_trimmed_in_the_log(docker):
    _, entries = _logged(docker, {"site": [{"alerts": [_alert(solution="s" * 900, desc="d" * 3000,
                                                              reference="r" * 900)]}]})
    e = entries[0]
    assert len(e["expected"]) == 400 and len(e["details"]["description"]) == 1500
    assert len(e["details"]["reference"]) == 600


def test_operation_matching_strips_the_base_path(docker):
    inst = [{"uri": "http://host.docker.internal:8000/api/v1/items/9", "method": "GET"}]
    _, entries = _logged(docker, {"site": [{"alerts": [_alert(instances=inst)]}]}, base="http://localhost:8000/api/v1")
    assert entries[0]["operation"] == "GET /items/{id}"


def test_summary_when_url_count_unknown_and_no_alerts(docker):
    res, entries = _logged(docker, {"site": []})
    e, = entries
    assert res.findings == [] and "an unknown number of URLs" in e["details"]["message"]


def test_summary_reads_url_count_from_stdout_too(docker):
    docker.stdout = "Total of 7 URLs"
    _, entries = _logged(docker, {"site": []})
    assert entries[0]["details"]["message"].startswith("ZAP checked 7 URLs.")


def test_header_secret_in_alert_url_is_masked_in_the_log(docker):
    inst = [{"uri": "http://host.docker.internal:8000/items?key=supersecret1", "method": "GET"}]
    tl = TestLog(docker.out.parent / "log" / "t.ndjson", secrets=["supersecret1"])
    docker.report = {"site": [{"alerts": [_alert(instances=inst)]}]}
    zap.run(_spec(), Config(testlog=tl, headers={"X-Key": "supersecret1"}), docker.out)
    assert "supersecret1" not in tl.path.read_text(encoding="utf-8")


def test_header_secret_in_alert_evidence_is_masked_in_the_log(docker):
    inst = [{"uri": "http://host.docker.internal:8000/items", "method": "GET", "evidence": "token=supersecret1",
             "otherinfo": "Authorization: Bearer supersecret1"}]
    tl = TestLog(docker.out.parent / "log" / "t.ndjson", secrets=["supersecret1"])
    docker.report = {"site": [{"alerts": [_alert(instances=inst)]}]}
    zap.run(_spec(), Config(testlog=tl, headers={"X-Key": "supersecret1"}), docker.out)
    assert "supersecret1" not in tl.path.read_text(encoding="utf-8")


# ---------- helpers ----------

@pytest.mark.parametrize("html, text", [
    ("<p>One</p><p>Two</p>", "One Two"),
    ("  a\n\n b\t c ", "a b c"),
    ("<a href='x'>link</a>", "link"),
    ("", ""),
    (None, ""),
    ("no tags", "no tags"),
])
def test_strip_html(html, text):
    assert zap._strip_html(html) == text


def _progress(lines):
    got = []
    zap._live(Config(on_progress=got.append), lines)
    return [(g["msg"], g["done"], g["total"]) for g in got]


@pytest.mark.parametrize("line, expected", [
    ("2026-10-02 10:35:35,757 Starting ZAP", ("ZAP is starting up (usually 1–3 minutes)", None, None)),
    ("Starting ZAP", ("ZAP is starting up (usually 1–3 minutes)", None, None)),
    ("2026-10-02 10:37:52,677 Set max pscan alerts", ("ZAP is up; importing the API definition", None, None)),
    ("Number of Imported URLs: 0", ("Imported 0 URLs from the spec", None, None)),
    ("Number of Imported URLs: 1234", ("Imported 1234 URLs from the spec", None, None)),
    ("Spider progress %: 0", ("Crawling 0%", 0, 100)),
    ("2026 DEBUG Spider progress %: 55", ("Crawling 55%", 55, 100)),
    ("Active Scan progress %: 0", ("Active scan: attacking the APIs 0%", 0, 100)),
    ("Active Scan progress %: 100", ("Active scan: attacking the APIs 100%", 100, 100)),
    ("Active Scan complete", ("Active scan complete 100%", 100, 100)),
    ("Records to scan...", ("Passive scan: analysing responses", None, None)),
    ("Passive scanning complete", ("Passive scan complete; writing the report", None, None)),
    ("Total of 39 URLs", ("Finished: 39 URLs checked", None, None)),
    ("\ufeffTotal of 1 URLs\r", ("Finished: 1 URLs checked", None, None)),
])
def test_live_line_variants(line, expected):
    assert _progress([line]) == [expected]


@pytest.mark.parametrize("line", [
    "", "   ", "Starting ZAPPER", "starting zap", "Starting new HTTP connection (1): localhost:43174",
    "Spider progress %: ", "Active Scan progress %: abc", "Number of Imported URLs:", "Total of URLs",
    "PASS: Vulnerable JS Library [10003]", "WARN-NEW: X-Content-Type-Options Header Missing [10021] x 3",
])
def test_live_ignores_other_lines(line):
    assert _progress([line]) == []


def test_live_one_event_per_line_first_pattern_wins():
    assert _progress(["Starting ZAP ... Total of 5 URLs"]) == [("ZAP is starting up (usually 1–3 minutes)", None, None)]


def test_live_keeps_order_and_handles_many_lines():
    lines = [f"Active Scan progress %: {i}" for i in range(0, 101, 10)]
    assert [d for _, d, _ in _progress(lines)] == list(range(0, 101, 10))
    assert _progress([]) == []


def test_live_without_listener_is_a_noop():
    zap._live(Config(), ["Starting ZAP", "Active Scan progress %: 5"])


def test_live_events_are_zap_stage_info_level():
    got = []
    zap._live(Config(on_progress=got.append), ["Spider progress %: 3"])
    assert got == [{"stage": "zap", "msg": "Crawling 3%", "op": "", "done": 3, "total": 100, "level": "info"}]


# ---------- real ZAP ----------

class _Api(http.server.BaseHTTPRequestHandler):
    seen_keys: list = []

    def do_GET(self):
        self.seen_keys.append(self.headers.get("X-Api-Key"))
        body = b'[{"id": 1}]' if self.path.startswith("/items") else b'{"detail": "not found"}'
        self.send_response(200 if self.path.startswith("/items") else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _zap_ready(image):
    if not shutil.which("docker"):
        pytest.skip("docker not installed")
    try:
        if subprocess.run(["docker", "info"], capture_output=True, timeout=120).returncode != 0:
            pytest.skip("docker daemon not running")
        if subprocess.run(["docker", "image", "inspect", image], capture_output=True, timeout=120).returncode != 0:
            pytest.skip(f"{image} not pulled locally (won't pull it in a test)")
    except subprocess.TimeoutExpired:
        pytest.skip("docker not responding")


@pytest.mark.external
@pytest.mark.slow
def test_real_zap_scan_of_a_tiny_local_api(tmp_path):
    cfg = Config(headers={"X-Api-Key": "k-123456"})
    _zap_ready(cfg.zap_image)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Api)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = f"http://localhost:{srv.server_address[1]}"
        raw = {"openapi": "3.0.3", "info": {"title": "t", "version": "1"}, "servers": [{"url": base}],
               "paths": {"/items": {"get": {"responses": {"200": {"description": "ok"}}}}}}
        spec = Spec(raw, base + "/openapi.json", "openapi3", base, [Operation("get", "/items", False, False)],
                    json.dumps(raw), json.dumps(raw))
        out = tmp_path / "out"
        out.mkdir()
        got = []
        cfg.on_progress, cfg.testlog = got.append, TestLog(tmp_path / "log" / "test-log.ndjson")
        res = zap.run(spec, cfg, out)
    finally:
        srv.shutdown()
    assert res.status == "ok", res.note
    assert (out / "zap.json").is_file() and (out / "zap.log").is_file() and (out / "zap.html").is_file()
    assert "Imported" in " ".join(g["msg"] for g in got)
    assert "k-123456" in _Api.seen_keys  # the replacer rule put our header on ZAP's requests
    assert all(f.severity in ("high", "medium", "low", "info") for f in res.findings)
    # the toy server sets no security headers, so ZAP's passive scan must flag it
    assert any(f.title == "X-Content-Type-Options Header Missing" and f.severity == "low" for f in res.findings)
    entries = list(iter_entries(cfg.testlog.path))
    assert entries[-1]["scenario"] == "ZAP scan summary"
    assert any(e["operation"] == "GET /items" for e in entries[:-1])
