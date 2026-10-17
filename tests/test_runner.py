"""runner.py: stage orchestration, cancellation, errors, reports, annotate() and failed().
Stage functions are stubbed, so nothing here touches the network, Node or Docker."""
import json
import threading
import time

import httpx
import pytest

from sprat import runner
from sprat.auth import LoginConfig, LoginError, TokenProvider
from sprat.config import ALL_STAGES, Config
from sprat.models import SEVERITIES, Finding, StageResult
from sprat.proc import Cancelled, progress
from sprat.runner import _template_regex, annotate, failed, run_pipeline
from sprat.spec import load_spec
from sprat.testlog import TestLog

DOC = {
    "openapi": "3.0.1", "info": {"title": "Shop", "version": "1"},
    "servers": [{"url": "https://shop.test/api"}],
    "paths": {
        "/": {"get": {"responses": {}}},
        "/items": {"get": {"responses": {}}, "post": {"responses": {}}},
        "/items/{id}": {"get": {"responses": {}}, "delete": {"responses": {}}},
        "/items/mine": {"get": {"responses": {}}},
        "/health": {"get": {"responses": {}}},
    },
}
LABELS = ["GET /", "GET /items", "POST /items", "GET /items/{id}", "DELETE /items/{id}", "GET /items/mine",
          "GET /health"]


@pytest.fixture
def spec_file(tmp_path):
    f = tmp_path / "spec.json"
    f.write_text(json.dumps(DOC), encoding="utf-8")
    return str(f)


@pytest.fixture
def calls(monkeypatch):
    """Replace every stage with a recording stub; tests override single stages with setitem."""
    seen = []

    def make(name):
        def stub(spec, cfg, out):
            seen.append((name, spec, cfg, out))
            return StageResult(name)
        return stub
    for name in ALL_STAGES:
        monkeypatch.setitem(runner.STAGE_FUNCS, name, make(name))
    return seen


def _cfg(tmp_path, spec_file, **kw):
    kw.setdefault("out_dir", str(tmp_path / "out"))
    return Config(spec=spec_file, **kw)


def _run(cfg):
    events = []
    return run_pipeline(cfg, events.append), events


# ---------- pipeline ----------

def test_stage_funcs_cover_all_stages():
    assert set(runner.STAGE_FUNCS) == set(ALL_STAGES)


def test_runs_all_stages_in_order_and_emits_events(tmp_path, spec_file, calls):
    cfg = _cfg(tmp_path, spec_file)
    results, events = _run(cfg)
    assert [r.name for r in results] == ALL_STAGES and all(r.status == "ok" for r in results)
    assert [c[0] for c in calls] == ALL_STAGES
    types = [e["type"] for e in events]
    assert types == ["spec_loading", "spec"] + ["stage_start", "stage_end"] * 5 + ["done"]
    assert events[0] == {"type": "spec_loading", "spec": spec_file}
    spec_ev = events[1]
    assert spec_ev["version"] == "openapi3" and spec_ev["operations"] == 7
    assert spec_ev["base_url"] == "https://shop.test/api" and spec_ev["labels"] == LABELS
    end = events[3]
    assert end["stage"] == "lint" and end["status"] == "ok" and end["findings"] == 0 and end["note"] == ""
    assert isinstance(end["duration"], float)
    assert events[-1]["report"].endswith("test-report.html")


def test_writes_every_report_file(tmp_path, spec_file, calls):
    out = tmp_path / "deep" / "nested" / "out"
    run_pipeline(_cfg(tmp_path, spec_file, out_dir=str(out)))
    for name in ("report.json", "report.html", "test-log.ndjson", "test-log.csv", "coverage.json",
                 "coverage.csv", "test-report.html"):
        assert (out / name).is_file(), name


def test_stage_gets_spec_cfg_and_out_dir(tmp_path, spec_file, calls):
    cfg = _cfg(tmp_path, spec_file, stages=["lint"])
    run_pipeline(cfg)
    name, spec, got_cfg, out = calls[0]
    assert got_cfg is cfg and out == tmp_path / "out" and not spec.filtered
    assert [o.label for o in spec.operations] == LABELS
    assert isinstance(cfg.testlog, TestLog)


def test_base_url_override(tmp_path, spec_file, calls):
    _, events = _run(_cfg(tmp_path, spec_file, base_url="http://other", stages=[]))
    assert events[1]["base_url"] == "http://other"
    assert json.loads((tmp_path / "out" / "report.json").read_text())["base_url"] == "http://other"


def test_only_selected_stages_run(tmp_path, spec_file, calls):
    results, _ = _run(_cfg(tmp_path, spec_file, stages=["types", "lint"]))
    assert [c[0] for c in calls] == ["types", "lint"] and [r.name for r in results] == ["types", "lint"]


def test_no_stages(tmp_path, spec_file, calls):
    results, events = _run(_cfg(tmp_path, spec_file, stages=[]))
    assert results == [] and calls == [] and events[-1]["type"] == "done"


def test_stage_exception_becomes_error_and_others_still_run(tmp_path, spec_file, calls, monkeypatch):
    def boom(spec, cfg, out):
        raise RuntimeError("kaput")
    monkeypatch.setitem(runner.STAGE_FUNCS, "conformance", boom)
    cfg = _cfg(tmp_path, spec_file, stages=["lint", "conformance", "types"])
    results, events = _run(cfg)
    assert [r.status for r in results] == ["ok", "error", "ok"]
    assert results[1].note == "RuntimeError: kaput" and results[1].duration >= 0
    assert [c[0] for c in calls] == ["lint", "types"]
    assert events[-1]["type"] == "done" and failed(cfg, results)
    stages = json.loads((tmp_path / "out" / "report.json").read_text())["stages"]
    assert stages[1]["status"] == "error"


def test_unknown_stage_name_is_reported_as_error(tmp_path, spec_file, calls):
    results, _ = _run(_cfg(tmp_path, spec_file, stages=["nope", "lint"]))
    assert results[0].status == "error" and results[0].note.startswith("KeyError")
    assert results[1].status == "ok"


def test_stage_findings_and_note_in_events(tmp_path, spec_file, calls, monkeypatch):
    monkeypatch.setitem(runner.STAGE_FUNCS, "lint", lambda s, c, o: StageResult(
        "lint", "skipped", "no node", [Finding("lint", "low", "a"), Finding("lint", "high", "b")]))
    _, events = _run(_cfg(tmp_path, spec_file, stages=["lint"]))
    end = [e for e in events if e["type"] == "stage_end"][0]
    assert (end["status"], end["findings"], end["note"]) == ("skipped", 2, "no node")


def test_duration_is_measured(tmp_path, spec_file, calls, monkeypatch):
    def slow(spec, cfg, out):
        time.sleep(0.05)
        return StageResult("lint", duration=999)
    monkeypatch.setitem(runner.STAGE_FUNCS, "lint", slow)
    results, _ = _run(_cfg(tmp_path, spec_file, stages=["lint"]))
    assert 0.04 <= results[0].duration < 5  # the runner overwrites whatever the stage set


def test_findings_are_annotated_with_operations(tmp_path, spec_file, calls, monkeypatch):
    monkeypatch.setitem(runner.STAGE_FUNCS, "zap", lambda s, c, o: StageResult(
        "zap", findings=[Finding("zap", "medium", "x", "GET https://shop.test/api/items/7")]))
    results, _ = _run(_cfg(tmp_path, spec_file, stages=["zap"]))
    assert results[0].findings[0].operation == "GET /items/{id}"
    rep = json.loads((tmp_path / "out" / "report.json").read_text())
    assert rep["stages"][0]["findings"][0]["operation"] == "GET /items/{id}"


# ---------- cancellation ----------

def test_cancel_before_start_runs_nothing(tmp_path, spec_file, calls):
    ev = threading.Event()
    ev.set()
    results, events = _run(_cfg(tmp_path, spec_file, cancel=ev, stages=["lint", "types"]))
    assert calls == [] and [r.status for r in results] == ["cancelled", "cancelled"]
    assert results[0].note == "Run stopped before this stage"
    assert [e["type"] for e in events if e["type"].startswith("stage")] == ["stage_end", "stage_end"]
    assert all(e["note"] == "not run" and e["duration"] == 0 for e in events if e["type"] == "stage_end")
    assert events[-1]["type"] == "cancelled" and events[-1]["report"].endswith("test-report.html")
    assert (tmp_path / "out" / "test-report.html").is_file()  # partial report still written


def test_cancelled_exception_stops_remaining_stages(tmp_path, spec_file, calls, monkeypatch):
    def stop(spec, cfg, out):
        raise Cancelled()
    monkeypatch.setitem(runner.STAGE_FUNCS, "conformance", stop)
    cfg = _cfg(tmp_path, spec_file, stages=["lint", "conformance", "types", "zap"])
    results, events = _run(cfg)
    assert [r.status for r in results] == ["ok", "cancelled", "cancelled", "cancelled"]
    assert results[1].note == "Stopped by user" and results[2].note == "Run stopped before this stage"
    assert [c[0] for c in calls] == ["lint"] and events[-1]["type"] == "cancelled"
    assert not failed(cfg, results)  # stopping isn't failing


def test_cancel_set_during_a_stage_skips_the_rest(tmp_path, spec_file, calls, monkeypatch):
    ev = threading.Event()

    def setter(spec, cfg, out):
        ev.set()
        return StageResult("lint", findings=[Finding("lint", "info", "x")])
    monkeypatch.setitem(runner.STAGE_FUNCS, "lint", setter)
    results, events = _run(_cfg(tmp_path, spec_file, cancel=ev, stages=["lint", "types"]))
    assert [r.status for r in results] == ["ok", "cancelled"] and len(results[0].findings) == 1
    assert events[-1]["type"] == "cancelled"


# ---------- operations / exclusions / spec errors ----------

def test_operations_filter(tmp_path, spec_file, calls):
    _, events = _run(_cfg(tmp_path, spec_file, stages=["lint"], operations=["get /health", "POST /items"]))
    spec = calls[0][1]
    assert spec.filtered and sorted(o.label for o in spec.operations) == ["GET /health", "POST /items"]
    assert events[1]["operations"] == 2


def test_operations_filter_unknown_op_raises(tmp_path, spec_file, calls):
    with pytest.raises(ValueError, match="not in the spec: GET /nope"):
        run_pipeline(_cfg(tmp_path, spec_file, operations=["GET /nope"]))


def test_exclude_paths_that_match_nothing_keep_spec_unfiltered(tmp_path, spec_file, calls):
    run_pipeline(_cfg(tmp_path, spec_file, stages=["lint"], exclude_paths=["^/nothing-here$"]))
    assert not calls[0][1].filtered and len(calls[0][1].operations) == 7


def test_exclude_paths_regexes_are_searched(tmp_path, spec_file, calls):
    run_pipeline(_cfg(tmp_path, spec_file, stages=["lint"], exclude_paths=["items", "^/$"]))
    assert [o.label for o in calls[0][1].operations] == ["GET /health"]
    cov = json.loads((tmp_path / "out" / "coverage.json").read_text())
    assert len(cov["apis"]) == 7  # coverage still lists excluded APIs


def test_exclude_paths_removing_everything_raises(tmp_path, spec_file, calls):
    with pytest.raises(ValueError, match="nothing to test"):
        run_pipeline(_cfg(tmp_path, spec_file, exclude_paths=[".*"]))
    assert calls == []


def test_missing_spec_file_raises(tmp_path, calls):
    with pytest.raises(FileNotFoundError):
        run_pipeline(_cfg(tmp_path, str(tmp_path / "missing.json")))


def test_not_a_spec_raises(tmp_path, calls):
    f = tmp_path / "x.json"
    f.write_text('{"hello": 1}')
    with pytest.raises(ValueError, match="Not a Swagger"):
        run_pipeline(_cfg(tmp_path, str(f)))


def test_testlog_masks_configured_secrets(tmp_path, spec_file, calls):
    cfg = _cfg(tmp_path, spec_file, stages=[], headers={"A": "Bearer aaaaaaaa"}, headers_b={"B": "bbbbbbbb"},
               variables={"PW": "pppppppp"})
    run_pipeline(cfg)
    assert {"Bearer aaaaaaaa", "bbbbbbbb", "pppppppp"} <= set(cfg.testlog.secrets)


# ---------- progress / login ----------

def test_progress_callback_receives_stage_messages(tmp_path, spec_file, calls, monkeypatch):
    got = []
    monkeypatch.setitem(runner.STAGE_FUNCS, "lint",
                        lambda s, c, o: (progress(c, "lint", "half way", done=1, total=2), StageResult("lint"))[1])
    run_pipeline(_cfg(tmp_path, spec_file, stages=["lint"], on_progress=got.append))
    assert got == [{"stage": "lint", "msg": "half way", "op": "", "done": 1, "total": 2, "level": "info"}]


@pytest.fixture
def login_api(monkeypatch):
    """Fake login API on http://auth.test/login; returns {"t": token} unless status is changed."""
    state = {"status": 200, "count": 0, "auth_seen": []}

    def handler(request):
        state["count"] += 1
        if state["status"] != 200:
            return httpx.Response(state["status"], json={"message": "Bad credentials"})
        return httpx.Response(200, json={"t": f"token-{state['count']}-xxxxxxxx"})
    real = httpx.Client

    def fake_client(*a, **kw):
        kw["transport"] = httpx.MockTransport(handler)
        return real(*a, **kw)
    monkeypatch.setattr(httpx, "Client", fake_client)
    return state


LOGIN = {"url": "http://auth.test/login", "body": '{"u": "qa"}', "token_path": "t", "expiry": "fixed",
         "fixed_minutes": 5}


def test_login_config_logs_in_once_and_reports_it(tmp_path, spec_file, calls, login_api):
    got = []
    cfg = _cfg(tmp_path, spec_file, stages=["authz"], login_a=LOGIN, on_progress=got.append)
    _, events = _run(cfg)
    assert login_api["count"] == 1 and cfg.auth_a.token == "token-1-xxxxxxxx" and cfg.auth_b is None
    assert {"type": "spec_loading", "spec": spec_file, "msg": "Logging in"} in events
    auth = [p for p in got if p["stage"] == "auth"]
    assert len(auth) == 1 and auth[0]["level"] == "ok"
    assert "Logged in as user A (login #1)" in auth[0]["msg"] and "fixed 5 min" in auth[0]["msg"]
    assert cfg.testlog.token_sources == [cfg.auth_a]  # so the login token is masked in the test log


def test_login_failure_raises_login_error(tmp_path, spec_file, calls, login_api):
    login_api["status"] = 401
    with pytest.raises(LoginError, match="user A: login failed with HTTP 401: Bad credentials"):
        run_pipeline(_cfg(tmp_path, spec_file, login_b=None, login_a=LOGIN))
    assert calls == []


def test_login_b_only(tmp_path, spec_file, calls, login_api):
    got = []
    cfg = _cfg(tmp_path, spec_file, stages=[], login_b=LOGIN, on_progress=got.append)
    run_pipeline(cfg)
    assert cfg.auth_a is None and cfg.auth_b.label == "user B"
    assert [p["msg"].split(" (")[0] for p in got] == ["Logged in as user B"]


def test_prelogged_provider_is_reported_once_and_not_logged_in_again(tmp_path, spec_file, calls, login_api):
    p = TokenProvider(LoginConfig.from_dict(LOGIN))
    p.current_token()
    got = []
    run_pipeline(_cfg(tmp_path, spec_file, stages=[], auth_a=p, on_progress=got.append))
    assert login_api["count"] == 1 and len([g for g in got if g["stage"] == "auth"]) == 1


def test_provider_with_more_logins_is_not_reported_again(tmp_path, spec_file, calls, login_api):
    p = TokenProvider(LoginConfig.from_dict(LOGIN))
    p.current_token()
    p.ensure_valid_for(10 ** 6)  # second login
    got = []
    run_pipeline(_cfg(tmp_path, spec_file, stages=[], auth_a=p, on_progress=got.append))
    assert p.logins == 2 and got == []


def test_preset_provider_logging_in_during_run_is_reported_once(tmp_path, spec_file, calls, login_api):
    p = TokenProvider(LoginConfig.from_dict(LOGIN))
    got = []
    run_pipeline(_cfg(tmp_path, spec_file, stages=[], auth_a=p, on_progress=got.append))
    assert login_api["count"] == 1
    assert len([g for g in got if g["stage"] == "auth"]) == 1


def test_login_token_is_sent_when_loading_spec(tmp_path, monkeypatch, calls):
    seen = []

    def handler(request):
        if request.url.path == "/login":
            return httpx.Response(200, json={"t": "tok-abcdefgh"})
        seen.append(request.headers.get("authorization"))
        return httpx.Response(200, json=DOC)
    real = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda *a, **kw: real(*a, **{**kw, "transport": httpx.MockTransport(handler)}))
    cfg = Config(spec="http://shop.test/openapi.json", out_dir=str(tmp_path / "o"), stages=[], login_a=LOGIN,
                 headers={"X-Static": "s"})
    run_pipeline(cfg)
    assert seen == ["Bearer tok-abcdefgh"]


# ---------- annotate ----------

@pytest.fixture
def spec(spec_file):
    return load_spec(spec_file)


@pytest.mark.parametrize("endpoint,expected", [
    ("GET /items/{id}", "GET /items/{id}"),
    ("get /items", "GET /items"),
    ("POST /items {'a': 1}", "POST /items"),
    ("GET https://shop.test/api/items/42", "GET /items/{id}"),
    ("GET https://shop.test/api/items/42/", "GET /items/{id}"),
    ("GET https://shop.test/api/items?page=2", "GET /items"),
    ("GET https://shop.test/api", "GET /"),
    ("GET https://shop.test/api/", "GET /"),
    ("DELETE /api/items/9?force=1", "DELETE /items/{id}"),
    ("DELETE /items/9", "DELETE /items/{id}"),
    ("POST https://shop.test/api/items/42", ""),     # method not defined for that path
    ("GET https://shop.test/api/items/1/extra", ""),
    ("PUT /items", ""),
    ("FETCH /items", ""),
    ("GET", ""),
    ("", ""),
    ("info", ""),
    ("paths//health/get", "GET /health"),
    ("paths//items/{id}/delete/responses/200", "DELETE /items/{id}"),
    ("paths//items/post", "POST /items"),
    ("paths//items", ""),
    ("paths//items/getter", ""),
    ("components/schemas/X", ""),
])
def test_annotate(spec, endpoint, expected):
    f = Finding("s", "low", "t", endpoint)
    annotate(spec, "https://shop.test/api", [StageResult("s", findings=[f])])
    assert f.operation == expected


def test_annotate_without_base_url(spec):
    fs = [Finding("zap", "low", "t", "GET http://h/items/5"), Finding("zap", "low", "t", "GET http://h/api/items/5")]
    annotate(spec, "", [StageResult("zap", findings=fs)])
    assert [f.operation for f in fs] == ["GET /items/{id}", ""]


def test_annotate_leaves_unmatched_operation_alone(spec):
    f = Finding("s", "low", "t", "nowhere", operation="GET /health")
    annotate(spec, "", [StageResult("s", findings=[f])])
    assert f.operation == "GET /health"


def test_annotate_handles_many_results_and_empty(spec):
    annotate(spec, "https://shop.test/api", [])
    rs = [StageResult("a", findings=[Finding("a", "low", "t", "GET /health")]), StageResult("b"),
          StageResult("c", findings=[Finding("c", "low", "t", "POST /items")])]
    annotate(spec, "https://shop.test/api", rs)
    assert [f.operation for r in rs for f in r.findings] == ["GET /health", "POST /items"]


def test_annotate_prefers_literal_path_over_template(spec):
    f = Finding("zap", "low", "t", "GET https://shop.test/api/items/mine")
    annotate(spec, "https://shop.test/api", [StageResult("zap", findings=[f])])
    assert f.operation == "GET /items/mine"


@pytest.mark.parametrize("template,path,match", [
    ("/items/{id}", "/items/1", True),
    ("/items/{id}", "/items/abc-def", True),
    ("/items/{id}", "/items/1/", True),
    ("/items/{id}", "/items/", False),
    ("/items/{id}", "/items/1/x", False),
    ("/items/{id}", "/items", False),
    ("/a/{x}/b/{y}", "/a/1/b/2", True),
    ("/a/{x}/b/{y}", "/a/1/c/2", False),
    ("/file.json", "/file.json", True),
    ("/file.json", "/fileXjson", False),   # dots are literal
    ("/v1/{id}.json", "/v1/7.json", True),
    ("/", "/", True),
    ("/", "/x", False),
    ("/a+b", "/a+b", True),
    ("/a+b", "/aab", False),
])
def test_template_regex(template, path, match):
    assert bool(_template_regex(template).match(path)) is match


# ---------- failed() ----------

def _res(*sevs, status="ok"):
    return StageResult("s", status, findings=[Finding("s", s, "t") for s in sevs])


@pytest.mark.parametrize("fail_on,sevs,expected", [
    ("high", [], False),
    ("high", ["info", "low", "medium"], False),
    ("high", ["high"], True),
    ("high", ["critical"], True),
    ("critical", ["high"], False),
    ("critical", ["critical"], True),
    ("medium", ["medium"], True),
    ("medium", ["low"], False),
    ("low", ["low"], True),
    ("info", ["info"], True),
    ("info", [], False),
    ("high", ["bogus"], False),   # unknown severity ranks as info
    ("info", ["bogus"], True),
    ("bogus", ["info"], True),    # unknown threshold is the strictest
])
def test_failed_threshold(fail_on, sevs, expected):
    assert failed(Config(fail_on=fail_on), [_res(*sevs)]) is expected


@pytest.mark.parametrize("fail_on", SEVERITIES)
def test_failed_on_error_stage_regardless_of_threshold(fail_on):
    assert failed(Config(fail_on=fail_on), [_res(), _res(status="error")])


@pytest.mark.parametrize("status", ["ok", "skipped", "cancelled"])
def test_failed_ignores_non_error_statuses(status):
    assert not failed(Config(), [_res(status=status)])


def test_failed_looks_across_all_stages():
    assert failed(Config(), [_res("low"), _res(), _res("info", "high")])
    assert not failed(Config(), [])
