"""cli.py and __main__.py: argument parsing, config merging, output and the exit-code policy.
Stages are stubbed and HTTP goes through httpx.MockTransport, so nothing leaves the process."""
import json
import os
import runpy
import subprocess
import sys
import warnings

import httpx
import pytest

from sprat import cli, runner
from sprat.config import ALL_STAGES
from sprat.models import SEVERITIES, Finding, StageResult

DOC = {
    "openapi": "3.0.1", "info": {"title": "Shop", "version": "2.1"},
    "servers": [{"url": "https://shop.test/api"}],
    "components": {"securitySchemes": {"b": {"type": "http", "scheme": "bearer"}}},
    "paths": {
        "/items": {"get": {"responses": {}}, "post": {"security": [{"b": []}], "responses": {}}},
        "/items/{id}": {"delete": {"responses": {}}},
    },
}


@pytest.fixture(autouse=True)
def _cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # a forgotten --out must never write into the repo


@pytest.fixture
def spec_file(tmp_path):
    f = tmp_path / "spec.json"
    f.write_text(json.dumps(DOC), encoding="utf-8")
    return str(f)


@pytest.fixture
def out(tmp_path):
    return str(tmp_path / "out")


@pytest.fixture
def stages(monkeypatch):
    """Stub every stage. Set findings[name] = [severities] or errors.add(name) to shape results."""
    state = {"findings": {}, "errors": set(), "ran": [], "cfg": None}

    def make(name):
        def stub(spec, cfg, out):
            state["ran"].append(name)
            state["cfg"] = cfg
            if name in state["errors"]:
                raise RuntimeError(f"{name} broke")
            return StageResult(name, findings=[Finding(name, s, f"{s} thing", "GET /items")
                                               for s in state["findings"].get(name, [])])
        return stub
    for n in ALL_STAGES:
        monkeypatch.setitem(runner.STAGE_FUNCS, n, make(n))  # same dict object cli imported
    return state


@pytest.fixture
def captured(monkeypatch):
    """Replace run_pipeline to capture the merged Config without running anything."""
    got = {}

    def fake(cfg, emit):
        got["cfg"] = cfg
        got["emit"] = emit
        return []
    monkeypatch.setattr(cli, "run_pipeline", fake)
    return got


def _mock_http(monkeypatch, handler):
    real = httpx.Client

    def fake_client(*a, **kw):
        kw["transport"] = httpx.MockTransport(handler)
        return real(*a, **kw)
    monkeypatch.setattr(httpx, "Client", fake_client)


# ---------- parser / help ----------

def test_top_level_help(capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["--help"])
    assert e.value.code == 0
    text = capsys.readouterr().out
    assert "usage: sprat" in text and all(c in text for c in ("run", "discover", "ui"))


@pytest.mark.parametrize("cmd,options", [
    ("run", ["--config", "--base-url", "-H", "--header", "--header-b", "--stages", "--max-examples", "--fail-on",
             "--out", "--no-mutating-authz", "--op", "spec"]),
    ("discover", ["url", "-H", "--header"]),
    ("ui", ["--host", "--port", "--data-dir"]),
])
def test_subcommand_help_lists_options(capsys, cmd, options):
    with pytest.raises(SystemExit) as e:
        cli.main([cmd, "--help"])
    assert e.value.code == 0
    text = capsys.readouterr().out
    for o in options:
        assert o in text, o


def test_run_help_lists_stages_and_severities(capsys):
    with pytest.raises(SystemExit):
        cli.main(["run", "--help"])
    text = capsys.readouterr().out
    assert ",".join(ALL_STAGES) in text and all(s in text for s in SEVERITIES)


@pytest.mark.parametrize("argv,msg", [
    ([], "required"),
    (["bogus"], "invalid choice"),
    (["run", "s", "--fail-on", "severe"], "invalid choice"),
    (["run", "s", "--fail-on"], "expected one argument"),
    (["run", "s", "--max-examples", "ten"], "invalid int"),
    (["run", "s", "--frobnicate"], "unrecognized arguments"),
    (["run", "a", "b"], "unrecognized arguments"),
    (["discover"], "required"),
    (["ui", "--port", "http"], "invalid int"),
    (["run", "s", "-H"], "expected one argument"),
])
def test_bad_arguments_exit_2(capsys, argv, msg):
    with pytest.raises(SystemExit) as e:
        cli.main(argv)
    assert e.value.code == 2 and msg in capsys.readouterr().err


def test_parser_defaults():
    p = cli.build_parser()
    r = p.parse_args(["run"])
    assert r.spec is None and r.header == [] and r.header_b == [] and r.op == [] and not r.no_mutating_authz
    assert r.config is r.stages is r.fail_on is r.out is r.max_examples is r.base_url is None
    u = p.parse_args(["ui"])
    assert (u.host, u.port, u.data_dir) == ("127.0.0.1", 8787, "reports")
    d = p.parse_args(["discover", "http://x", "-H", "A: 1", "--header", "B: 2"])
    assert d.url == "http://x" and d.header == ["A: 1", "B: 2"]


def test_repeatable_options_accumulate():
    a = cli.build_parser().parse_args(["run", "s", "-H", "A: 1", "--header", "B: 2", "--header-b", "C: 3",
                                       "--op", "GET /a", "--op", "POST /b"])
    assert a.header == ["A: 1", "B: 2"] and a.header_b == ["C: 3"] and a.op == ["GET /a", "POST /b"]


# ---------- ui ----------

def test_ui_calls_serve_with_defaults(monkeypatch):
    import sprat.web.app as web
    got = []
    monkeypatch.setattr(web, "serve", lambda *a: got.append(a))
    assert cli.main(["ui"]) == 0
    assert got == [("127.0.0.1", 8787, "reports")]


def test_ui_calls_serve_with_options(monkeypatch, tmp_path):
    import sprat.web.app as web
    got = []
    monkeypatch.setattr(web, "serve", lambda *a: got.append(a))
    assert cli.main(["ui", "--host", "0.0.0.0", "--port", "9001", "--data-dir", str(tmp_path / "d")]) == 0
    assert got == [("0.0.0.0", 9001, str(tmp_path / "d"))]


# ---------- run: argument -> Config merging ----------

def test_run_without_spec_exits_2(capsys, captured):
    assert cli.main(["run"]) == 2
    assert "error: no spec given" in capsys.readouterr().err and "cfg" not in captured


def test_run_with_empty_config_and_no_spec_exits_2(tmp_path, capsys, captured):
    c = tmp_path / "c.yaml"
    c.write_text("max_examples: 3\n")
    assert cli.main(["run", "--config", str(c)]) == 2
    assert "no spec given" in capsys.readouterr().err


@pytest.mark.parametrize("stages_arg,bad", [("lint,nope", "['nope']"), ("LINT", "['LINT']"), ("lint,", "['']"),
                                            ("zap,dast,fuzz", "['dast', 'fuzz']")])
def test_run_unknown_stage_exits_2(capsys, captured, stages_arg, bad):
    assert cli.main(["run", "s.json", "--stages", stages_arg]) == 2
    assert f"error: unknown stage(s): {bad}" in capsys.readouterr().err and "cfg" not in captured


def test_unknown_stage_in_config_exits_2(tmp_path, capsys, captured):
    c = tmp_path / "c.yaml"
    c.write_text("spec: s.json\nstages: [lint, bogus]\n")
    assert cli.main(["run", "--config", str(c)]) == 2
    assert "bogus" in capsys.readouterr().err


def test_run_defaults_without_config(captured):
    assert cli.main(["run", "s.json"]) == 0
    c = captured["cfg"]
    assert c.spec == "s.json" and c.stages == ALL_STAGES and c.fail_on == "high" and c.out_dir == "reports"
    assert c.headers == {} and c.headers_b == {} and c.operations == [] and c.max_examples == 50
    assert captured["emit"] is cli._print_event and callable(c.on_progress)


def test_every_option_reaches_config(captured, monkeypatch, out):
    monkeypatch.setenv("SPRAT_CLI_TOK", "from-env")
    assert cli.main(["run", "s.json", "--base-url", "http://b", "-H", "Authorization: Bearer ${SPRAT_CLI_TOK}",
                     "-H", "X-Url: http://h:1/p", "--header-b", "Authorization:  Bearer b:c ",
                     "--stages", " lint , types ", "--max-examples", "9", "--fail-on", "low", "--out", out,
                     "--no-mutating-authz", "--op", "GET /items", "--op", "post /items"]) == 0
    c = captured["cfg"]
    assert c.base_url == "http://b" and c.max_examples == 9 and c.fail_on == "low" and c.out_dir == out
    assert c.headers == {"Authorization": "Bearer from-env", "X-Url": "http://h:1/p"}
    assert c.headers_b == {"Authorization": "Bearer b:c"}
    assert c.stages == ["lint", "types"] and c.no_mutating_authz is True
    assert c.operations == ["GET /items", "post /items"]


def test_config_file_is_used_and_cli_overrides_it(tmp_path, captured, monkeypatch):
    monkeypatch.setenv("SPRAT_CFG_TOK", "cfg-tok")
    c = tmp_path / "c.yaml"
    c.write_text("spec: from-config.json\nbase_url: http://cfg\nheaders: {Authorization: 'Bearer ${SPRAT_CFG_TOK}', "
                 "X-Keep: k}\nheaders_b: {B: b}\nstages: [lint]\nmax_examples: 3\nfail_on: critical\n"
                 "out_dir: cfg-out\noperations: ['GET /a']\nno_mutating_authz: true\n", encoding="utf-8")
    assert cli.main(["run", "--config", str(c)]) == 0
    cfg = captured["cfg"]
    assert cfg.spec == "from-config.json" and cfg.headers == {"Authorization": "Bearer cfg-tok", "X-Keep": "k"}
    assert (cfg.stages, cfg.max_examples, cfg.fail_on, cfg.out_dir) == (["lint"], 3, "critical", "cfg-out")
    assert cli.main(["run", "cli.json", "--config", str(c), "-H", "Authorization: cli", "--header-b", "C: c",
                     "--stages", "types", "--max-examples", "5", "--fail-on", "info", "--out", "o",
                     "--base-url", "http://cli", "--op", "GET /b"]) == 0
    cfg = captured["cfg"]
    assert cfg.spec == "cli.json" and cfg.base_url == "http://cli"
    assert cfg.headers == {"Authorization": "cli", "X-Keep": "k"} and cfg.headers_b == {"B": "b", "C": "c"}
    assert (cfg.stages, cfg.max_examples, cfg.fail_on, cfg.out_dir) == (["types"], 5, "info", "o")
    assert cfg.operations == ["GET /b"] and cfg.no_mutating_authz is True  # flag can't be turned off from the CLI


def test_on_progress_prints_only_auth_messages(captured, capsys):
    cli.main(["run", "s.json"])
    capsys.readouterr()
    cb = captured["cfg"].on_progress
    cb({"stage": "auth", "msg": "Logged in as user A"})
    cb({"stage": "lint", "msg": "linting"})
    assert capsys.readouterr().out == "  Logged in as user A\n"


# ---------- _print_event ----------

@pytest.mark.parametrize("event,expected", [
    ({"type": "spec_loading", "spec": "s.json"}, "Loading spec: s.json\n"),
    ({"type": "spec_loading", "spec": "s.json", "msg": "Logging in"}, "Logging in...\n"),
    ({"type": "spec_loading", "spec": "s.json", "msg": ""}, "Loading spec: s.json\n"),
    ({"type": "spec", "version": "openapi3", "operations": 3, "base_url": "http://b"},
     "  openapi3, 3 operations, base URL: http://b\n"),
    ({"type": "spec", "version": "swagger2", "operations": 0, "base_url": ""},
     "  swagger2, 0 operations, base URL: (none)\n"),
    ({"type": "stage_start", "stage": "lint"}, "[lint] running...\n"),
    ({"type": "stage_end", "stage": "zap", "status": "skipped", "findings": 0, "note": "no docker"},
     "[zap] skipped: 0 finding(s) no docker\n"),
    ({"type": "done", "report": "r/test-report.html"}, "Report: r/test-report.html\n"),
    ({"type": "cancelled", "report": "r"}, ""),
    ({"type": "whatever"}, ""),
])
def test_print_event(capsys, event, expected):
    cli._print_event(event)
    assert capsys.readouterr().out == expected


# ---------- run: end to end with stubbed stages ----------

def test_run_end_to_end_output_and_files(spec_file, out, stages, capsys, tmp_path):
    stages["findings"]["lint"] = ["low", "medium"]
    assert cli.main(["run", spec_file, "--out", out]) == 0
    text = capsys.readouterr().out
    assert f"Loading spec: {spec_file}" in text
    assert "  openapi3, 3 operations, base URL: https://shop.test/api" in text
    assert "[lint] running..." in text and "[lint] ok: 2 finding(s)" in text
    assert text.strip().splitlines()[-1] == f"Report: {os.path.join(out, 'test-report.html')}"
    assert stages["ran"] == ALL_STAGES
    for name in ("report.json", "report.html", "test-report.html", "coverage.json", "test-log.csv"):
        assert (tmp_path / "out" / name).is_file()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["out", "spec.json"]  # nothing written elsewhere


@pytest.mark.parametrize("fail_on,sev,code", [
    (None, "medium", 0), (None, "high", 1), (None, "critical", 1),
    ("critical", "high", 0), ("critical", "critical", 1),
    ("medium", "medium", 1), ("medium", "low", 0),
    ("low", "low", 1), ("info", "info", 1), ("info", None, 0), (None, None, 0),
])
def test_exit_code_follows_fail_on(spec_file, out, stages, fail_on, sev, code):
    if sev:
        stages["findings"]["types"] = ["info", sev]
    argv = ["run", spec_file, "--out", out, "--stages", "lint,types"]
    if fail_on:
        argv += ["--fail-on", fail_on]
    assert cli.main(argv) == code


def test_fail_on_from_config(tmp_path, spec_file, out, stages):
    c = tmp_path / "c.yaml"
    c.write_text("fail_on: low\n")
    stages["findings"]["lint"] = ["low"]
    assert cli.main(["run", spec_file, "--config", str(c), "--out", out, "--stages", "lint"]) == 1
    assert cli.main(["run", spec_file, "--config", str(c), "--out", out, "--stages", "lint",
                     "--fail-on", "high"]) == 0


def test_stage_error_exits_1_even_without_findings(spec_file, out, stages, capsys):
    stages["errors"].add("authz")
    assert cli.main(["run", spec_file, "--out", out, "--stages", "lint,authz,zap", "--fail-on", "critical"]) == 1
    text = capsys.readouterr().out
    assert "[authz] error: 0 finding(s) RuntimeError: authz broke" in text
    assert stages["ran"] == ["lint", "authz", "zap"]


def test_base_url_none_for_relative_server_in_local_file(tmp_path, out, stages, capsys):
    f = tmp_path / "rel.json"
    f.write_text(json.dumps({**DOC, "servers": [{"url": "/api"}]}))
    assert cli.main(["run", str(f), "--out", out, "--stages", "lint"]) == 0
    assert "base URL: (none)" in capsys.readouterr().out
    assert cli.main(["run", str(f), "--out", out, "--stages", "lint", "--base-url", "http://given"]) == 0
    assert "base URL: http://given" in capsys.readouterr().out


def test_op_filter_end_to_end(spec_file, out, stages, capsys):
    assert cli.main(["run", spec_file, "--out", out, "--stages", "lint", "--op", "DELETE /items/{id}"]) == 0
    assert "1 operations" in capsys.readouterr().out
    assert stages["cfg"].operations == ["DELETE /items/{id}"]


def test_headers_reach_stages(spec_file, out, stages, monkeypatch):
    monkeypatch.setenv("SPRAT_E2E_TOK", "tok-123456")
    cli.main(["run", spec_file, "--out", out, "--stages", "authz", "-H", "Authorization: Bearer ${SPRAT_E2E_TOK}",
              "--header-b", "Authorization: Bearer other", "--no-mutating-authz"])
    cfg = stages["cfg"]
    assert cfg.headers == {"Authorization": "Bearer tok-123456"} and cfg.headers_b == {"Authorization": "Bearer other"}
    assert cfg.no_mutating_authz


# ---------- run: automatic login ----------

def _login_config(tmp_path, spec_file):
    c = tmp_path / "login.yaml"
    c.write_text(f"spec: {json.dumps(spec_file)}\nlogin_a:\n  url: http://auth.test/login\n  body: '{{\"u\": \"qa\"}}'\n"
                 "  token_path: t\n  expiry: fixed\n", encoding="utf-8")
    return str(c)


def test_login_success_prints_progress(tmp_path, spec_file, out, stages, monkeypatch, capsys):
    _mock_http(monkeypatch, lambda r: httpx.Response(200, json={"t": "tok-abcdefgh"}))
    assert cli.main(["run", "--config", _login_config(tmp_path, spec_file), "--out", out, "--stages", "lint"]) == 0
    text = capsys.readouterr().out
    assert "Logging in..." in text and "  Logged in as user A (login #1)" in text
    assert stages["cfg"].auth_a.token == "tok-abcdefgh"


def test_login_failure_exits_2(tmp_path, spec_file, out, stages, monkeypatch, capsys):
    _mock_http(monkeypatch, lambda r: httpx.Response(401, json={"message": "Invalid password"}))
    assert cli.main(["run", "--config", _login_config(tmp_path, spec_file), "--out", out]) == 2
    err = capsys.readouterr().err
    assert err.startswith("error: user A: login failed with HTTP 401: Invalid password")
    assert stages["ran"] == []


def test_login_unreachable_exits_2(tmp_path, spec_file, out, stages, monkeypatch, capsys):
    def down(r):
        raise httpx.ConnectError("refused")
    _mock_http(monkeypatch, down)
    assert cli.main(["run", "--config", _login_config(tmp_path, spec_file), "--out", out]) == 2
    assert "couldn't reach the login API" in capsys.readouterr().err


# ---------- run: user errors that currently escape as tracebacks ----------

@pytest.mark.parametrize("extra", [
    ["-H", "NoColonHere"],
    ["--header-b", "X: ${SPRAT_DEFINITELY_UNSET}"],
    ["--op", "GET /not-in-spec"],
    ["--config", "BADCONFIG"],
    ["MISSINGSPEC"],
], ids=["bad-header", "unset-var", "unknown-op", "unknown-config-key", "missing-spec-file"])
def test_user_errors_exit_2_with_message(tmp_path, spec_file, out, stages, capsys, monkeypatch, extra):
    monkeypatch.delenv("SPRAT_DEFINITELY_UNSET", raising=False)
    bad_cfg = tmp_path / "bad.yaml"
    bad_cfg.write_text("nonsense_key: 1\n")
    extra = [str(bad_cfg) if a == "BADCONFIG" else str(tmp_path / "nope.json") if a == "MISSINGSPEC" else a
             for a in extra]
    argv = ["run"] + ([] if extra == [str(tmp_path / "nope.json")] else [spec_file]) + ["--out", out] + extra
    assert cli.main(argv) == 2
    assert capsys.readouterr().err.startswith("error: ")


# ---------- discover ----------

def test_discover_lists_specs_and_operations(monkeypatch, capsys):
    seen = []

    def handler(r):
        seen.append(r.headers.get("x-key"))
        return httpx.Response(200, json=DOC) if r.url.path == "/openapi.json" else httpx.Response(404)
    _mock_http(monkeypatch, handler)
    assert cli.main(["discover", "http://app.test/openapi.json", "-H", "X-Key: k:1"]) == 0
    text = capsys.readouterr().out
    assert "Shop 2.1  [openapi3]  http://app.test/openapi.json" in text and "embedded" not in text
    lines = [l.split() for l in text.splitlines() if l.startswith("  ")]
    assert lines == [["GET", "/items"], ["POST", "/items", "[secured]"], ["DELETE", "/items/{id}"]]
    assert set(seen) == {"k:1"}


def test_discover_embedded_and_untitled(monkeypatch, spec_file, capsys):
    import sprat.discover as disc
    got = {}

    def fake(url, headers):
        got["args"] = (url, headers)
        return {"specs": [{"title": "", "api_version": "1", "spec_version": "swagger2", "url": spec_file,
                           "embedded": True}], "tried": 1, "errors": 0, "error": ""}
    monkeypatch.setattr(disc, "discover", fake)
    assert cli.main(["discover", "http://ui.test/docs", "-H", " A :  b "]) == 0
    text = capsys.readouterr().out
    assert "(untitled) 1  [swagger2]" in text and "(embedded in Swagger UI page)" in text
    assert got["args"] == ("http://ui.test/docs", {"A": "b"})


def test_discover_nothing_found_exits_1(monkeypatch, capsys):
    _mock_http(monkeypatch, lambda r: httpx.Response(404))
    assert cli.main(["discover", "http://app.test"]) == 1
    text = capsys.readouterr().out
    assert "No Swagger/OpenAPI document found" in text and "Pass the spec URL directly" in text


def test_discover_connection_refused_exits_1(monkeypatch, capsys):
    def down(r):
        raise httpx.ConnectError("refused")
    _mock_http(monkeypatch, down)
    assert cli.main(["discover", "app.test"]) == 1
    assert "Couldn't connect to the server" in capsys.readouterr().out


def test_discover_bad_header_raises(monkeypatch):
    with pytest.raises(ValueError, match="Name: value"):
        cli.main(["discover", "http://app.test", "-H", "nocolon"])


def test_discover_expands_env_in_headers(monkeypatch, capsys):
    monkeypatch.setenv("SPRAT_DISC_TOK", "secret-tok")
    seen = []

    def handler(r):
        seen.append(r.headers.get("authorization"))
        return httpx.Response(200, json=DOC)
    _mock_http(monkeypatch, handler)
    assert cli.main(["discover", "http://app.test/openapi.json", "-H", "Authorization: Bearer ${SPRAT_DISC_TOK}"]) == 0
    assert set(seen) == {"Bearer secret-tok"}


# ---------- entry points ----------

def _run_module(name, argv, monkeypatch):
    monkeypatch.setattr(sys, "argv", argv)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)  # "found in sys.modules" from runpy
        with pytest.raises(SystemExit) as e:
            runpy.run_module(name, run_name="__main__")
    return e.value.code


def test_cli_module_as_main(monkeypatch, capsys):
    assert _run_module("sprat.cli", ["sprat", "run"], monkeypatch) == 2
    assert "no spec given" in capsys.readouterr().err


def test_package_main(monkeypatch, capsys):
    assert _run_module("sprat", ["sprat", "--help"], monkeypatch) == 0
    assert "discover" in capsys.readouterr().out


@pytest.mark.slow
def test_python_dash_m_sprat(tmp_path):
    env = {**os.environ, "PYTHONPATH": os.path.dirname(os.path.dirname(os.path.abspath(cli.__file__)))}
    p = subprocess.run([sys.executable, "-m", "sprat", "run"], cwd=tmp_path, capture_output=True, text=True,
                       timeout=120, env=env)
    assert p.returncode == 2 and "error: no spec given" in p.stderr
    p = subprocess.run([sys.executable, "-m", "sprat", "run", "--help"], cwd=tmp_path, capture_output=True,
                       text=True, timeout=120, env=env)
    assert p.returncode == 0 and "--fail-on" in p.stdout
    assert list(tmp_path.iterdir()) == []
