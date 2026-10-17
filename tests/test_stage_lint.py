"""Spectral lint stage: tool lookup, command line, output parsing, filtering and the test log.

The subprocess layer is faked (lint.run_cmd); the `external` tests run the real Spectral via npx.
"""
import functools
import json
import os
import shutil
import subprocess
import threading

import pytest

from sprat.config import Config
from sprat.models import Finding
from sprat.proc import Cancelled, Result
from sprat.spec import Operation, Spec
from sprat.stages import lint
from sprat.testlog import TestLog, iter_entries

NPX = r"C:\nodejs\npx.cmd"
SPEC_JSON = '{"openapi": "3.0.3", "info": {"title": "t", "version": "1"}, "paths": {}}'
SPEC_YAML = "openapi: 3.0.3\ninfo: {title: t, version: '1'}\npaths: {}\n"


def _ops():
    return [Operation("get", "/items", False, False), Operation("post", "/items", False, True),
            Operation("get", "/users/{id}", False, False), Operation("delete", "/users/{id}", False, False)]


def _spec(text=SPEC_JSON, full_text="", ops=None, filtered=False):
    return Spec({}, "http://x/openapi.json", "openapi3", "http://localhost:8000",
                _ops() if ops is None else ops, text, full_text, filtered)


def _item(code="rule", path=(), severity=1, message="msg", line=None):
    it = {"code": code, "path": list(path), "message": message, "severity": severity}
    if line is not None:
        it["range"] = {"start": {"line": line, "character": 0}, "end": {"line": line, "character": 5}}
    return it


class FakeTool:
    def __init__(self):
        self.calls, self.result, self.exc = [], Result(0, "[]", ""), None

    def output(self, items=None, stdout=None, stderr="", rc=0):
        self.result = Result(rc, json.dumps(items) if stdout is None else stdout, stderr)

    def __call__(self, cmd, **kw):
        self.calls.append((cmd, kw))
        if self.exc:
            raise self.exc
        return self.result


@pytest.fixture
def tool(monkeypatch):
    t = FakeTool()
    monkeypatch.setattr(lint.shutil, "which", lambda name: NPX if name == "npx" else None)
    monkeypatch.setattr(lint, "run_cmd", t)
    monkeypatch.setattr(lint, "ca_bundle", lambda: r"C:\ca\bundle.pem")
    return t


def _run(tmp_path, spec=None, items=None, tool=None, cfg=None, **out):
    if tool is not None and (items is not None or out):
        tool.output(items, **out)
    return lint.run(spec or _spec(), cfg or Config(), tmp_path)


def _log(tmp_path):
    return TestLog(tmp_path / "log" / "test-log.ndjson")


# ---------- tool lookup ----------

def test_missing_npx_is_skipped_not_passed(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(lint.shutil, "which", lambda name: None)
    monkeypatch.setattr(lint, "run_cmd", lambda *a, **k: called.append(a))
    res = lint.run(_spec(), Config(), tmp_path)
    assert res.status == "skipped" and res.name == "lint"
    assert "npx not found" in res.note and "Node.js" in res.note
    assert res.findings == [] and called == [] and list(tmp_path.iterdir()) == []


def test_looks_up_npx_on_path(tmp_path, tool, monkeypatch):
    asked = []
    monkeypatch.setattr(lint.shutil, "which", lambda name: asked.append(name) or NPX)
    _run(tmp_path, tool=tool)
    assert asked == ["npx"] and tool.calls[0][0][0] == NPX


# ---------- command line and files ----------

def test_command_line(tmp_path, tool):
    cfg = Config(cancel=threading.Event())
    lint.run(_spec(), cfg, tmp_path)
    (cmd, kw), = tool.calls
    assert cmd == [NPX, "--yes", "--prefer-offline", "@stoplight/spectral-cli", "lint", str(tmp_path / "spec-full.json"),
                   "--ruleset", str(tmp_path / ".spectral.yaml"), "-f", "json", "--quiet"]
    assert kw["cancel"] is cfg.cancel and kw["timeout"] == 300
    assert (tmp_path / ".spectral.yaml").read_text() == 'extends: ["spectral:oas"]\n'


def test_env_inherits_and_adds_node_ca_bundle(tmp_path, tool, monkeypatch):
    monkeypatch.setenv("SPRAT_LINT_MARKER", "1")
    _run(tmp_path, tool=tool)
    env = tool.calls[0][1]["env"]
    assert env["NODE_EXTRA_CA_CERTS"] == r"C:\ca\bundle.pem" and env["SPRAT_LINT_MARKER"] == "1"
    assert os.environ.get("NODE_EXTRA_CA_CERTS") != r"C:\ca\bundle.pem"  # parent env untouched


@pytest.mark.parametrize("text, name", [(SPEC_JSON, "spec-full.json"), ("  \n" + SPEC_JSON, "spec-full.json"),
                                        (SPEC_YAML, "spec-full.yaml"), ('"openapi": "3.0.3"', "spec-full.yaml")])
def test_spec_file_extension_follows_content(tmp_path, tool, text, name):
    _run(tmp_path, spec=_spec(text=text), tool=tool)
    assert (tmp_path / name).read_text(encoding="utf-8") == text
    assert tool.calls[0][0][5] == str(tmp_path / name)


def test_lints_the_full_document_not_the_reduced_one(tmp_path, tool):
    _run(tmp_path, spec=_spec(text='{"reduced": true}', full_text=SPEC_YAML, filtered=True), tool=tool)
    assert (tmp_path / "spec-full.yaml").read_text(encoding="utf-8") == SPEC_YAML
    assert not (tmp_path / "spec-full.json").exists()


def test_non_ascii_spec_is_written_as_utf8(tmp_path, tool):
    text = '{"info": {"title": "Caf\u00e9 \u2013 \u65e5\u672c"}}'
    _run(tmp_path, spec=_spec(text=text), tool=tool)
    assert (tmp_path / "spec-full.json").read_bytes() == text.encode("utf-8")


def test_reports_progress(tmp_path, tool):
    got = []
    lint.run(_spec(), Config(on_progress=got.append), tmp_path)
    assert got == [{"stage": "lint", "msg": "Checking the Swagger document with Spectral", "op": "", "done": None,
                    "total": None, "level": "info"}]


# ---------- parsing ----------

@pytest.mark.parametrize("severity, expected", [(0, "high"), (1, "medium"), (2, "low"), (3, "info"),
                                                (None, "info"), (9, "info"), (-1, "info")])
def test_severity_mapping(tmp_path, tool, severity, expected):
    it = _item()
    if severity is None:
        del it["severity"]
    else:
        it["severity"] = severity
    res = _run(tmp_path, items=[it], tool=tool)
    assert [f.severity for f in res.findings] == [expected]


def test_spectral_output_becomes_findings(tmp_path, tool):
    items = [_item("info-contact", ["info"], 1, 'Info object must have "contact" object.', 0),
             _item("operation-operationId", ["paths", "/items", "get"], 1, 'Operation must have "operationId".'),
             _item("oas3-schema", ["paths", "/items", "post", "parameters", 0, "schema"], 0, "bad schema"),
             _item("parser", [], 0, "Unexpected end of the stream")]
    res = _run(tmp_path, items=items, tool=tool, rc=1)  # Spectral exits 1 when it found errors
    assert res.status == "ok" and res.note == ""
    assert res.findings == [
        Finding("lint", "medium", 'info-contact: Info object must have "contact" object.', "info"),
        Finding("lint", "medium", 'operation-operationId: Operation must have "operationId".', "paths//items/get"),
        Finding("lint", "high", "oas3-schema: bad schema", "paths//items/post/parameters/0/schema"),
        Finding("lint", "high", "parser: Unexpected end of the stream", ""),
    ]


def test_item_without_path_code_or_message(tmp_path, tool):
    res = _run(tmp_path, items=[{}], tool=tool)
    assert res.findings == [Finding("lint", "info", "None: None", "")]


@pytest.mark.parametrize("stdout", ["[]", "", "  []\n"])
def test_clean_document_has_no_findings(tmp_path, tool, stdout):
    res = _run(tmp_path, tool=tool, stdout=stdout)
    assert res.status == "ok" and res.findings == []


@pytest.mark.parametrize("stdout", ["No files found to lint.", "[{", "<html>", "Error: something\n[1,2"])
def test_malformed_output_is_an_error_with_stderr(tmp_path, tool, stdout):
    res = _run(tmp_path, tool=tool, stdout=stdout, stderr="npm error boom", rc=2)
    assert res.status == "error" and res.note == "npm error boom" and res.findings == []


def test_malformed_output_without_stderr_shows_stdout_tail(tmp_path, tool):
    junk = "x" * 1000 + "THE END"
    res = _run(tmp_path, tool=tool, stdout=junk, rc=2)
    assert res.status == "error" and len(res.note) == 500 and res.note.endswith("THE END")


def test_long_stderr_is_trimmed_to_its_tail(tmp_path, tool):
    res = _run(tmp_path, tool=tool, stdout="oops", stderr="a" * 2000 + "last words")
    assert len(res.note) == 500 and res.note.endswith("last words")


def test_json_that_is_not_a_list_is_never_ok(tmp_path, tool):
    tool.output(stdout='{"error": "unexpected"}')
    try:
        res = lint.run(_spec(), Config(), tmp_path)
    except Exception:
        return  # the runner turns a raised exception into status "error"
    assert res.status == "error"


def test_tool_failure_with_empty_stdout_is_an_error(tmp_path, tool):
    res = _run(tmp_path, tool=tool, stdout="", stderr="npm error code E404\nnpm error 404 Not Found", rc=1)
    assert res.status == "error" and "E404" in res.note


def test_timeout_propagates(tmp_path, tool):
    tool.exc = subprocess.TimeoutExpired(["npx"], 300)
    with pytest.raises(subprocess.TimeoutExpired):
        lint.run(_spec(), Config(), tmp_path)


def test_cancel_propagates(tmp_path, tool):
    tool.exc = Cancelled()
    with pytest.raises(Cancelled):
        lint.run(_spec(), Config(), tmp_path)


def test_runner_reports_a_lint_timeout_as_error(tmp_path, tool, monkeypatch):
    from sprat import runner
    tool.exc = subprocess.TimeoutExpired(["npx"], 300)
    monkeypatch.setattr(runner, "load_spec", lambda *a, **k: _spec())
    res, = runner.run_pipeline(Config(spec="x", stages=["lint"], out_dir=str(tmp_path / "out")))
    assert res.status == "error" and "TimeoutExpired" in res.note


# ---------- selected operations ----------

FILTER_ITEMS = [
    _item("a", ["info"]),
    _item("b", ["paths", "/items", "get"]),
    _item("c", ["paths", "/items", "post", "responses"]),
    _item("d", ["paths", "/items", "parameters", 0]),  # path-level, not an operation
    _item("e", ["paths", "/items"]),
    _item("f", ["paths", "/users/{id}", "get"]),
    _item("g", ["paths", "/other", "get"]),
    _item("h", ["components", "schemas", "X"]),
    _item("i", ["paths"]),
]


def test_unfiltered_spec_keeps_every_finding(tmp_path, tool):
    res = _run(tmp_path, items=FILTER_ITEMS, tool=tool)
    assert [f.title.split(":")[0] for f in res.findings] == list("abcdefghi")


def test_filtered_spec_keeps_selected_operations_and_document_level_findings(tmp_path, tool):
    spec = _spec(ops=[Operation("get", "/items", False, False)], filtered=True)
    res = _run(tmp_path, spec=spec, items=FILTER_ITEMS, tool=tool)
    # kept: document-level (a, h, i), the selected GET (b), path-level items of the selected path (d, e)
    assert [f.title.split(":")[0] for f in res.findings] == ["a", "b", "d", "e", "h", "i"]


def test_filtered_spec_with_two_operations(tmp_path, tool):
    spec = _spec(ops=[Operation("post", "/items", False, True), Operation("get", "/users/{id}", False, False)],
                 filtered=True)
    res = _run(tmp_path, spec=spec, items=FILTER_ITEMS, tool=tool)
    assert [f.title.split(":")[0] for f in res.findings] == ["a", "c", "d", "e", "f", "h", "i"]


def test_filtered_spec_without_operations_drops_path_findings(tmp_path, tool):
    res = _run(tmp_path, spec=_spec(ops=[], filtered=True), items=FILTER_ITEMS, tool=tool)
    assert [f.title.split(":")[0] for f in res.findings] == ["a", "h", "i"]


# ---------- test log ----------

def test_findings_are_logged_per_rule(tmp_path, tool):
    tl = _log(tmp_path)
    items = [_item("operation-tags", ["paths", "/users/{id}", "delete"], 1, "needs tags", 12),
             _item("info-hint", ["info"], 3, "a hint"),
             _item("top", [], 0, "root problem")]
    res = _run(tmp_path, items=items, tool=tool, cfg=Config(testlog=tl))
    assert len(res.findings) == 3
    e = list(iter_entries(tl.path))
    assert [x["scenario"] for x in e] == ["Swagger rule `operation-tags`", "Swagger rule `info-hint`",
                                          "Swagger rule `top`"]
    assert [x["operation"] for x in e] == ["DELETE /users/{id}", "", ""]
    assert [x["verdict"] for x in e] == ["fail", "info", "fail"]
    assert e[0]["expected"] == "The Swagger document follows this OpenAPI rule"
    assert e[0]["explanation"] == "needs tags (at paths//users/{id}/delete)."
    assert e[2]["explanation"] == "root problem (at document root)."
    assert e[0]["details"] == {"message": "needs tags", "severity": "medium",
                               "spec_location": "paths//users/{id}/delete", "line": 12}
    assert e[1]["details"]["line"] is None and e[1]["stage"] == "lint"


def test_non_method_path_item_has_no_operation_in_log(tmp_path, tool):
    tl = _log(tmp_path)
    _run(tmp_path, items=[_item("x", ["paths", "/items", "parameters", 0])], tool=tool, cfg=Config(testlog=tl))
    assert next(iter_entries(tl.path))["operation"] == ""


def test_clean_run_logs_one_pass(tmp_path, tool):
    tl = _log(tmp_path)
    _run(tmp_path, tool=tool, cfg=Config(testlog=tl))
    e, = iter_entries(tl.path)
    assert (e["scenario"], e["verdict"], e["expected"]) == ("Spectral OpenAPI ruleset", "pass", "No rule violations")


def test_filtered_out_findings_still_log_a_pass(tmp_path, tool):
    tl = _log(tmp_path)
    spec = _spec(ops=[Operation("get", "/items", False, False)], filtered=True)
    res = _run(tmp_path, spec=spec, items=[_item("g", ["paths", "/other", "get"])], tool=tool, cfg=Config(testlog=tl))
    assert res.findings == [] and [x["verdict"] for x in iter_entries(tl.path)] == ["pass"]


def test_error_and_skip_log_nothing(tmp_path, tool, monkeypatch):
    tl = _log(tmp_path)
    _run(tmp_path, tool=tool, stdout="garbage", cfg=Config(testlog=tl))
    monkeypatch.setattr(lint.shutil, "which", lambda n: None)
    _run(tmp_path, cfg=Config(testlog=tl))
    assert list(iter_entries(tl.path)) == []


def test_findings_get_operations_from_runner_annotate(tmp_path, tool):
    from sprat.runner import annotate
    items = [_item("b", ["paths", "/users/{id}", "get", "responses"]), _item("a", ["info"])]
    res = _run(tmp_path, items=items, tool=tool)
    annotate(_spec(), "http://localhost:8000", [res])
    assert [f.operation for f in res.findings] == ["GET /users/{id}", ""]


# ---------- real Spectral ----------

@functools.lru_cache(maxsize=None)
def _spectral_missing() -> str:
    npx = shutil.which("npx")
    if not npx:
        return "npx not installed"
    try:
        p = subprocess.run([npx, "--yes", "--offline", "@stoplight/spectral-cli", "--version"],
                           capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"npx unusable: {e}"
    return "" if p.returncode == 0 else "@stoplight/spectral-cli is not in the npm cache (won't download it in a test)"


def _spectral_cached():
    reason = _spectral_missing()
    if reason:
        pytest.skip(reason)


REAL_SPEC = {"openapi": "3.0.3", "info": {"title": "t", "version": "1"},
             "servers": [{"url": "http://localhost:1"}],
             "paths": {"/items": {"get": {"responses": {"200": {"description": "ok"}}}},
                       "/other": {"get": {"responses": {"200": {"description": "ok"}}}}}}


@pytest.mark.external
@pytest.mark.slow
def test_real_spectral_finds_rule_violations(tmp_path):
    _spectral_cached()
    tl = _log(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    res = lint.run(_spec(text=json.dumps(REAL_SPEC), ops=[]), Config(testlog=tl), out)
    assert res.status == "ok", res.note
    codes = {(f.title.split(":")[0], f.endpoint) for f in res.findings}
    assert ("operation-operationId", "paths//items/get") in codes
    assert ("info-contact", "info") in codes
    assert all(f.severity in ("high", "medium", "low", "info") for f in res.findings)
    assert any(e["operation"] == "GET /items" for e in iter_entries(tl.path))


@pytest.mark.external
@pytest.mark.slow
def test_real_spectral_respects_selected_operations(tmp_path):
    _spectral_cached()
    spec = _spec(text=json.dumps(REAL_SPEC), ops=[Operation("get", "/items", False, False)], filtered=True)
    res = lint.run(spec, Config(), tmp_path)
    assert res.status == "ok", res.note
    eps = {f.endpoint for f in res.findings}
    assert "paths//items/get" in eps and "paths//other/get" not in eps


@pytest.mark.external
@pytest.mark.slow
def test_real_spectral_reports_a_broken_yaml_document(tmp_path):
    _spectral_cached()
    res = lint.run(_spec(text="openapi: 3.0.3\ninfo: [unclosed\n", ops=[]), Config(), tmp_path)
    assert res.status == "ok", res.note
    assert any(f.severity == "high" for f in res.findings)
