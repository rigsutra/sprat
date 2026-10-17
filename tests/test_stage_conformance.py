"""Conformance stage: Schemathesis command line, JUnit/NDJSON parsing, findings, test log, live progress."""
import base64
import importlib.util
import json
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from sprat.auth import LoginConfig, TokenProvider
from sprat.config import Config
from sprat.proc import Cancelled, Result, Tail
from sprat.spec import Operation, Spec, filter_operations, load_spec
from sprat.stages import conformance
from sprat.stages.conformance import AUTH_HOOKS, SEVERITY_BY_CHECK, _Live, _split_checks, log_scenarios, scenario_cases
from sprat.testlog import TestLog, iter_entries

BASE = "http://api.test"
SPEC_TEXT = '{"openapi": "3.0.1", "paths": {}}'


def b64(s: str) -> dict:
    return {"$base64": base64.b64encode(s.encode()).decode()}


def op(method="get", path="/items"):
    return Operation(method, path, False, False)


def spec_of(*ops, base=BASE, filtered=False, from_page=False):
    ops = ops or (op(),)
    return Spec({}, BASE + "/openapi.json", "openapi3", base, list(ops), SPEC_TEXT, SPEC_TEXT, filtered, from_page)


def cfg_of(tmp_path=None, **kw):
    got = []
    kw.setdefault("spec", BASE + "/openapi.json")
    c = Config(on_progress=got.append, **kw)
    if tmp_path is not None:
        c.testlog = TestLog(tmp_path / "test-log.ndjson", ["token-a"])
    c.got = got
    return c


def msgs(cfg):
    return [g["msg"] for g in cfg.got]


# ---------- Schemathesis event builders ----------

def case(cid="c1", method="POST", path="/items", mode="positive", desc="", status=200, body=None, headers=None,
         failed=None, message="", elapsed=0.01234, ts=1700000000.0, req_body=None, response=True):
    checks = [{"name": "not_a_server_error", "status": "success"}]
    for name in ([failed] if isinstance(failed, str) else failed or []):
        checks.append({"name": name, "status": "failure",
                       "failure_info": {"failure": {"title": name.replace("_", " ").title(), "message": message}}})
    value = {"method": method, "path": path, "id": cid,
             "meta": {"generation": {"mode": mode}, "phase": {"data": {"description": desc}}}}
    rs = {"status_code": status, "headers": {"content-type": ["application/json"]}, "content": body,
          "elapsed": elapsed} if response else None
    inter = {"timestamp": ts, "request": {"method": method, "uri": BASE + path, "headers": headers or {},
                                          "body": req_body}, "response": rs}
    return cid, value, inter, checks


def scenario(*cases, label="POST /items", phase="coverage", status="success"):
    rec = {"label": label, "cases": {}, "interactions": {}, "checks": {}}
    for cid, value, inter, checks in cases:
        rec["cases"][cid] = {"value": value}
        rec["interactions"][cid] = inter
        rec["checks"][cid] = checks
    return {"ScenarioFinished": {"status": status, "phase": phase, "recorder": rec}}


def phase(name, enabled=True):
    return {"PhaseStarted": {"phase": {"name": name, "is_enabled": enabled}}}


class FakeTail:
    def __init__(self, lines=()):
        self.pending = list(lines)

    def push(self, *events):
        self.pending += [e if isinstance(e, str) else json.dumps(e) for e in events]

    def lines(self):
        out, self.pending = self.pending, []
        return out


def live(*events, total=3):
    cfg = cfg_of()
    tail = FakeTail()
    tail.push(*events)
    _Live(cfg, total, tail).tick()
    return [(g["op"], g["msg"], g["done"], g["level"]) for g in cfg.got]


# ---------- _split_checks ----------

JUNIT_TEXT = """1. Test Case ID: Dh8wxe

- API accepts requests without authentication

    Expected 401 or 403, got `200 OK` for `GET /admin/stats`

- Undocumented HTTP status code

    Received: 404

[404] Not Found:

    `{"detail":"not found"}`

Reproduce with:

    curl -X GET http://127.0.0.1:8000/admin/stats

2. Test Case ID: xJwM8f

- Undocumented HTTP status code

    Received: 401

3. Test Case ID: Zz9_-a

- Server error
"""


@pytest.mark.parametrize("title,severity", [
    ("Server error", "high"),
    ("Server error on unexpected Content-Type", "high"),
    ("API accepts requests without authentication", "high"),
    ("Missing header not rejected", "high"),
    ("Response violates schema", "medium"),
    ("API accepted schema-violating request", "medium"),
    ("API rejected schema-compliant request", "medium"),
    ("Undocumented Content-Type", "low"),
    ("Undocumented HTTP status code", "low"),
    ("Unsupported methods", "low"),
    ("Missing Content-Type header", "medium"),
    ("Use after free", "medium"),
    ("Resource is not available after creation", "medium"),
    ("Response time limit exceeded", "medium"),
    ("Some brand new check", "medium"),
    ("SERVER ERROR", "high"),  # case-insensitive
    ("Check failed", "medium"),
])
def test_check_title_severity(title, severity):
    [f] = _split_checks("GET /x", f"1. Test Case ID: abc\n\n- {title}\n\n    details\n")
    assert (f.stage, f.severity, f.title, f.endpoint) == ("conformance", severity, title, "GET /x")


@pytest.mark.parametrize("key,severity", SEVERITY_BY_CHECK)
def test_every_severity_rule_matches_its_own_key(key, severity):
    [f] = _split_checks("GET /x", f"- {key}")
    assert f.severity == severity


def test_invalid_authentication_accepted_is_high():
    [f] = _split_checks("GET /admin", "1. Test Case ID: a\n\n- API accepts invalid authentication\n")
    assert f.severity == "high"


def test_split_checks_dedupes_counts_and_keeps_first_seen_order():
    fs = _split_checks("GET /admin/stats", JUNIT_TEXT)
    assert [f.title for f in fs] == ["API accepts requests without authentication", "Undocumented HTTP status code",
                                     "Server error"]
    by = {f.title: f for f in fs}
    assert by["Undocumented HTTP status code"].detail.startswith("2 failing case(s). First:\n\n- API accepts")
    assert "Received: 404" in by["Undocumented HTTP status code"].detail  # the first case is the example
    assert by["Server error"].detail == "1 failing case(s). First:\n\n- Server error"
    assert "Test Case ID" not in by["Server error"].detail


def test_split_checks_example_is_truncated():
    text = "1. Test Case ID: a\n\n- Server error\n\n" + "    x" * 2000
    [f] = _split_checks("POST /x", text)
    assert len(f.detail) == len("1 failing case(s). First:\n\n") + 1500


def test_split_checks_titles_are_stripped_and_indented_dashes_ignored():
    text = "1. Test Case ID: a\n\n- Server error   \n\n    - not a title\n  - nor this\n-no space either\n"
    assert [f.title for f in _split_checks("GET /x", text)] == ["Server error"]


def test_split_checks_without_case_headers():
    assert [f.title for f in _split_checks("GET /x", "- Response violates schema\n- Server error")] == [
        "Response violates schema", "Server error"]


def test_split_checks_unstructured_text():
    [f] = _split_checks("GET /x", "Network Error: Connection refused")
    assert (f.title, f.severity) == ("Check failed", "medium")
    assert f.detail == "1 failing case(s). First:\n\nNetwork Error: Connection refused"


def test_split_checks_empty_text_is_no_finding():
    assert _split_checks("GET /x", "") == []


def test_split_checks_case_id_variants():
    text = "1. Test Case ID: a-B_9\n- A\n12. Test Case ID: zz\n- A\n"
    [f] = _split_checks("GET /x", text)
    assert f.detail.startswith("2 failing case(s)")


# ---------- scenario_cases ----------

def test_scenario_cases_full_record():
    sc = scenario(case(mode="negative", desc="- in_stock: Incorrect type", status=200, body=b64('{"id": 1}'),
                       headers={"Authorization": "Bearer t"}, failed="negative_data_rejection",
                       message="Invalid data should have been rejected", req_body=b64('{"in_stock": 0}')))
    [c] = scenario_cases(sc["ScenarioFinished"])
    assert c["phase"] == "coverage" and c["mode"] == "negative" and c["case_id"] == "c1"
    assert c["ts"] == 1700000000.0
    assert c["operation"] == "POST /items"
    assert c["scenario"] == "Edge cases: `in_stock` has the wrong type"
    assert c["expected"].startswith("The API should refuse it with a 4xx")
    assert c["blocked"] == ""
    assert c["request"] == {"method": "POST", "url": BASE + "/items", "headers": {"Authorization": "Bearer t"},
                            "body": '{"in_stock": 0}'}
    assert c["response"]["status"] == 200 and c["response"]["body"] == '{"id": 1}'
    assert c["response"]["elapsed_ms"] == 12.3
    assert c["checks"] == [{"name": "not_a_server_error", "status": "success"},
                           {"name": "negative_data_rejection", "status": "failure"}]
    assert c["failures"] == ["Accepted invalid input (HTTP 200). It should have refused it with a 4xx."]
    assert c["failures_raw"] == ["Negative Data Rejection: Invalid data should have been rejected"]


def test_scenario_cases_empty_and_partial_bodies():
    assert list(scenario_cases({})) == []
    assert list(scenario_cases({"recorder": None})) == []
    [c] = scenario_cases({"recorder": {"interactions": {"x": {}}}})
    assert c["operation"] == "" and c["response"] is None and c["failures"] == [] and c["checks"] == []
    assert c["request"] == {"method": "", "url": "", "headers": None, "body": None}


def test_scenario_cases_without_response_or_elapsed():
    [c] = scenario_cases(scenario(case(response=False))["ScenarioFinished"])
    assert c["response"] is None
    sc = scenario(case(elapsed=None))
    [c] = scenario_cases(sc["ScenarioFinished"])
    assert c["response"]["elapsed_ms"] is None


def test_scenario_cases_method_falls_back_to_request():
    cid, value, inter, checks = case(method="DELETE", path="/x/1")
    del value["method"]
    [c] = scenario_cases(scenario((cid, value, inter, checks))["ScenarioFinished"])
    assert c["operation"] == "DELETE /x/1"


def test_scenario_cases_server_error_shows_what_the_server_said():
    sc = scenario(case(status=500, body=b64('{"detail": "database is down"}'), failed="not_a_server_error",
                       message='{"message": "other"}'))
    [c] = scenario_cases(sc["ScenarioFinished"])
    assert c["failures"] == ["The server crashed (HTTP 500). A server error is always a bug. "
                             "Server said: database is down"]
    sc = scenario(case(status=502, body="Bad Gateway", failed=["not_a_server_error", "status_code_conformance"]))
    [c] = scenario_cases(sc["ScenarioFinished"])
    assert c["failures"][0].endswith("Server said: Bad Gateway")
    assert len(c["failures"]) == 2 and "Server said" not in c["failures"][1]


def test_scenario_cases_unknown_check_and_missing_failure_info():
    cid, value, inter, _ = case(status=200)
    checks = [{"name": "custom_check", "status": "failure"}]
    [c] = scenario_cases(scenario((cid, value, inter, checks))["ScenarioFinished"])
    assert c["failures"] == ["custom check."]
    assert c["failures_raw"] == ["custom_check: "]


@pytest.mark.parametrize("status,headers,desc,body,expected", [
    (401, {"Authorization": "Bearer x"}, "Default positive test case", None,
     "Not really tested: refused with HTTP 401 (login not accepted), so the API's logic was never reached."),
    (403, {"X-API-Key": "k"}, "", '{"required": ["read:items"]}',
     "Not really tested: refused with HTTP 403 Forbidden before anything else, so the API's logic was never "
     "reached. (missing permission `read:items`)"),
    (401, {"cookie": "s=1"}, "", '{"detail": "Session expired"}',
     "Not really tested: refused with HTTP 401 (login not accepted), so the API's logic was never reached. "
     "(server said: Session expired)"),
    (401, {}, "", None, ""),  # no credentials sent: a 401 is the right answer
    (401, {"Authorization": "x"}, "Missing `Authorization` at header", None, ""),  # the case is about auth
    (403, {"Authorization": "x"}, "Unspecified HTTP method: PUT", None, ""),
    (200, {"Authorization": "x"}, "", None, ""),
])
def test_scenario_cases_blocked_by_auth(status, headers, desc, body, expected):
    [c] = scenario_cases(scenario(case(status=status, headers=headers, desc=desc, body=body))["ScenarioFinished"])
    assert c["blocked"] == expected


def test_scenario_cases_negative_blocked_wording():
    [c] = scenario_cases(scenario(case(status=403, mode="negative", headers={"Authorization": "x"}))
                         ["ScenarioFinished"])
    assert c["blocked"].endswith("so the invalid input was never checked.")


# ---------- _Live (progress from the NDJSON stream) ----------

def test_live_phases_and_probing_ignored():
    got = live(phase("probing"), phase("examples"), phase("fuzzing", enabled=False), phase("stateful"))
    assert [g[1].split(".")[0] for g in got] == ["Now running: Swagger examples", "Now running: Request chains"]
    assert all(g[2] == 0 and g[3] == "info" for g in got)


def test_live_unknown_phase_name():
    [(_, msg, _, _)] = live(phase("chaos"))
    assert msg == "Now running: Chaos. "


def test_live_skips_noise():
    got = live("not json", "", "{truncated", {"Initialize": {}}, {"EngineStarted": {}},
               {"ScenarioFinished": {"status": "skip", "recorder": {"label": "GET /a"}}},
               {"ScenarioFinished": {"status": "success", "recorder": {"label": ""}}},
               {"ScenarioFinished": {"status": "success"}})
    assert got == []


@pytest.mark.parametrize("line", ["{}", "null", "[1, 2]", "42"])
def test_live_skips_non_object_json(line):
    assert live(line) == []


def test_live_skips_events_whose_body_is_not_an_object():
    assert live({"PhaseStarted": 5}, {"ScenarioFinished": ["x"]}) == []


def test_live_requests_without_response_are_a_warning_not_a_pass():
    got = live(phase("coverage"), scenario(case(), case("c2", status=None, response=False), label="GET /a"))
    assert got[1] == ("GET /a", "Edge cases: 1 of 2 request(s) got no response (network error or timeout), "
                                "so they weren't checked", 1, "warn")


def test_remove_retries_while_windows_holds_the_file(tmp_path, monkeypatch):
    f = tmp_path / "events.ndjson"
    f.write_text("x")
    real, calls = Path.unlink, []

    def flaky(self, missing_ok=False):
        calls.append(self)
        if len(calls) < 3:
            raise PermissionError("in use")
        real(self, missing_ok=missing_ok)
    monkeypatch.setattr(Path, "unlink", flaky)
    monkeypatch.setattr(conformance.time, "sleep", lambda s: None)
    conformance._remove(f)
    assert len(calls) == 3 and not f.exists()


def test_remove_gives_up_quietly_on_a_file_that_stays_locked(tmp_path, monkeypatch):
    def locked(self, missing_ok=False):
        raise PermissionError("in use")
    monkeypatch.setattr(Path, "unlink", locked)
    monkeypatch.setattr(conformance.time, "sleep", lambda s: None)
    conformance._remove(tmp_path / "events.ndjson")  # no exception: it must not hide a Cancelled


def test_live_counts_and_levels():
    ok = scenario(case(), case("c2"), label="GET /a", phase="coverage")
    one = scenario(case(), label="GET /b")
    bad2 = scenario(case(failed="not_a_server_error", status=500), case("c2", failed="not_a_server_error", status=500),
                    label="POST /c")
    bad3 = scenario(*[case(f"c{i}", status=200, failed="status_code_conformance") for i in range(3)],
                    label="PUT /d")
    got = live(phase("coverage"), ok, one, bad2, bad3, total=3)
    assert got[1] == ("GET /a", "Edge cases: 2 requests sent, all checks passed", 1, "ok")
    assert got[2] == ("GET /b", "Edge cases: 1 request sent, all checks passed", 2, "ok")
    assert got[3][0] == "POST /c" and got[3][2:] == (3, "bad")
    assert got[3][1].startswith("Edge cases: valid request → got HTTP 500. The server crashed")
    assert got[3][1].endswith("(+1 more failing request)")
    assert got[4][1].endswith("(+2 more failing requests)")
    assert got[4][2] == 3  # capped at the number of operations


def test_live_all_requests_refused():
    sc = scenario(case(status=401, headers={"Authorization": "x"}), case("c2", status=401, headers={"Authorization": "x"}),
                  label="GET /secret")
    [(op_, msg, done, level)] = live(sc, total=1)
    assert (op_, done, level) == ("GET /secret", 1, "warn")
    assert msg == ("Test: all 2 request(s) were refused before being processed. Not really tested: refused with "
                   "HTTP 401 (login not accepted), so the API's logic was never reached.")


def test_live_some_requests_refused():
    sc = scenario(case(status=200), case("c2", status=403, headers={"Authorization": "x"}), label="GET /mixed")
    [(_, msg, _, level)] = live(phase("fuzzing"), sc)[1:]
    assert level == "ok"
    assert msg == "Random data: 2 requests sent, all checks passed (1 refused with 401/403, so not really tested)"


def test_live_request_chains_are_not_an_operation():
    got = live(phase("stateful"), scenario(case(failed="use_after_free"), label="Stateful tests", phase="stateful"))
    assert got[1][0] == "" and got[1][2] is None and got[1][3] == "bad"
    assert "Something that was deleted could still be fetched." in got[1][1]


def test_live_phase_change_resets_counter():
    tail = FakeTail()
    cfg = cfg_of()
    lv = _Live(cfg, 5, tail)
    tail.push(phase("examples"), scenario(case(), label="GET /a"), scenario(case(), label="GET /b"))
    lv.tick()
    assert lv.done == 2 and lv.phase == "examples"
    tail.push(phase("coverage"), scenario(case(), label="GET /a"))
    lv.tick()
    assert (lv.done, lv.phase) == (1, "coverage")
    lv.tick()  # nothing new
    assert len(cfg.got) == 5


def test_live_with_real_tail_and_partial_lines(tmp_path):
    p = tmp_path / "events.ndjson"
    cfg = cfg_of()
    lv = _Live(cfg, 2, Tail(p))
    lv.tick()  # file doesn't exist yet
    line = json.dumps(scenario(case(), label="GET /a"))
    with open(p, "w", encoding="utf-8") as f:
        f.write(json.dumps(phase("examples")) + "\n" + line[:20])
    lv.tick()
    assert len(cfg.got) == 1
    with open(p, "a", encoding="utf-8") as f:
        f.write(line[20:] + "\n")
    lv.tick()
    assert cfg.got[-1]["op"] == "GET /a" and cfg.got[-1]["done"] == 1


# ---------- log_scenarios ----------

def write_events(path: Path, *events):
    path.write_text("\n".join(e if isinstance(e, str) else json.dumps(e) for e in events) + "\n", encoding="utf-8")
    return path


def test_log_scenarios_without_log_or_file(tmp_path):
    ev = write_events(tmp_path / "e.ndjson", scenario(case()))
    assert log_scenarios(Config(), ev) == 0
    assert log_scenarios(cfg_of(tmp_path), tmp_path / "missing.ndjson") == 0


def test_log_scenarios_verdicts(tmp_path):
    cfg = cfg_of(tmp_path)
    ev = write_events(
        tmp_path / "e.ndjson",
        "garbage line", phase("coverage"), {"Initialize": {}},
        scenario(case("f", status=500, failed="not_a_server_error", body=b64("boom"))),
        scenario(case("r", status=503), label="Stateful tests", phase="stateful"),
        scenario(case("b", status=401, headers={"Authorization": "Bearer token-a"})),
        scenario(case("n", mode="negative", status=422, desc="- name: Incorrect type")),
        scenario(case("p", status=200, ts=1234.5), phase="examples"),
        '{"ScenarioFinished": null}',
    )
    assert log_scenarios(cfg, ev) == 5
    e = list(iter_entries(cfg.testlog.path))
    assert [x["verdict"] for x in e] == ["fail", "fail", "error", "pass", "pass"]
    assert e[0]["explanation"] == ("The server crashed (HTTP 500). A server error is always a bug. "
                                   "Server said: boom")
    assert e[1]["explanation"].startswith("The server crashed (HTTP 503)") and "repeat" in e[1]["explanation"]
    assert e[2]["explanation"].startswith("Not really tested: refused with HTTP 401")
    assert e[2]["request"]["headers"] == {"Authorization": "Bearer ***"}  # masked
    assert e[3]["explanation"] == "Refused with HTTP 422, as it should."
    assert e[4]["explanation"] == "Answered HTTP 200; the response matches the Swagger."
    assert e[4]["ts"] == 1234.5 and e[4]["scenario"] == "Swagger examples: valid request"
    assert all(x["stage"] == "conformance" and x["operation"] == "POST /items" for x in e)
    d = e[0]["details"]
    assert d["phase"] == "coverage" and d["phase_meaning"].startswith("Deliberately chosen")
    assert d["generation_mode"] == "positive" and d["case_id"] == "f"
    assert d["failures"] == [e[0]["explanation"]] and d["tool_messages"] == ["Not A Server Error: "]
    assert [c["name"] for c in d["checks"]] == ["not_a_server_error", "not_a_server_error"]
    assert e[1]["details"]["phase_meaning"].startswith("Chains of calls")


def test_log_scenarios_request_without_response_is_not_a_pass(tmp_path):
    cfg = cfg_of(tmp_path)
    log_scenarios(cfg, write_events(tmp_path / "e.ndjson", scenario(case(status=None, response=False))))
    [e] = iter_entries(cfg.testlog.path)
    assert e["response"] is None
    assert e["verdict"] == "error"


def test_log_scenarios_unknown_phase_meaning(tmp_path):
    cfg = cfg_of(tmp_path)
    log_scenarios(cfg, write_events(tmp_path / "e.ndjson", scenario(case(), phase="mystery")))
    [e] = iter_entries(cfg.testlog.path)
    assert e["details"]["phase_meaning"] == "" and e["scenario"] == "Mystery: valid request"


def test_log_scenarios_tolerates_invalid_utf8(tmp_path):
    cfg = cfg_of(tmp_path)
    p = tmp_path / "e.ndjson"
    p.write_bytes(b"\xff\xfe junk\n" + json.dumps(scenario(case())).encode() + b"\n")
    assert log_scenarios(cfg, p) == 1


# ---------- run(): command line, environment, results ----------

class FakeSchemathesis:
    """Replaces proc.run_cmd: records the command, writes the reports Schemathesis would."""

    def __init__(self, junit=None, events=(), stdout="", stderr="", rc=0, exc=None):
        self.junit, self.events, self.stdout, self.stderr, self.rc, self.exc = junit, events, stdout, stderr, rc, exc
        self.calls = []

    def __call__(self, cmd, *, cancel=None, timeout=3600, env=None, on_cancel=None, on_tick=None):
        self.cmd, self.env, self.cancel, self.timeout = cmd, env, cancel, timeout
        self.calls.append(cmd)
        jp = Path(cmd[cmd.index("--report-junit-path") + 1])
        ep = Path(cmd[cmd.index("--report-ndjson-path") + 1])
        self.stale = (jp.exists(), ep.exists())
        for ev in self.events:
            with open(ep, "a", encoding="utf-8") as f:
                f.write((ev if isinstance(ev, str) else json.dumps(ev)) + "\n")
            if on_tick:
                on_tick([])
        if self.junit is not None:
            jp.write_text(self.junit, encoding="utf-8")
        if self.exc:
            raise self.exc
        return Result(self.rc, self.stdout, self.stderr)

    def opt(self, name):
        return self.cmd[self.cmd.index(name) + 1]

    def pairs(self, name):
        return [self.cmd[i + 1] for i, a in enumerate(self.cmd) if a == name]


JUNIT_OK = """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="schemathesis">
  <testcase name="GET /items" time="0.1" />
</testsuite></testsuites>"""

JUNIT_FAIL = """<?xml version="1.0" encoding="utf-8"?>
<testsuites errors="1" failures="3" tests="5"><testsuite name="schemathesis">
  <testcase name="GET /admin/stats">
    <failure type="failure">1. Test Case ID: WN5y6e

- API accepts requests without authentication

    Expected 401 or 403, got `200 OK` for `GET /admin/stats`

- Missing header not rejected

    Got 200 when missing required 'Authorization' header, expected 401</failure>
  </testcase>
  <testcase name="GET /health" time="0.15" />
  <testcase name="POST /items">
    <failure type="failure">1. Test Case ID: pR3YBG

- API accepted schema-violating request

    Invalid data should have been rejected</failure>
    <failure type="failure">1. Test Case ID: v8UQpr

- Server error

- Undocumented HTTP status code

    Received: 500</failure>
  </testcase>
  <testcase name="GET /items/{item_id}">
    <error type="error" message="Network Error: Connection reset" />
  </testcase>
  <testcase name="Stateful tests">
    <failure type="failure">1. Test Case ID: s1

- Use after free</failure>
  </testcase>
</testsuite></testsuites>"""


@pytest.fixture
def st(monkeypatch):
    monkeypatch.setattr(conformance, "ca_bundle", lambda: "C:/ca/bundle.pem")

    def install(**kw):
        fake = FakeSchemathesis(**kw)
        monkeypatch.setattr(conformance, "run_cmd", fake)
        return fake
    return install


def test_no_base_url_is_an_error(st, tmp_path):
    fake = st(junit=JUNIT_OK)
    res = conformance.run(spec_of(base=""), cfg_of(), tmp_path)
    assert (res.status, res.note) == ("error", "No base URL (pass --base-url)")
    assert fake.calls == []


def test_command_line_for_a_remote_spec(st, tmp_path):
    fake = st(junit=JUNIT_OK)
    cfg = cfg_of(max_examples=7)
    res = conformance.run(spec_of(), cfg, tmp_path)
    assert res.status == "ok" and res.note == "1 operation(s) tested" and res.findings == []
    c = fake.cmd
    assert c[:5] == [sys.executable, "-m", "schemathesis.cli", "run", BASE + "/openapi.json"]
    assert fake.opt("--url") == BASE
    assert fake.opt("--checks") == "all"
    assert fake.opt("--max-examples") == "7"
    assert "--continue-on-failure" in c and "--no-color" in c
    assert fake.opt("--report") == "junit,ndjson"
    assert fake.opt("--report-junit-path") == str(tmp_path / "schemathesis-junit.xml")
    assert fake.opt("--report-ndjson-path") == str(tmp_path / "schemathesis-events.ndjson")
    assert fake.opt("--tls-verify") == "C:/ca/bundle.pem"
    assert "-H" not in c and "--exclude-path-regex" not in c
    assert not (tmp_path / "spec.json").exists()
    assert fake.timeout == 1800 and fake.cancel is None


def test_cancel_event_is_passed_to_the_process(st, tmp_path):
    fake = st(junit=JUNIT_OK)
    cfg = cfg_of(cancel=threading.Event())
    conformance.run(spec_of(), cfg, tmp_path)
    assert fake.cancel is cfg.cancel


@pytest.mark.parametrize("spec_src,kw", [
    ("C:/specs/openapi.yaml", {}),  # local file
    (BASE + "/swagger", {"from_page": True}),  # spec embedded in a Swagger UI page
    (BASE + "/openapi.json", {"filtered": True}),  # reduced to selected operations
])
def test_spec_is_written_to_a_file_when_schemathesis_cant_fetch_it(st, tmp_path, spec_src, kw):
    fake = st(junit=JUNIT_OK)
    conformance.run(spec_of(**kw), cfg_of(spec=spec_src), tmp_path)
    assert fake.cmd[4] == str(tmp_path / "spec.json")
    assert (tmp_path / "spec.json").read_text(encoding="utf-8") == SPEC_TEXT


def test_selected_operations_reach_schemathesis_as_a_reduced_spec(st, tmp_path):
    raw = {"openapi": "3.0.1", "paths": {"/a": {"get": {"responses": {}}}, "/b": {"post": {"responses": {}}}}}
    full = Spec(raw, BASE, "openapi3", BASE, [op("get", "/a"), op("post", "/b")], json.dumps(raw))
    fake = st(junit=JUNIT_OK)
    conformance.run(filter_operations(full, ["POST /b"]), cfg_of(operations=["POST /b"]), tmp_path)
    written = json.loads((tmp_path / "spec.json").read_text(encoding="utf-8"))
    assert list(written["paths"]) == ["/b"] and fake.cmd[4] == str(tmp_path / "spec.json")


def test_config_base_url_overrides_spec(st, tmp_path):
    fake = st(junit=JUNIT_OK)
    conformance.run(spec_of(base="http://from-spec"), cfg_of(base_url="http://override:8080/api"), tmp_path)
    assert fake.opt("--url") == "http://override:8080/api"


def test_headers_and_exclusions(st, tmp_path):
    fake = st(junit=JUNIT_OK)
    cfg = cfg_of(headers={"Authorization": "Bearer token-a", "X-Tenant": "t1"},
                 headers_b={"Authorization": "Bearer token-b"}, exclude_paths=["^/admin", "logout$"])
    conformance.run(spec_of(), cfg, tmp_path)
    assert fake.pairs("-H") == ["Authorization: Bearer token-a", "X-Tenant: t1"]  # user B is never sent
    assert fake.pairs("--exclude-path-regex") == ["^/admin", "logout$"]


def test_environment(st, tmp_path, monkeypatch):
    monkeypatch.setenv("PYTHONIOENCODING", "utf-8:surrogateescape")
    monkeypatch.setenv("SPRAT_SOMETHING", "kept")
    fake = st(junit=JUNIT_OK)
    conformance.run(spec_of(), cfg_of(), tmp_path)
    env = fake.env
    assert env["PYTHONIOENCODING"] == "utf-8" and env["PYTHONUTF8"] == "1"
    assert env["REQUESTS_CA_BUNDLE"] == "C:/ca/bundle.pem"
    assert env["SPRAT_SOMETHING"] == "kept"
    assert "SCHEMATHESIS_HOOKS" not in env and "SPRAT_LOGIN_A" not in env
    assert not (tmp_path / "sprat_auth_hooks.py").exists()


def test_automatic_login_goes_through_a_hooks_file(st, tmp_path):
    login = LoginConfig(url="http://auth.test/login", body='{"email": "a@x", "password": "${PW}"}')
    cfg = cfg_of()
    cfg.auth_a = TokenProvider(login, variables={"PW": "s3cret-pass"})
    fake = st(junit=JUNIT_OK)
    conformance.run(spec_of(), cfg, tmp_path)
    hooks = tmp_path / "sprat_auth_hooks.py"
    assert fake.env["SCHEMATHESIS_HOOKS"] == str(hooks)
    assert hooks.read_text(encoding="utf-8") == AUTH_HOOKS
    login_env = json.loads(fake.env["SPRAT_LOGIN_A"])
    assert login_env["url"] == "http://auth.test/login"
    assert json.loads(login_env["body"]) == {"email": "a@x", "password": "s3cret-pass"}
    for f in tmp_path.rglob("*"):  # the secret lives only in the subprocess environment
        if f.is_file():
            assert "s3cret-pass" not in f.read_text(encoding="utf-8", errors="replace")
    assert "s3cret-pass" not in " ".join(fake.cmd)


def test_auth_hooks_source_is_valid_python():
    compile(AUTH_HOOKS, "sprat_auth_hooks.py", "exec")
    assert "retry_on=[]" in AUTH_HOOKS and "refresh_interval=None" in AUTH_HOOKS


def test_stale_reports_are_removed_before_running(st, tmp_path):
    (tmp_path / "schemathesis-junit.xml").write_text(JUNIT_FAIL, encoding="utf-8")
    (tmp_path / "schemathesis-events.ndjson").write_text(json.dumps(scenario(case())) + "\n", encoding="utf-8")
    fake = st(junit=None, stderr="crashed")
    cfg = cfg_of(tmp_path)
    res = conformance.run(spec_of(), cfg, tmp_path)
    assert fake.stale == (False, False)
    assert res.status == "error" and res.findings == []  # the old failures are not reported again
    assert list(iter_entries(cfg.testlog.path)) == []


@pytest.mark.parametrize("stdout,stderr,expected", [
    ("", "Error: No module named schemathesis.cli", "Schemathesis ran no tests: Error: No module named "
                                                     "schemathesis.cli"),
    ("Schema could not be loaded\n", "", "Schemathesis ran no tests: Schema could not be loaded"),
    ("", "", "Schemathesis ran no tests: "),
])
def test_no_junit_means_schemathesis_failed(st, tmp_path, stdout, stderr, expected):
    st(junit=None, stdout=stdout, stderr=stderr, rc=1)
    res = conformance.run(spec_of(), cfg_of(), tmp_path)
    assert (res.status, res.note, res.findings) == ("error", expected, [])
    assert (tmp_path / "schemathesis.log").read_text(encoding="utf-8") == stdout + "\n" + stderr


def test_error_note_keeps_the_tail_of_long_output(st, tmp_path):
    st(junit=None, stderr="x" * 2000 + "THE END")
    res = conformance.run(spec_of(), cfg_of(), tmp_path)
    assert res.note.endswith("THE END") and len(res.note) == len("Schemathesis ran no tests: ") + 600


def test_junit_without_test_cases_is_an_error(st, tmp_path):
    st(junit='<?xml version="1.0"?><testsuites><testsuite name="schemathesis"/></testsuites>',
       stdout="Unmatched filters", rc=0)
    res = conformance.run(spec_of(), cfg_of(), tmp_path)
    assert res.status == "error" and "Unmatched filters" in res.note


def test_failures_become_findings(st, tmp_path):
    st(junit=JUNIT_FAIL, stdout="out", stderr="err", rc=1)
    res = conformance.run(spec_of(), cfg_of(), tmp_path)
    assert res.status == "ok" and res.note == "5 operation(s) tested"
    assert [(f.stage, f.severity, f.title, f.endpoint) for f in res.findings] == [
        ("conformance", "high", "API accepts requests without authentication", "GET /admin/stats"),
        ("conformance", "high", "Missing header not rejected", "GET /admin/stats"),
        ("conformance", "medium", "API accepted schema-violating request", "POST /items"),
        ("conformance", "high", "Server error", "POST /items"),
        ("conformance", "low", "Undocumented HTTP status code", "POST /items"),
        ("conformance", "medium", "Check failed", "GET /items/{item_id}"),  # <error message=...> with no text
        ("conformance", "medium", "Use after free", "Stateful tests"),
    ]
    assert res.findings[5].detail.endswith("Network Error: Connection reset")
    assert (tmp_path / "schemathesis.log").read_text(encoding="utf-8") == "out\nerr"


def test_progress_and_test_log_from_the_event_stream(st, tmp_path):
    events = [phase("probing"), phase("coverage"),
              scenario(case(status=500, failed="not_a_server_error"), label="GET /items"),
              scenario(case("c2"), label="GET /other"),
              "partial garbage"]
    st(junit=JUNIT_OK, events=events)
    cfg = cfg_of(tmp_path)
    conformance.run(spec_of(op(), op("get", "/other")), cfg, tmp_path)
    m = msgs(cfg)
    assert m[0] == "Starting Schemathesis" and cfg.got[0]["total"] == 2
    assert m[1].startswith("Now running: Edge cases.")
    assert cfg.got[2]["op"] == "GET /items" and cfg.got[2]["level"] == "bad" and cfg.got[2]["done"] == 1
    assert cfg.got[3]["op"] == "GET /other" and cfg.got[3]["level"] == "ok" and cfg.got[3]["done"] == 2
    assert m[-1] == "Logged 2 request(s) to the test log"
    assert [e["verdict"] for e in iter_entries(cfg.testlog.path)] == ["fail", "pass"]


def test_without_test_log_nothing_is_logged(st, tmp_path):
    st(junit=JUNIT_OK, events=[scenario(case())])
    cfg = cfg_of()
    conformance.run(spec_of(), cfg, tmp_path)
    assert msgs(cfg)[-1] == "Logged 0 request(s) to the test log"


@pytest.mark.parametrize("exc", [Cancelled(), subprocess.TimeoutExpired(["schemathesis"], 1800)])
def test_stop_or_timeout_still_logs_what_finished(st, tmp_path, exc):
    st(junit=None, events=[scenario(case())], exc=exc)
    cfg = cfg_of(tmp_path)
    with pytest.raises(type(exc)):
        conformance.run(spec_of(), cfg, tmp_path)
    assert len(list(iter_entries(cfg.testlog.path))) == 1
    assert msgs(cfg)[-1] == "Logged 1 request(s) to the test log"
    assert not (tmp_path / "schemathesis.log").exists()


# ---------- real Schemathesis against the demo API ----------

def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def demo_api():
    uvicorn = pytest.importorskip("uvicorn")
    pytest.importorskip("schemathesis")
    path = Path(__file__).resolve().parent.parent / "examples" / "demo_api.py"
    spec = importlib.util.spec_from_file_location("demo_api_conformance_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    server = uvicorn.Server(uvicorn.Config(mod.app, host="127.0.0.1", port=_free_port(), log_level="warning"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    end = time.time() + 20
    while not server.started:
        if time.time() > end or not t.is_alive():
            raise RuntimeError("demo API did not start")
        time.sleep(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}", mod
    server.should_exit = True
    t.join(10)


def _real_cfg(base, tmp_path, **kw):
    # fixed seed (Schemathesis reads schemathesis.toml from the CWD, which these tests set to tmp_path):
    # with max_examples=5 a random run doesn't always reach the planted flaws
    (tmp_path / "schemathesis.toml").write_text("seed = 4321\n", encoding="utf-8")
    kw.setdefault("headers", {"Authorization": "Bearer token-a"})
    kw.setdefault("max_examples", 5)
    return cfg_of(tmp_path / "log", spec=base + "/openapi.json", base_url=base, **kw)


@pytest.mark.slow
@pytest.mark.e2e
def test_real_conformance_finds_demo_flaws(demo_api, tmp_path, monkeypatch):
    base, _ = demo_api
    monkeypatch.chdir(tmp_path)  # Schemathesis writes .schemathesis / .hypothesis caches into the CWD
    out = tmp_path / "out"
    out.mkdir()
    cfg = _real_cfg(base, tmp_path)
    res = conformance.run(load_spec(cfg.spec), cfg, out)
    assert res.status == "ok", res.note
    assert res.note.endswith("operation(s) tested")
    got = {(f.severity, f.title, f.endpoint) for f in res.findings}
    assert ("high", "API accepts requests without authentication", "GET /admin/stats") in got
    # Schemathesis reports a failure once, under the phase that hit it first: the negative-price crash
    # may surface from the request chains rather than from POST /items itself
    assert {("high", "Server error", "POST /items"), ("high", "Server error", "Stateful tests")} & got
    assert not any(f.endpoint == "GET /health" for f in res.findings)
    assert (out / "schemathesis-junit.xml").is_file() and (out / "schemathesis.log").is_file()
    log = list(iter_entries(cfg.testlog.path))
    assert log and {e["stage"] for e in log} == {"conformance"}
    assert any(e["verdict"] == "fail" and e["operation"] == "POST /items" for e in log)
    assert not any("token-a" in json.dumps(e) for e in log)  # the static token is masked
    m = msgs(cfg)
    assert m[0] == "Starting Schemathesis" and any(x.startswith("Now running:") for x in m)


@pytest.mark.slow
@pytest.mark.e2e
def test_real_conformance_selected_and_excluded_operations(demo_api, tmp_path, monkeypatch):
    base, _ = demo_api
    monkeypatch.chdir(tmp_path)
    full = load_spec(base + "/openapi.json")
    spec = filter_operations(full, ["GET /admin/stats", "GET /health"])
    cfg = _real_cfg(base, tmp_path, exclude_paths=["^/health$"])
    res = conformance.run(spec, cfg, tmp_path)
    assert res.status == "ok", res.note
    assert (tmp_path / "spec.json").is_file()
    assert {f.endpoint for f in res.findings} == {"GET /admin/stats"}
    assert {e["operation"].split(" ", 1)[1] for e in iter_entries(cfg.testlog.path)} == {"/admin/stats"}


@pytest.mark.slow
@pytest.mark.e2e
def test_real_conformance_with_automatic_login(demo_api, tmp_path, monkeypatch):
    base, mod = demo_api
    monkeypatch.chdir(tmp_path)
    full = load_spec(base + "/openapi.json")
    spec = filter_operations(full, ["GET /users/{uid}/orders/{oid}"])
    cfg = _real_cfg(base, tmp_path, headers={})
    cfg.auth_a = TokenProvider(LoginConfig(url=base + "/auth/login", token_path="data.accessToken",
                                           body='{"email": "alice@demo.test", "password": "${DEMO_PW}"}'),
                               variables={"DEMO_PW": "alice-pass"})
    before = mod.LOGINS["count"]
    res = conformance.run(spec, cfg, tmp_path)
    assert res.status == "ok", res.note
    assert mod.LOGINS["count"] > before  # the Schemathesis subprocess logged in through the hooks file
    # the endpoint answers 401 to anyone not logged in; 200/404 means the login token was accepted
    codes = {(e["response"] or {}).get("status") for e in iter_entries(cfg.testlog.path)}
    assert codes & {200, 404}


@pytest.mark.slow
@pytest.mark.e2e
def test_real_conformance_can_be_stopped(demo_api, tmp_path, monkeypatch):
    base, _ = demo_api
    monkeypatch.chdir(tmp_path)
    cancel = threading.Event()
    cfg = _real_cfg(base, tmp_path, cancel=cancel, max_examples=200)

    def on_progress(ev):
        cfg.got.append(ev)
        if ev["msg"].startswith("Now running:"):
            cancel.set()
    cfg.on_progress = on_progress
    t = time.time()
    with pytest.raises(Cancelled):
        conformance.run(load_spec(cfg.spec), cfg, tmp_path)
    assert time.time() - t < 60
    assert msgs(cfg)[-1].startswith("Logged ")


@pytest.mark.slow
@pytest.mark.e2e
def test_real_conformance_unreachable_spec(tmp_path, monkeypatch):
    pytest.importorskip("schemathesis")
    monkeypatch.chdir(tmp_path)
    base = f"http://127.0.0.1:{_free_port()}"
    res = conformance.run(spec_of(base=base), cfg_of(spec=base + "/openapi.json", max_examples=1), tmp_path)
    assert res.status == "error" and res.note.startswith("Schemathesis ran no tests: ")
    assert len(res.note) > len("Schemathesis ran no tests: ")
