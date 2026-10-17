"""Refusals sent as HTTP 200 with an error body, access reasons from the server's own words, lenient null
findings, and saved working examples per API."""
import json

import httpx

from sprat import coverage, triage
from sprat.config import Config
from sprat.explain import failure_body
from sprat.models import Finding
from sprat.spec import Operation, Spec, apply_examples
from sprat.stages import authz
from sprat.stages import conformance as C
from sprat.stages import types as T
from sprat.testlog import TestLog, iter_entries

from test_coverage_report import A, _build, op
from test_stage_types import BASE, OAS, body_op, obj, run_stage

FAILED = {"status": "Failed", "message": "API key is required", "id": 0, "data": None}


# ---------------- failure_body ----------------

def test_failure_body_reads_the_usual_shapes():
    assert failure_body(json.dumps(FAILED)) == "API key is required"
    assert failure_body('{"success": false, "errorMessage": "Invalid WorkflowId"}') == "Invalid WorkflowId"
    assert failure_body('{"isSuccess": false}') == "the response body says the request failed"
    assert failure_body('{"Status": "ERROR", "Detail": "no"}') == "no"


def test_failure_body_ignores_success_and_non_objects():
    for body in ('{"errorMessage": "Successfully created."}', '{"status": "Success", "message": null}',
                 '{"success": true}', '[{"status": "Failed"}]', '"Success"', "", None, "not json {"):
        assert failure_body(body) == "", body


# ---------------- types stage ----------------

def test_types_wrong_types_refused_with_200_are_passes_plus_one_low_finding(monkeypatch, tmp_path):
    schema = obj({"qty": {"type": "integer"}}, ["qty"])

    def api(r):
        body = json.loads(r.content)
        return httpx.Response(200, json={"status": "Success", "id": 5} if isinstance(body["qty"], int)
                              and not isinstance(body["qty"], bool) else {"status": "Failed", "message": "Input is invalid"})
    cfg = Config(base_url=BASE)
    cfg.testlog = TestLog(tmp_path / "log.ndjson")
    res, _ = run_stage(monkeypatch, tmp_path, api, [body_op(schema, example={"qty": 1})], cfg=cfg)
    assert [f.title for f in res.findings] == ["Reports errors with HTTP 200 instead of 4xx"]
    assert res.findings[0].severity == "low" and "Input is invalid" in res.findings[0].detail
    probes = [e for e in iter_entries(tmp_path / "log.ndjson") if not e["scenario"].startswith("Valid")]
    assert probes and all(e["verdict"] == "pass" and e["details"]["error_200"] == "Input is invalid" for e in probes)


def test_types_baseline_refused_with_200_skips_the_api(monkeypatch, tmp_path):
    cfg = Config(base_url=BASE)
    cfg.testlog = TestLog(tmp_path / "log.ndjson")
    res, calls = run_stage(monkeypatch, tmp_path, lambda r: httpx.Response(200, json=FAILED),
                           [body_op(obj({"qty": {"type": "integer"}}), example={"qty": 1})], cfg=cfg)
    assert len(calls) == 1 and res.findings[0].severity == "info"
    assert res.findings[0].title.endswith("got HTTP 200 with an error body")
    base = next(iter_entries(tmp_path / "log.ndjson"))
    assert base["verdict"] == "error" and "API key is required" in base["explanation"]
    assert "access problem" in base["explanation"]


def test_types_baseline_hint_points_to_saved_examples(monkeypatch, tmp_path):
    cfg = Config(base_url=BASE)
    cfg.testlog = TestLog(tmp_path / "log.ndjson")
    run_stage(monkeypatch, tmp_path, lambda r: httpx.Response(404, json={"title": "No record found"}),
              [body_op(obj({"qty": {"type": "integer"}}), example={"qty": 1})], cfg=cfg)
    assert "✎ Example" in next(iter_entries(tmp_path / "log.ndjson"))["explanation"]


# ---------------- conformance stage ----------------

def _scenario(status, body, checks, mode="negative"):
    return {"phase": "coverage", "recorder": {
        "cases": {"c1": {"value": {"id": "c1", "method": "POST", "path": "/t",
                                   "meta": {"generation": {"mode": mode}, "phase": {"data": {"description": "bad"}}}}}},
        "interactions": {"c1": {"request": {"method": "POST", "uri": "http://x/t", "headers": {}},
                                "response": {"status_code": status, "headers": {},
                                             "content": json.dumps(body)}, "timestamp": 1}},
        "checks": {"c1": [{"name": n, "status": "failure", "failure_info": {"failure": {"title": n}}} for n in checks]}}}


def test_conformance_refusal_checks_answered_with_an_error_body_are_dropped():
    c = next(C.scenario_cases(_scenario(200, FAILED, ["negative_data_rejection", "status_code_conformance"])))
    assert c["refused_200"] == ["negative_data_rejection"] and c["error_200"] == "API key is required"
    assert len(c["failures"]) == 1 and "200" in c["failures"][0]  # the undocumented status still counts
    c = next(C.scenario_cases(_scenario(200, {"id": 1}, ["negative_data_rejection"])))
    assert c["refused_200"] == [] and c["real_refusal_fails"] == ["negative_data_rejection"] and c["failures"]


def test_conformance_findings_swap_to_one_error_200_finding():
    f = [Finding("conformance", "medium", "API accepted schema-violating request", "POST /t"),
         Finding("conformance", "high", "API accepts requests without authentication", "POST /t"),
         Finding("conformance", "medium", "API accepted schema-violating request", "POST /u")]
    stats = {"POST /t": {"negative_data_rejection": {"error_200": 3, "real": 0, "example": "e"},
                         "ignored_auth": {"error_200": 1, "real": 2}},
             "POST /u": {"negative_data_rejection": {"error_200": 0, "real": 4}}}
    out = C._error_200_findings(f, stats)
    assert [(x.title, x.endpoint) for x in out] == [
        ("API accepts requests without authentication", "POST /t"),  # also had real failures: kept
        ("API accepted schema-violating request", "POST /u"),
        ("Reports errors with HTTP 200 instead of 4xx", "POST /t")]
    assert out[-1].severity == "low" and out[-1].detail.startswith("4 request(s)")


# ---------------- authz stage ----------------

def test_authz_refusal_with_200_and_error_body_is_not_a_bypass(monkeypatch, tmp_path):
    from test_stage_authz import cfg_of, entries, fake as _fake  # noqa: F401
    api = httpx.MockTransport(lambda r: httpx.Response(200, json=FAILED, headers={"x-content-type-options": "nosniff"}))
    monkeypatch.setattr(authz, "client_for", lambda base, **kw: httpx.Client(transport=api))
    cfg = cfg_of(tmp_path)
    res = authz.run(Spec({}, BASE, "openapi3", BASE, [Operation("get", "/t", True, False)]), cfg, tmp_path)
    assert not [f for f in res.findings if f.severity == "critical"]
    es = entries(cfg)
    assert all(e["verdict"] == "pass" and "error body" in e["explanation"] for e in es)


# ---------------- coverage: writes and access reasons ----------------

def test_write_count_leaves_out_refusals_sent_as_200(tmp_path):
    cov = _build(tmp_path, [op("post", "/w")], {"stages": ["types"], "headers": A}, None,
                 ("types", "POST /w", "s", "pass", 200, {"body": json.dumps(FAILED)}),
                 ("types", "POST /w", "s", "fail", 201, {"body": '{"id": 3}'}))
    w = next(w for w in cov["warnings"] if "write request" in w)
    assert w.startswith("1 write request(s)") and "1 more that got HTTP 2xx" in w


def test_access_reason_uses_what_the_server_said(tmp_path):
    cov = _build(tmp_path, [op("post", "/k", secured=True)], {"stages": ["types"], "headers": A}, None,
                 ("types", "POST /k", "Valid request first", "error", 200, {"body": json.dumps(FAILED)}))
    acc = cov["apis"][0]["access"]
    assert acc["status"] == "blocked" and "needs an API key" in acc["reason"]
    assert 'the server said "API key is required"' in acc["reason"]


def test_access_issue_hidden_behind_a_400(tmp_path):
    cov = _build(tmp_path, [op("post", "/u", secured=True)], {"stages": ["types"], "headers": A}, None,
                 ("types", "POST /u", "Valid request first", "error", 400, {"body": '{"title": "User is not authorized."}'}))
    acc = cov["apis"][0]["access"]
    assert acc["status"] == "blocked" and "isn't allowed to use this API" in acc["reason"]
    plain = _build(tmp_path / "x", [op("post", "/u")], {"stages": ["types"], "headers": A}, None,
                   ("types", "POST /u", "Valid request first", "error", 400, {"body": '{"title": "Input is invalid"}'}))
    assert plain["apis"][0]["access"]["status"] == "ok"


# ---------------- triage ----------------

def test_null_accepted_is_a_swagger_problem_in_lenient_mode():
    e = {"stage": "types", "verdict": "fail", "scenario": "s", "response": {"status": 200},
         "details": {"field": "x", "sent_value": None, "required": True, "problem": "wrong type accepted"}}
    assert triage.triage_entry(e)["severity"] == "medium"
    assert triage.triage_entry(e, lenient=True)["severity"] == "info"
    r = [type("R", (), {"name": "types", "findings": [Finding("types", "medium", "Field `x` (string, required) accepted null")]})()]
    assert triage.apply_lenient(r) == 1 and r[0].findings[0].severity == "info"


def test_error_200_refusals_form_their_own_root_cause_group():
    es = [{"stage": "types", "verdict": "pass", "scenario": "s", "response": {"status": 200},
           "details": {"error_200": "Input is invalid"}}] * 3
    s = triage.summarize({"POST /t": es})
    g = s["causes"][0]
    assert (g["cause"], g["tests"], g["severity"]) == ("error_as_200", 3, "low") and s["top"] == []
    assert triage.finding_cause("types", "Reports errors with HTTP 200 instead of 4xx") == "error_as_200"


# ---------------- saved examples ----------------

RAW = {"openapi": "3.0.1", "paths": {
    "/items/{id}": {"parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                    "put": {"parameters": [{"name": "v", "in": "query", "schema": {"type": "string"}}],
                            "requestBody": {"$ref": "#/components/requestBodies/Item"}}},
    "/other": {"get": {}}},
    "components": {"requestBodies": {"Item": {"content": {"application/json": {
        "schema": {"type": "object"}, "examples": {"a": {"value": {"name": "swagger"}}}}}}}}}


def _spec():
    ops = [Operation("put", "/items/{id}", False, True, {"id": "1"}, {}, RAW["paths"]["/items/{id}"]["put"],
                     [{"name": "id", "in": "path"}, {"name": "v", "in": "query"}]),
           Operation("get", "/other", False, False, op=RAW["paths"]["/other"]["get"])]
    return Spec(json.loads(json.dumps(RAW)), "s", "openapi3", BASE, ops, json.dumps(RAW), json.dumps(RAW))


def test_apply_examples_writes_body_path_and_query_into_a_copy():
    s = _spec()
    out = apply_examples(s, {"PUT /items/{id}": {"body": {"name": "real"}, "path": {"id": 42}, "query": {"v": "x"}},
                             "GET /nope": {"body": {}}})
    o = next(o for o in out.operations if o.label == "PUT /items/{id}")
    assert T.body_schema(out.raw, o)[1] == {"name": "real"}  # replaces the Swagger's own examples
    assert o.path_params == {"id": "42"} and o.query_params == {"v": "x"}
    params = {(p["in"], p["name"]): p.get("example") for p in out.raw["paths"]["/items/{id}"]["put"]["parameters"]}
    assert params == {("path", "id"): "42", ("query", "v"): "x"}
    assert out.modified and out.full_text == s.full_text and json.loads(out.text) == out.raw
    assert s.raw == RAW and "example" not in json.dumps(s.raw["paths"])  # the original is untouched
    assert apply_examples(s, {}) is s and apply_examples(s, {"GET /nope": {"body": {}}}) is s


def test_types_stage_starts_from_the_saved_example(monkeypatch, tmp_path):
    raw = {"openapi": "3.0.1", "paths": {"/items": {"post": {"requestBody": {"content": {"application/json": {
        "schema": obj({"site": {"type": "string"}, "qty": {"type": "integer"}}), "example": {"site": "nope", "qty": 1}}}}}}}}
    ops = [Operation("post", "/items", False, True, op=raw["paths"]["/items"]["post"])]
    spec = apply_examples(Spec(raw, "s", "openapi3", BASE, ops), {"POST /items": {"body": {"site": "NDHR1", "qty": 2}}})
    seen = []

    def api(r):
        b = json.loads(r.content)
        seen.append(b)
        return httpx.Response(201 if b.get("site") == "NDHR1" and isinstance(b.get("qty"), int) else 400)
    monkeypatch.setattr(T, "client_for", lambda base, **kw: httpx.Client(transport=httpx.MockTransport(api), **kw))
    cfg = Config(base_url=BASE, examples={"POST /items": {}})
    cfg.testlog = TestLog(tmp_path / "log.ndjson")
    res = T.run(spec, cfg, tmp_path)
    assert seen[0] == {"site": "NDHR1", "qty": 2} and len(seen) > 1 and "1 operation(s) probed" in res.note
    base = next(iter_entries(tmp_path / "log.ndjson"))
    assert base["scenario"].endswith("your saved example") and base["details"]["example_source"] == "project"
