"""Per-API coverage: every stage's status rules, verdicts, run-level warnings, CSV/JSON output."""
import csv
import io
import json

import pytest

from sprat import coverage
from sprat.spec import Operation
from sprat.testlog import TestLog

ALL = ["lint", "conformance", "types", "authz", "zap"]
OK = {s: {"status": "ok"} for s in ALL}
A = {"Authorization": "***"}


def op(method, path, secured=False, body=False, params=None, summary=""):
    path_params = {n: "1" for n in __import__("re").findall(r"{(\w+)}", path)}
    return Operation(method, path, secured, body, path_params, {}, {"summary": summary} if summary else {},
                     params or [])


def _log(tmp_path, *entries):
    """entries: (stage, op, scenario, verdict, status, extra) ; extra = dict for add()."""
    tl = TestLog(tmp_path / "test-log.ndjson")
    for e in entries:
        stage, o, scen, verdict, status = e[:5]
        extra = dict(e[5]) if len(e) > 5 else {}
        method = o.split()[0] if o else "GET"
        tl.add(stage, scen, operation=o, verdict=verdict, request={"method": method, "url": "http://x"},
               response={"status": status, "body": extra.pop("body", None)} if status is not None else None, **extra)
    return tmp_path / "test-log.ndjson"


def _build(tmp_path, ops, settings, results=None, *entries):
    return coverage.build(ops, settings, OK if results is None else results, _log(tmp_path, *entries))


def _tests(cov, label):
    a = next(a for a in cov["apis"] if a["operation"] == label)
    return {t["test"]: t for t in a["tests"]}


def test_no_operations(tmp_path):
    cov = _build(tmp_path, [], {"stages": ALL, "headers": A, "headers_b": A})
    assert cov["apis"] == [] and cov["totals"] == {}
    assert cov["warnings"] == ["No cross-user scenarios are configured, so no API was checked for one user reading "
                               "another user's data (BOLA). Add some under Settings → Cross-user scenarios."]


def test_no_stages_means_ok_and_no_warnings(tmp_path):
    cov = _build(tmp_path, [op("get", "/a")], {})
    assert cov["apis"][0]["verdict"] == "ok" and cov["apis"][0]["tests"] == [] and cov["warnings"] == []
    assert cov["totals"] == {"ok": 1}


def test_all_excluded(tmp_path):
    ops = [op("get", "/a"), op("post", "/a/b", body=True)]
    cov = _build(tmp_path, ops, {"stages": ["lint", "authz", "custom"], "exclude_paths": ["^/a"]})
    assert cov["totals"] == {"excluded": 2}
    for a in cov["apis"]:
        assert a["excluded"] and [t["test"] for t in a["tests"]] == ["Swagger quality", "Access control", "custom"]
        assert all(t["status"] == "not_tested" and "Excluded" in t["reason"] for t in a["tests"])


def test_invalid_exclude_pattern_is_ignored(tmp_path):
    cov = _build(tmp_path, [op("get", "/a")], {"stages": ["lint"], "exclude_paths": ["(", "^/zzz$"]})
    assert cov["apis"][0]["verdict"] == "ok"
    assert coverage._valid("(") is False and coverage._valid("^/a$") is True


def test_selection_hides_unselected_but_keeps_excluded(tmp_path):
    ops = [op("get", "/a"), op("get", "/b"), op("get", "/c")]
    cov = _build(tmp_path, ops, {"stages": ["lint"], "operations": ["GET /a"], "exclude_paths": ["^/c$"]})
    assert [(a["operation"], a["verdict"]) for a in cov["apis"]] == [("GET /a", "ok"), ("GET /c", "excluded")]


@pytest.mark.parametrize("status,note,start", [
    ("skipped", "Docker is not running", "The test was skipped: Docker is not running."),
    ("error", "boom", "The test tool failed: boom."),
    ("error", "", "The test tool failed."),
    ("cancelled", "ignored note", "The run was stopped before this test reached this API."),
])
def test_stage_that_did_not_run(tmp_path, status, note, start):
    cov = _build(tmp_path, [op("get", "/a")], {"stages": ["zap"]}, {"zap": {"status": status, "note": note}})
    t = _tests(cov, "GET /a")["Security scan (OWASP ZAP)"]
    assert t["status"] == "not_tested" and t["reason"] == start
    assert cov["apis"][0]["verdict"] == "incomplete"
    w = cov["warnings"][-1]
    assert w.startswith("Security scan (OWASP ZAP) ")
    assert {"skipped": "didn't run", "error": "failed to run", "cancelled": "was stopped"}[status] in w


def test_stopped_stage_with_some_requests_still_counts_them(tmp_path):
    cov = _build(tmp_path, [op("get", "/a")], {"stages": ["lint"]}, {"lint": {"status": "cancelled"}},
                 ("lint", "GET /a", "rule", "fail", None))
    assert _tests(cov, "GET /a")["Swagger quality"]["status"] == "tested"


def test_missing_stage_result_is_treated_as_ran(tmp_path):
    cov = _build(tmp_path, [op("get", "/a")], {"stages": ["lint"]}, {})
    assert _tests(cov, "GET /a")["Swagger quality"]["status"] == "tested"


def test_unrecorded_stage_of_old_run(tmp_path):
    cov = _build(tmp_path, [op("get", "/a")], {"stages": ["authz", "lint"], "unrecorded_stages": ["authz", "lint"]},
                 {"authz": {"status": "ok", "note": "3 findings"}, "lint": {"status": "ok"}},
                 ("lint", "GET /a", "rule", "pass", None))
    t = _tests(cov, "GET /a")
    assert t["Access control"]["status"] == "not_recorded" and "3 findings" in t["Access control"]["reason"]
    assert t["Swagger quality"]["status"] == "tested"  # it had entries
    assert cov["apis"][0]["verdict"] == "incomplete"
    cov2 = _build(tmp_path, [op("get", "/a")], {"stages": ["authz"], "unrecorded_stages": ["authz"]})
    assert "summary: none" in _tests(cov2, "GET /a")["Access control"]["reason"]


def test_lint(tmp_path):
    cov = _build(tmp_path, [op("get", "/a"), op("get", "/b")], {"stages": ["lint"]}, None,
                 ("lint", "GET /a", "r1", "fail", None), ("lint", "GET /a", "r2", "fail", None),
                 ("lint", "GET /a", "r3", "pass", None))
    a, b = _tests(cov, "GET /a")["Swagger quality"], _tests(cov, "GET /b")["Swagger quality"]
    assert (a["reason"], a["requests"], a["failed"]) == ("2 Swagger rule problem(s) for this API.", 3, 2)
    assert b["reason"] == "No Swagger rule problems for this API." and b["requests"] == 0
    assert {x["operation"]: x["verdict"] for x in cov["apis"]} == {"GET /a": "problems", "GET /b": "ok"}
    assert cov["totals"] == {"problems": 1, "ok": 1}


def test_conformance_not_tested_and_tested(tmp_path):
    ops = [op("get", "/a"), op("get", "/b"), op("get", "/c")]
    cov = _build(tmp_path, ops, {"stages": ["conformance"], "headers": A}, None,
                 ("conformance", "GET /b", "s", "pass", 200), ("conformance", "GET /b", "s", "pass", 404),
                 ("conformance", "GET /c", "s", "fail", 500), ("conformance", "GET /c", "s", "pass", None))
    name = "Behaviour vs Swagger"
    assert _tests(cov, "GET /a")[name] == {"stage": "conformance", "test": name, "status": "not_tested",
                                           "reason": "Schemathesis sent no requests to this API.",
                                           "requests": 0, "failed": 0}
    b = _tests(cov, "GET /b")[name]
    assert b["status"] == "tested" and b["reason"] == "2 requests (responses: 200×1, 404×1); all checks passed."
    c = _tests(cov, "GET /c")[name]
    assert c["reason"] == "2 requests (responses: 500×1, None×1). 1 failed a check." and c["failed"] == 1


def test_secured_api_that_only_saw_refusals(tmp_path):
    ops = [op("get", "/s", secured=True)]
    entries = [("conformance", "GET /s", "s", "pass", 401)] * 3 + [("conformance", "GET /s", "s", "pass", 422),
                                                                   ("conformance", "GET /s", "s", "fail", 503)]
    no_token = _build(tmp_path, ops, {"stages": ["conformance"]}, None, *entries)
    t = _tests(no_token, "GET /s")["Behaviour vs Swagger"]
    assert t["status"] == "partial" and "because no token was set for user A" in t["reason"]
    assert "3 refused with 401/403, 1 rejected as invalid input before the login check, 1 crashed the server" \
        in t["reason"]
    assert no_token["warnings"][0].startswith("No token was set for user A, but 1 of 1 APIs require login.")
    refused = _build(tmp_path, ops, {"stages": ["conformance"], "headers": A}, None,
                     *[("conformance", "GET /s", "s", "pass", 401)] * 10)
    t = _tests(refused, "GET /s")["Behaviour vs Swagger"]
    assert "user A's token was refused" in t["reason"]
    assert refused["warnings"][0].startswith("User A's token was refused for almost every request")


def test_secured_api_with_some_accepted_is_tested(tmp_path):
    cov = _build(tmp_path, [op("get", "/s", secured=True)], {"stages": ["conformance"], "headers": A}, None,
                 *[("conformance", "GET /s", "s", "pass", 401)] * 8, ("conformance", "GET /s", "s", "pass", 200))
    assert _tests(cov, "GET /s")["Behaviour vs Swagger"]["status"] == "tested"
    assert not any("refused for almost every" in w for w in cov["warnings"])  # 8/9 < 90 %


def test_missing_permission_variants(tmp_path):
    perm = lambda key, val: {"body": json.dumps({key: val})}
    entries = [("conformance", "GET /s", "s", "error", 403, perm("requiredScopes", ["read:s"])),
               ("conformance", "GET /s", "s", "error", 403, perm("required_scopes", ["write:s"])),
               ("conformance", "GET /s", "s", "error", 403, {"body": "not json"}),
               ("conformance", "GET /s", "s", "error", 403, {"body": "[1, 2]"}),
               ("conformance", "GET /s", "s", "error", 403, perm("required", "not-a-list")),
               ("conformance", "", "s", "error", 403, perm("required", ["admin"])),
               ("conformance", "GET /s", "s", "error", 401, perm("required", ["ignored:401"]))]
    cov = _build(tmp_path, [op("get", "/s", secured=True)], {"stages": ["conformance"], "headers": A}, None, *entries)
    w = cov["warnings"][0]
    assert "`admin` (needed by ?)" in w and "`read:s` (needed by GET /s)" in w and "`write:s`" in w
    assert "ignored:401" not in w
    reason = _tests(cov, "GET /s")["Behaviour vs Swagger"]["reason"]
    assert "lacks the permission `read:s`, `write:s`" in reason


def test_more_401_than_403_blames_the_token_not_permissions(tmp_path):
    body = {"body": json.dumps({"required": ["p"]})}
    cov = _build(tmp_path, [op("get", "/s", secured=True)], {"stages": ["conformance"], "headers": A}, None,
                 ("conformance", "GET /s", "s", "error", 403, body), *[("conformance", "GET /s", "s", "pass", 401)] * 2)
    assert "user A's token was refused" in _tests(cov, "GET /s")["Behaviour vs Swagger"]["reason"]


@pytest.mark.parametrize("method,body,want", [("get", False, "No request body"), ("delete", True, "No request body"),
                                              ("post", False, "No request body"), ("put", True, "isn't JSON")])
def test_types_not_applicable(tmp_path, method, body, want):
    cov = _build(tmp_path, [op(method, "/t", body=body)], {"stages": ["types"]})
    t = _tests(cov, f"{method.upper()} /t")["Wrong data types"]
    assert t["status"] == "not_applicable" and want in t["reason"]
    assert cov["apis"][0]["verdict"] == "ok"  # not applicable doesn't make it incomplete


def test_types_base_request_refused(tmp_path):
    cov = _build(tmp_path, [op("post", "/t", body=True)], {"stages": ["types"]}, None,
                 ("types", "POST /t", "Valid request first (all correct)", "error", 401,
                  {"explanation": "Refused with 401"}),
                 ("types", "POST /t", "Field x", "pass", 400))
    t = _tests(cov, "POST /t")["Wrong data types"]
    assert t["status"] == "not_tested" and t["reason"] == "Refused with 401"
    assert t["requests"] == 2 and t["failed"] == 0


def test_types_base_refused_without_explanation(tmp_path):
    log = tmp_path / "test-log.ndjson"
    tl = TestLog(log)
    tl.add("types", "Valid request first", operation="PATCH /t", verdict="fail")
    cov = coverage.build([op("patch", "/t", body=True)], {"stages": ["types"]}, OK, log)
    assert _tests(cov, "PATCH /t")["Wrong data types"]["reason"] == "The valid request was refused."


def test_types_probes(tmp_path):
    f = lambda name: {"details": {"field": name}}
    cov = _build(tmp_path, [op("post", "/t", body=True), op("put", "/u", body=True)], {"stages": ["types"]}, None,
                 ("types", "POST /t", "Valid request first", "pass", 201),
                 ("types", "POST /t", "qty as string", "fail", 201, f("qty")),
                 ("types", "POST /t", "qty as bool", "pass", 400, f("qty")),
                 ("types", "POST /t", "name as int", "pass", 400, f("name")),
                 ("types", "PUT /u", "a as int", "pass", 422, f("a")))
    t = _tests(cov, "POST /t")["Wrong data types"]
    assert t["reason"] == "2 field(s), 3 wrong-type requests; 1 were wrongly accepted or crashed the server."
    assert (t["requests"], t["failed"]) == (4, 1)
    assert _tests(cov, "PUT /u")["Wrong data types"]["reason"] == "1 field(s), 1 wrong-type requests; all were refused."


def test_authz_secured(tmp_path):
    ops = [op("get", "/s", secured=True), op("get", "/t", secured=True), op("get", "/u", secured=True)]
    cov = _build(tmp_path, ops, {"stages": ["authz"], "headers": A, "headers_b": A}, None,
                 ("authz", "GET /s", "no token", "pass", 401), ("authz", "GET /s", "fake token", "pass", 401),
                 ("authz", "GET /t", "no token", "fail", 200), ("authz", "GET /t", "fake token", "pass", 401))
    assert _tests(cov, "GET /s")["Login required"]["reason"].endswith("both were refused.")
    t = _tests(cov, "GET /t")["Login required"]
    assert "1 of 2 were wrongly served" in t["reason"] and t["failed"] == 1
    assert _tests(cov, "GET /u")["Login required"]["status"] == "not_tested"


def test_authz_public(tmp_path):
    ops = [op("post", "/w"), op("get", "/r"), op("get", "/q"), op("get", "/none")]
    cov = _build(tmp_path, ops, {"stages": ["authz"]}, None,
                 ("authz", "GET /r", "headers", "pass", 200), ("authz", "GET /q", "headers", "fail", 200))
    w = _tests(cov, "POST /w")["Public API checks"]
    assert w["status"] == "not_tested" and "to avoid writing data" in w["reason"]
    assert _tests(cov, "GET /r")["Public API checks"]["reason"].endswith("; no problems.")
    assert _tests(cov, "GET /q")["Public API checks"]["reason"].endswith("; 1 problem(s).")
    n = _tests(cov, "GET /none")["Public API checks"]
    assert n["status"] == "not_tested" and n["reason"] == "No request was sent to this API."


def test_bola(tmp_path):
    ops = [op("get", "/o/{id}"), op("get", "/p/{id}"), op("get", "/e/{id}"), op("get", "/q", params=[
        {"name": "orderId", "in": "query"}]), op("get", "/h", params=[{"name": "page", "in": "query"},
                                                                       {"name": "id", "in": "header"}])]
    bola = [{"method": "get", "path": "/o/{id}?x=1"}, {"path": "/p/{id}"}]
    cov = _build(tmp_path, ops, {"stages": ["authz"], "headers": A, "headers_b": A, "bola": bola}, None,
                 ("authz", "GET /o/{id}", "Cross-user: A reads", "pass", 200),
                 ("authz", "GET /o/{id}", "Cross-user: B reads", "fail", 200),
                 ("authz", "GET /p/{id}", "Cross-user: A reads", "pass", 200),
                 ("authz", "GET /p/{id}", "Cross-user: B reads", "pass", 403),
                 ("authz", "GET /e/{id}", "Cross-user: A reads", "error", 404, {"explanation": "A can't read it"}))
    o = _tests(cov, "GET /o/{id}")["Cross-user (BOLA)"]
    assert (o["status"], o["reason"], o["requests"], o["failed"]) == ("tested", "User B could read user A's data.", 2, 1)
    assert _tests(cov, "GET /p/{id}")["Cross-user (BOLA)"]["reason"] == "User B was refused, as it should be."
    e = _tests(cov, "GET /e/{id}")["Cross-user (BOLA)"]
    assert e["status"] == "not_tested" and e["reason"] == "A can't read it"
    q = _tests(cov, "GET /q")["Cross-user (BOLA)"]
    assert q["status"] == "not_tested" and "no user B" not in q["reason"]
    assert "Cross-user (BOLA)" not in _tests(cov, "GET /h")  # no ID-like path/query parameter
    assert not any("BOLA" in w for w in cov["warnings"])  # B set and scenarios configured


def test_bola_error_without_explanation_and_no_user_b(tmp_path):
    cov = _build(tmp_path, [op("get", "/e/{id}"), op("get", "/n/{key}")], {"stages": ["authz"]}, None,
                 ("authz", "GET /e/{id}", "Cross-user", "error", None))
    assert _tests(cov, "GET /e/{id}")["Cross-user (BOLA)"]["reason"] == ""
    assert "and no user B is set" in _tests(cov, "GET /n/{key}")["Cross-user (BOLA)"]["reason"]
    assert any(w.startswith("No second user (user B)") for w in cov["warnings"])


def test_zap(tmp_path):
    cov = _build(tmp_path, [op("get", "/a"), op("get", "/b")], {"stages": ["zap"]}, None,
                 ("zap", "GET /a", "XSS", "fail", 200), ("zap", "GET /a", "Info", "info", 200))
    a = _tests(cov, "GET /a")["Security scan (OWASP ZAP)"]
    assert (a["reason"], a["requests"], a["failed"]) == ("ZAP raised 1 alert(s) for this API.", 2, 1)
    assert "no alerts were raised" in _tests(cov, "GET /b")["Security scan (OWASP ZAP)"]["reason"]


def test_unknown_stage_adds_no_item(tmp_path):
    cov = _build(tmp_path, [op("get", "/a")], {"stages": ["custom"]})
    assert cov["apis"][0]["tests"] == [] and cov["apis"][0]["verdict"] == "ok"


def test_successful_writes_warning_counts_only_2xx_writes(tmp_path):
    cov = _build(tmp_path, [op("post", "/w", body=True)], {"stages": ["conformance"], "headers": A}, None,
                 ("conformance", "POST /w", "s", "pass", 201), ("conformance", "DELETE /w", "s", "pass", 204),
                 ("conformance", "PUT /w", "s", "pass", 400), ("conformance", "GET /w", "s", "pass", 200),
                 ("conformance", "PATCH /w", "s", "pass", None))
    assert any(w.startswith("2 write request(s)") for w in cov["warnings"])


def test_api_fields_and_counts(tmp_path):
    cov = _build(tmp_path, [op("get", "/a", secured=True, summary="List A")], {"stages": ["lint"]}, None,
                 ("lint", "GET /a", "r", "fail", None), ("lint", "GET /a", "r", "pass", None),
                 ("lint", "GET /a", "r", "info", None))
    a = cov["apis"][0]
    assert {k: a[k] for k in ("operation", "method", "path", "summary", "secured", "excluded", "verdict")} == \
        {"operation": "GET /a", "method": "get", "path": "/a", "summary": "List A", "secured": True,
         "excluded": False, "verdict": "problems"}
    assert a["counts"] == {"fail": 1, "pass": 1, "info": 1}


def test_write_json_and_csv(tmp_path):
    cov = {"warnings": [], "totals": {}, "apis": [{"operation": "GET /a", "verdict": "incomplete", "tests": [
        coverage._item("authz", "Login required", "not_tested", 'No request, "quoted", with, commas\nand ✓', 0, 0),
        coverage._item("lint", "Swagger quality", "tested", "fine", 3, 1)]}, {"operation": "GET /b", "verdict": "ok",
                                                                               "tests": []}]}
    coverage.write(cov, tmp_path)
    assert json.loads((tmp_path / "coverage.json").read_text(encoding="utf-8")) == cov
    raw = (tmp_path / "coverage.csv").read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")
    rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
    assert [r["test"] for r in rows] == ["Login required", "Swagger quality"]  # API without tests: no rows
    assert rows[0] == {"api": "GET /a", "overall": "incomplete", "access": "ok", "test": "Login required",
                       "status": "not_tested",
                       "requests": "0", "failed": "0", "reason": 'No request, "quoted", with, commas\nand ✓'}
    assert rows[1]["requests"] == "3" and rows[1]["failed"] == "1"


def test_warning_order_no_token_beats_permission_and_stage_warnings_last(tmp_path):
    cov = _build(tmp_path, [op("get", "/s", secured=True)], {"stages": ["conformance", "authz", "zap"]},
                 {"conformance": {"status": "ok"}, "authz": {"status": "ok"}, "zap": {"status": "skipped",
                                                                                     "note": "  no docker  "}},
                 ("conformance", "GET /s", "s", "pass", 401))
    w = cov["warnings"]
    assert w[0].startswith("No token was set") and w[1].startswith("No second user")
    assert w[-1] == "Security scan (OWASP ZAP) didn't run: no docker"


def test_no_token_warning_needs_conformance_stage(tmp_path):
    cov = _build(tmp_path, [op("get", "/s", secured=True)], {"stages": ["lint"]})
    assert cov["warnings"] == []
