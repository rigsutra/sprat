"""Root causes, severities, recommended fixes, report priorities, lenient mode and per-API access status."""
from sprat import coverage, triage
from sprat.models import Finding, StageResult

from test_coverage_report import A, ALL, _build, op


def entry(stage, verdict="fail", status=200, scenario="s", **details):
    return {"stage": stage, "verdict": verdict, "scenario": scenario, "expected": "",
            "response": {"status": status, "body": details.pop("body", None)}, "details": details}


def conf(*checks, status=200):
    return entry("conformance", status=status, checks=[{"name": c, "status": "failure"} for c in checks])


# ---------------- failed tests ----------------

def test_server_error_is_high_and_wins_over_spec_mismatches():
    t = triage.triage_entry(conf("status_code_conformance", "not_a_server_error", status=500))
    assert (t["cause"], t["severity"], t["spec_issue"]) == ("server_error", "high", False)
    assert t["causes"] == ["server_error", "undocumented_status"] and "Validate input" in t["fix"]


def test_a_repeated_crash_without_a_failed_check_is_still_a_server_error():
    assert triage.triage_entry(entry("conformance", status=502))["cause"] == "server_error"


def test_wrong_type_is_medium_null_depends_on_required_crash_is_high():
    coerced = entry("types", field="qty", sent_value="1", required=True, problem="wrong type accepted")
    assert triage.triage_entry(coerced)["severity"] == "medium"
    assert "strict" in triage.triage_entry(coerced)["fix"]
    null_req = entry("types", field="qty", sent_value=None, required=True, problem="wrong type accepted")
    null_opt = entry("types", field="qty", sent_value=None, required=False, problem="wrong type accepted")
    assert [triage.triage_entry(e)["cause"] for e in (null_req, null_opt)] == ["null_accepted"] * 2
    assert [triage.triage_entry(e)["severity"] for e in (null_req, null_opt)] == ["medium", "low"]
    crash = entry("types", status=500, field="qty", sent_value="1", problem="server crashed (5xx)")
    assert triage.triage_entry(crash)["severity"] == "high"


def test_authz_causes():
    bypass = entry("authz", scenario="Protected API called with no credentials", passive_issues=[])
    bola = entry("authz", scenario="Cross-user check, step 2: user B tries to read user A's data")
    passive = entry("authz", scenario="Public API: response checked",
                    passive_issues=["Missing security header: X-Content-Type-Options",
                                    "CORS allows any origin with credentials"])
    assert triage.triage_entry(bypass)["severity"] == "critical"
    assert triage.triage_entry(bola)["cause"] == "bola"
    t = triage.triage_entry(passive)
    assert t["causes"] == ["cors", "missing_security_header"] and t["severity"] == "high"


def test_lint_and_zap_keep_their_own_severity_and_zap_uses_its_solution():
    assert triage.triage_entry(entry("lint", severity="low"))["severity"] == "low"
    z = dict(entry("zap", risk="high"), expected="Escape the output.")
    assert triage.triage_entry(z)["severity"] == "high" and triage.triage_entry(z)["fix"] == "Escape the output."


def test_only_failed_tests_get_a_severity():
    assert triage.triage_entry(entry("conformance", verdict="pass")) == {}
    assert triage.triage_entry(entry("conformance", verdict="error", status=401)) == {}


def test_lenient_turns_pure_spec_mismatches_into_info_but_not_real_bugs():
    spec_only = conf("status_code_conformance", "response_schema_conformance")
    assert triage.triage_entry(spec_only)["severity"] == "medium"
    assert triage.triage_entry(spec_only, lenient=True)["severity"] == "info"
    mixed = conf("status_code_conformance", "not_a_server_error", status=500)
    assert triage.triage_entry(mixed, lenient=True)["severity"] == "high"
    coerced = entry("types", field="qty", sent_value="1", problem="wrong type accepted")
    assert triage.triage_entry(coerced, lenient=True)["severity"] == "medium"


# ---------------- findings ----------------

def test_finding_causes_and_fixes():
    cases = {("conformance", "Server error"): "server_error",
             ("conformance", "Undocumented HTTP status code"): "undocumented_status",
             ("conformance", "API accepted schema-violating request"): "invalid_input_accepted",
             ("types", "Field `qty` (integer) accepted wrong types: numeric string"): "wrong_type_accepted",
             ("types", "Field `qty` (integer) crashed the server on wrong type"): "server_error",
             ("authz", "Secured endpoint accepted no credentials (HTTP 200)"): "auth_bypass",
             ("authz", "BOLA: user B accessed user A's resource"): "bola",
             ("lint", "operation-tags: Operation must have tags"): "swagger_rule",
             ("zap", "SQL Injection"): "zap_alert"}
    for (stage, title), cause in cases.items():
        assert triage.finding_cause(stage, title) == cause, title
    assert triage.finding_cause("types", "Type probing skipped: valid baseline body got HTTP 401", "info") == ""
    rep = triage.enrich_report({"stages": [{"name": "conformance", "findings": [{"severity": "low",
                                                                                   "title": "Undocumented HTTP status code"}]}]})
    f = rep["stages"][0]["findings"][0]
    assert f["cause"] == "undocumented_status" and f["spec_issue"] and "Add the status code" in f["fix"]
    assert triage.enrich_report({}) == {}


def test_apply_lenient_demotes_spec_findings_only():
    r = StageResult("conformance", findings=[Finding("conformance", "medium", "Response violates schema", "GET /a"),
                                             Finding("conformance", "high", "Server error", "GET /a")])
    lint = StageResult("lint", findings=[Finding("lint", "high", "oas3-schema: bad", "paths")])
    assert triage.apply_lenient([r, lint]) == 2
    assert [f.severity for f in r.findings + lint.findings] == ["info", "high", "info"]
    assert r.findings[0].detail.startswith("Swagger problem (lenient mode): would be medium")


# ---------------- report priorities ----------------

def test_summarize_groups_ranks_and_lists_crashes_and_wrong_types():
    by_op = {
        "POST /items": [conf("not_a_server_error", status=500) | {"response": {"status": 500, "body": '{"detail":"boom"}'}},
                        entry("types", field="qty", sent_value="1", problem="wrong type accepted"),
                        entry("types", field="qty", sent_value=True, problem="wrong type accepted"),
                        entry("types", field="name", sent_value=123, problem="wrong type accepted"),
                        entry("types", verdict="pass", status=400)],
        "GET /health": [conf("status_code_conformance")],
        "GET /ok": [entry("conformance", verdict="pass")],
        "": [entry("lint", severity="medium")],
    }
    s = triage.summarize(by_op)
    assert [g["cause"] for g in s["causes"]] == ["server_error", "wrong_type_accepted", "swagger_rule",
                                                "undocumented_status"]
    wt = s["causes"][1]
    assert wt["tests"] == 3 and wt["apis"] == [{"operation": "POST /items", "fails": 3}] and "strict" in wt["fix"]
    assert [t["operation"] for t in s["top"]] == ["POST /items", "GET /health"]  # "" (no API) isn't ranked
    assert s["top"][0] == {"operation": "POST /items", "fails": 4, "worst": "high",
                           "causes": ["Accepts values of the wrong type", "Crashes with a server error (HTTP 5xx)"]}
    assert s["crashes"] == [{"operation": "POST /items", "requests": 1, "codes": [500], "server_said": "boom",
                             "stages": ["conformance"]}]
    assert s["wrong_types"] == [{"operation": "POST /items", "requests": 3, "fields": {"qty": ["1", True], "name": [123]}}]


def test_summarize_top_is_at_most_ten_and_lenient_puts_swagger_problems_last():
    by_op = {f"GET /a{i}": [conf("response_schema_conformance")] * (i + 1) for i in range(12)}
    by_op["GET /crash"] = [conf("not_a_server_error", status=500)]
    s = triage.summarize(by_op, lenient=True)
    assert len(s["top"]) == 10 and s["top"][0]["operation"] == "GET /a11"
    assert [g["cause"] for g in s["causes"]] == ["server_error", "response_schema"]
    assert s["causes"][1]["severity"] == "info" and s["causes"][1]["spec_issue"]


# ---------------- access status per API ----------------

def test_access_blocked_when_every_real_request_was_refused(tmp_path):
    cov = _build(tmp_path, [op("get", "/s", secured=True)], {"stages": ALL, "headers": A}, None,
                 ("conformance", "GET /s", "s", "error", 403, {"body": '{"required": ["read:s"]}'}),
                 ("conformance", "GET /s", "s", "error", 403),
                 ("authz", "GET /s", "Protected API called with no credentials", "pass", 401))
    acc = cov["apis"][0]["access"]
    assert acc["status"] == "blocked" and acc["refused"] == 2 and acc["reached"] == 0
    assert acc["reason"].startswith("Not tested due to an access issue") and "`read:s`" in acc["reason"]


def test_access_partial_marks_the_behaviour_test_partly_tested(tmp_path):
    cov = _build(tmp_path, [op("get", "/s", secured=True)], {"stages": ["conformance"], "headers": A}, None,
                 ("conformance", "GET /s", "s", "error", 401), ("conformance", "GET /s", "s", "pass", 200),
                 ("conformance", "GET /s", "s", "pass", 200))
    a = cov["apis"][0]
    assert a["access"]["status"] == "partial" and a["access"]["reason"].startswith(
        "Partly not tested due to an access issue: 1 of 3 requests")
    t = a["tests"][0]
    assert t["status"] == "partial" and "1 of the 3 requests were refused with 401/403" in t["reason"]


def test_access_ok_when_only_login_checks_got_401(tmp_path):
    cov = _build(tmp_path, [op("get", "/s", secured=True)], {"stages": ALL, "headers": A}, None,
                 ("authz", "GET /s", "Protected API called with no credentials", "pass", 401),
                 ("conformance", "GET /s", "s", "pass", 200))
    assert cov["apis"][0]["access"]["status"] == "ok"
    assert coverage._access(op("get", "/x"), [], True)["status"] == "ok"


def test_access_blocked_without_any_token_but_login_probes_dont_count(tmp_path):
    cov = _build(tmp_path, [op("get", "/s", secured=True)], {"stages": ["conformance"]}, None,
                 ("conformance", "GET /s", "Edge cases: valid request", "pass", 401),
                 ("conformance", "GET /s", "Edge cases: missing `Authorization` header", "pass", 401),
                 ("conformance", "GET /s", "Edge cases: Unspecified HTTP method: PUT", "pass", 405))
    acc = cov["apis"][0]["access"]
    assert acc["status"] == "blocked" and acc["refused"] == 1 and "no token was set for user A" in acc["reason"]
