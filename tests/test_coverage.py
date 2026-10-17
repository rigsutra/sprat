import json

from sprat import coverage
from sprat.spec import Operation
from sprat.testlog import TestLog


def _ops():
    return [
        Operation("get", "/sites", True, False, query_params={}, params=[{"name": "siteId", "in": "query"}]),
        Operation("post", "/ingress", True, True, op={"requestBody": {}}),
        Operation("get", "/health", False, False),
        Operation("post", "/recalc", True, True),
    ]


def _log(tmp_path, entries):
    tl = TestLog(tmp_path / "test-log.ndjson")
    for stage, op, scen, verdict, status in entries:
        tl.add(stage, scen, operation=op, verdict=verdict, explanation=f"{scen} -> {status}",
               request={"method": op.split()[0], "url": "http://x" + op.split()[1]}, response={"status": status})
    return tmp_path / "test-log.ndjson"


def test_no_token_is_called_out_per_api_and_for_the_run(tmp_path):
    log = _log(tmp_path, [("conformance", "GET /sites", "Edge cases: x", "pass", 401)] * 20 +
                         [("types", "POST /ingress", "Valid request first (every field the correct type)", "error", 401)])
    cov = coverage.build(_ops(), {"stages": ["conformance", "types", "authz"], "headers": {}, "headers_b": {},
                                  "bola": [], "exclude_paths": ["^/recalc$"]},
                         {"conformance": {"status": "ok"}, "types": {"status": "ok"}, "authz": {"status": "ok"}}, log)
    apis = {a["operation"]: a for a in cov["apis"]}
    sites = {t["test"]: t for t in apis["GET /sites"]["tests"]}
    assert sites["Behaviour vs Swagger"]["status"] == "partial"
    assert "no token was set" in sites["Behaviour vs Swagger"]["reason"]
    assert sites["Cross-user (BOLA)"]["status"] == "not_tested"  # takes siteId but no scenario
    assert sites["Wrong data types"]["status"] == "not_applicable"
    ingress = {t["test"]: t for t in apis["POST /ingress"]["tests"]}
    assert ingress["Wrong data types"]["status"] == "not_tested"
    assert apis["POST /recalc"]["verdict"] == "excluded"
    assert all(t["status"] == "not_tested" and "Excluded" in t["reason"] for t in apis["POST /recalc"]["tests"])
    assert apis["GET /sites"]["verdict"] == "incomplete"
    assert cov["warnings"][0].startswith("No token was set for user A")
    assert any("No second user" in w for w in cov["warnings"])
    coverage.write(cov, tmp_path)
    assert "partial" in (tmp_path / "coverage.csv").read_text(encoding="utf-8-sig")
    assert json.loads((tmp_path / "coverage.json").read_text())["apis"]


def test_missing_permission_is_named(tmp_path):
    tl = TestLog(tmp_path / "test-log.ndjson")
    body = json.dumps({"required": ["read:aggregation"], "detail": "Insufficient scope", "error": "INSUFFICIENT_SCOPE"})
    for _ in range(10):
        tl.add("conformance", "Random data: valid request", operation="GET /sites", verdict="error",
               request={"method": "GET", "url": "http://x/sites", "headers": {"Authorization": "Bearer t"}},
               response={"status": 403, "body": body})
    cov = coverage.build(_ops(), {"stages": ["conformance"], "headers": {"login": "auto"}},
                         {"conformance": {"status": "ok"}}, tmp_path / "test-log.ndjson")
    assert "doesn't have permission" in cov["warnings"][0] and "`read:aggregation` (needed by GET /sites)" in cov["warnings"][0]
    sites = next(a for a in cov["apis"] if a["operation"] == "GET /sites")
    reason = next(t for t in sites["tests"] if t["test"] == "Behaviour vs Swagger")["reason"]
    assert "lacks the permission `read:aggregation`" in reason


def test_blocked_and_method_probe_explanations():
    from sprat.explain import blocked_by_auth, expected_for, permission_detail
    assert "Not really tested" in blocked_by_auth(403, "positive", "Random data", True)
    assert blocked_by_auth(401, "negative", "Missing `Authorization` at header", True) == ""  # an auth test itself
    assert blocked_by_auth(403, "positive", "x", False) == ""  # no credentials sent: an expected refusal
    assert expected_for("positive", "Unspecified HTTP method: PUT").startswith("405 Method Not Allowed")
    assert permission_detail('{"required": ["read:aggregation"]}') == "missing permission `read:aggregation`"


def test_successful_writes_are_warned_about(tmp_path):
    log = _log(tmp_path, [("conformance", "POST /ingress", "Random data: valid request", "pass", 201)])
    cov = coverage.build(_ops(), {"stages": ["conformance"], "headers": {"Authorization": "***"}},
                         {"conformance": {"status": "ok"}}, log)
    assert any("write request(s)" in w for w in cov["warnings"])


def test_repeated_server_error_without_failures_is_not_a_pass(tmp_path):
    """Schemathesis reports a repeated failure once; later identical 500s carry no failures."""
    from types import SimpleNamespace
    from sprat.stages.conformance import log_scenarios
    event = {"ScenarioFinished": {"phase": "stateful", "recorder": {
        "cases": {"c1": {"value": {"id": "c1", "method": "POST", "path": "/items", "meta": {}}}},
        "interactions": {"c1": {"request": {"method": "POST", "uri": "http://x/items", "headers": {}},
                                "response": {"status_code": 500, "content": None}}},
        "checks": {"c1": [{"name": "not_a_server_error", "status": "success"}]}}}}
    events = tmp_path / "events.ndjson"
    events.write_text(json.dumps(event) + "\n", encoding="utf-8")
    tl = TestLog(tmp_path / "test-log.ndjson")
    assert log_scenarios(SimpleNamespace(testlog=tl), events) == 1
    row = json.loads((tmp_path / "test-log.ndjson").read_text(encoding="utf-8").splitlines()[0])
    assert row["verdict"] == "fail" and "crashed (HTTP 500)" in row["explanation"]
