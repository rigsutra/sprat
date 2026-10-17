"""Self-contained HTML report: data embedding, grouping, escaping of hostile content."""
import json
import re

import pytest

from sprat import htmlreport
from sprat.explain import FINDING_TITLES, PHASES, STAGES
from sprat.models import SEVERITIES
from sprat.testlog import TestLog

HOSTILE = '</script><script>alert(1)</script><img src=x onerror=alert(2)>'


def _data(html_text):
    m = re.search(r'<script type="application/json" id="data">(.*?)</script>', html_text, re.S)
    assert m, "data block missing"
    return json.loads(m.group(1))  # "<\/" is a valid JSON escape for "</"


def _api(op, verdict="ok", path=None, tests=None):
    method, p = op.split(" ", 1)
    return {"operation": op, "method": method.lower(), "path": path or p, "summary": "", "secured": False,
            "excluded": verdict == "excluded", "verdict": verdict, "counts": {}, "tests": tests or []}


def _build(tmp_path, meta=None, cov=None, report=None, entries=()):
    if report is not None:
        (tmp_path / "report.json").write_text(json.dumps(report), encoding="utf-8")
    if entries:
        tl = TestLog(tmp_path / "test-log.ndjson")
        for e in entries:
            tl.add(**e)
    out = htmlreport.build(tmp_path, meta or {}, cov or {})
    text = out.read_text(encoding="utf-8")
    return out, text, _data(text)


def test_empty_run_still_renders(tmp_path):
    out, text, d = _build(tmp_path)
    assert out == tmp_path / "test-report.html"
    assert text.startswith("<!doctype html>") and "<title>API test report — sprat</title>" in text
    assert "__DATA__" not in text and "__TITLE__" not in text
    assert d["apis"] == [] and d["warnings"] == [] and d["tests"] == {} and d["findings"] == {}
    assert d["run"]["id"] == tmp_path.name and d["run"]["project"] == "" and d["run"]["stages"] == {}
    assert d["run"]["user_a"] is False and d["run"]["selected"] == []
    assert set(d["stage_info"]) == set(STAGES)
    assert set(d["phase_info"]) == set(PHASES) - {"probing"}
    assert "https://" not in text and "<script src" not in text and 'rel="stylesheet"' not in text  # offline


def test_meta_and_stage_status(tmp_path):
    report = {"spec": "from-report.json", "base_url": "http://api.test", "stages": [
        {"name": "authz", "status": "ok", "note": "n", "findings": [], "duration": 1.5},
        {"name": "zap", "status": "skipped", "findings": []}]}
    meta = {"id": "r1", "project_name": "Shop", "status": "done", "started": 1, "finished": 2,
            "operations": ["GET /a"], "headers": {"Authorization": "***"}, "headers_b": {}}
    _, text, d = _build(tmp_path, meta, {"warnings": ["Read me"]}, report)
    r = d["run"]
    assert (r["id"], r["project"], r["spec"], r["base_url"], r["status"]) == ("r1", "Shop", "from-report.json",
                                                                              "http://api.test", "done")
    assert r["selected"] == ["GET /a"] and r["user_a"] is True and r["user_b"] is False
    assert r["stages"] == {"authz": {"status": "ok", "note": "n", "findings": 0, "duration": 1.5},
                           "zap": {"status": "skipped", "note": "", "findings": 0, "duration": 0}}
    assert d["warnings"] == ["Read me"] and "API test report — Shop" in text
    _, _, d2 = _build(tmp_path, {"spec": "meta-spec"}, {}, report)
    assert d2["run"]["spec"] == "meta-spec"


def test_findings_of_every_severity_grouped_per_api(tmp_path):
    raw_title = next(iter(FINDING_TITLES))
    findings = [{"severity": s, "title": raw_title, "operation": "GET /a", "detail": "d" * 2000} for s in SEVERITIES]
    findings.append({"severity": "high", "title": "Global thing", "operation": "", "detail": None})
    report = {"stages": [{"name": "conformance", "status": "ok", "findings": findings}]}
    _, _, d = _build(tmp_path, {}, {"apis": [_api("GET /a", "problems")]}, report)
    fs = d["findings"]["GET /a"]
    assert [f["severity"] for f in fs] == SEVERITIES
    assert all(f["title"] == FINDING_TITLES[raw_title] and len(f["detail"]) == 1500 and f["stage"] == "conformance"
               for f in fs)
    assert d["findings"][""] == [{"stage": "conformance", "severity": "high", "title": "Global thing", "detail": "",
                                  "fix": "See the failed test's explanation.", "spec_issue": False}]
    assert "Validate input" in fs[0]["fix"] and fs[0]["spec_issue"] is False  # "Server error" -> crash fix
    assert d["run"]["stages"]["conformance"]["findings"] == len(findings)


def test_tests_grouped_and_unknown_methods_moved_to_their_path(tmp_path):
    entries = [
        dict(stage="authz", scenario="ok", operation="GET /a", verdict="pass",
             request={"method": "GET", "url": "http://x/a", "headers": {"A": "1"}}, response={"status": 200, "body": "{}"}),
        dict(stage="conformance", scenario="method probe", operation="TRACE /a", verdict="fail",
             request={"method": "TRACE", "url": "http://x/a"}, response={"status": 200}),
        dict(stage="conformance", scenario="unknown url", operation="GET /nowhere", verdict="info"),
        dict(stage="lint", scenario="global", verdict="info"),
    ]
    _, _, d = _build(tmp_path, {}, {"apis": [_api("GET /a"), _api("POST /a")]}, entries=entries)
    ga = d["tests"]["GET /a"]
    assert [t["scenario"] for t in ga] == ["ok", "method probe"]  # first API on that path gets it
    assert "TRACE /a" not in d["tests"] and "GET /nowhere" not in d["tests"]
    assert {t["scenario"] for t in d["tests"][""]} == {"unknown url", "global"}
    t0 = ga[0]
    assert t0["req"] == {"method": "GET", "url": "http://x/a", "headers": {"A": "1"}, "body": None}
    assert t0["res"] == {"status": 200, "headers": {}, "body": "{}", "ms": None}
    assert [t for t in d["tests"][""] if t["scenario"] == "global"][0]["req"] is None


def test_long_bodies_are_cut(tmp_path):
    body = "z" * (htmlreport.BODY_LIMIT + 500)
    _, _, d = _build(tmp_path, {}, {"apis": [_api("POST /a")]}, entries=[dict(
        stage="types", scenario="s", operation="POST /a", request={"method": "POST", "url": "u", "body": body},
        response={"status": 400, "body": body})])
    t = d["tests"]["POST /a"][0]
    for b in (t["req"]["body"], t["res"]["body"]):
        assert b.startswith("z" * htmlreport.BODY_LIMIT) and b.endswith("[500 more characters in the NDJSON download]")
    assert htmlreport._cut(None) is None and htmlreport._cut("") == "" and htmlreport._cut("abc") == "abc"


def test_hostile_content_is_escaped(tmp_path):
    """A malicious API (or spec) must not be able to run script in the report."""
    op = f"GET /x{HOSTILE}"
    entries = [dict(stage="authz", scenario=HOSTILE, operation=op, verdict="fail", explanation=HOSTILE,
                    request={"method": "GET", "url": f"http://x/{HOSTILE}", "headers": {HOSTILE: HOSTILE}},
                    response={"status": 500, "body": HOSTILE, "headers": {"X": HOSTILE}})]
    report = {"stages": [{"name": "authz", "status": "ok", "findings": [
        {"severity": "high", "title": HOSTILE, "operation": op, "detail": HOSTILE}]}]}
    meta = {"project_name": HOSTILE, "spec": HOSTILE, "status": HOSTILE}
    cov = {"warnings": [HOSTILE], "apis": [_api(op, "problems", path=f"/x{HOSTILE}")]}
    _, text, d = _build(tmp_path, meta, cov, report, entries)
    assert text.count("</script>") == 2  # only the template's own two script blocks are closed
    assert "alert(1)</script>" not in text and "<img src=x" not in text.split('id="data">')[0]
    title = re.search(r"<title>(.*?)</title>", text, re.S).group(1)
    assert "<" not in title and "&lt;/script&gt;" in title
    # the data still round-trips exactly
    assert d["run"]["project"] == HOSTILE and d["warnings"] == [HOSTILE]
    assert d["tests"][op][0]["scenario"] == HOSTILE and d["tests"][op][0]["res"]["body"] == HOSTILE
    assert d["findings"][op][0]["title"] == HOSTILE
    # the page renders text via createTextNode / setAttribute, never innerHTML with data
    js = text.split('<script>', 1)[1]
    assert "html:" not in js.replace('"html"', "")


def test_html_comment_opener_in_content_cannot_break_the_data_block(tmp_path):
    body = "<!doctype html><!--[if lt IE 9]><script src=old.js>"  # cut off before the closing -->
    _, text, _ = _build(tmp_path, {}, {"apis": [_api("GET /a")]}, entries=[dict(
        stage="authz", scenario="s", operation="GET /a", response={"status": 404, "body": body})])
    blob = text.split('id="data">', 1)[1].split("</script>", 1)[0]
    assert "<!--" not in blob and "<script" not in blob


def test_unicode_everywhere(tmp_path):
    name = "Café ✓ 日本語 — Ünïcode"
    entries = [dict(stage="authz", scenario="Prüfung ✓", operation="GET /ü", verdict="pass",
                    response={"status": 200, "body": '{"name": "Zoë 🚀"}'})]
    out, text, d = _build(tmp_path, {"project_name": name}, {"apis": [_api("GET /ü")]}, entries=entries)
    assert f"API test report — {name}" in text
    assert "Zoë 🚀" in text  # stored as UTF-8, not \u escapes
    assert name.encode("utf-8") in out.read_bytes()
    assert d["tests"]["GET /ü"][0]["scenario"] == "Prüfung ✓"


def test_rebuild_overwrites(tmp_path):
    _build(tmp_path, {"project_name": "one"})
    _, text, _ = _build(tmp_path, {"project_name": "two"})
    assert "— two" in text and "— one" not in text
