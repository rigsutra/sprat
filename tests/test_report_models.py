"""models.py (severities, dataclasses) and report.py (report.json / report.html)."""
import json
import re

import pytest

from sprat.models import SEVERITIES, Finding, StageResult, sev_rank
from sprat.report import COLORS, write_reports


# ---------- models ----------

def test_severities_are_ordered_lowest_first():
    assert SEVERITIES == ["info", "low", "medium", "high", "critical"]


@pytest.mark.parametrize("sev,rank", list(zip(SEVERITIES, range(5))))
def test_sev_rank_known(sev, rank):
    assert sev_rank(sev) == rank


@pytest.mark.parametrize("sev", ["", "HIGH", "High", "warning", "error", " high", "crit"])
def test_sev_rank_unknown_ranks_as_info(sev):
    assert sev_rank(sev) == 0


def test_sev_rank_is_monotonic():
    assert [sev_rank(s) for s in SEVERITIES] == sorted(sev_rank(s) for s in SEVERITIES)


def test_finding_defaults():
    f = Finding("lint", "low", "t")
    assert (f.endpoint, f.detail, f.operation) == ("", "", "")


def test_stage_result_defaults_and_independent_lists():
    a, b = StageResult("a"), StageResult("b")
    assert (a.status, a.note, a.findings, a.duration) == ("ok", "", [], 0.0)
    a.findings.append(Finding("a", "info", "x"))
    assert b.findings == []


# ---------- report ----------

def test_every_severity_has_a_color():
    assert set(COLORS) == set(SEVERITIES)


def _results():
    return [
        StageResult("lint", "ok", "linted", [Finding("lint", "low", "L1", "paths//a/get"),
                                             Finding("lint", "critical", "C1", "GET /a", "boom\nline2"),
                                             Finding("lint", "medium", "M1")], 1.25),
        StageResult("zap", "skipped", "docker not found"),
        StageResult("types", "error", "RuntimeError: x"),
    ]


def test_report_json_round_trips_all_fields(tmp_path):
    write_reports(tmp_path, "spec.json", "http://b", _results())
    d = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert d["spec"] == "spec.json" and d["base_url"] == "http://b"
    assert [s["name"] for s in d["stages"]] == ["lint", "zap", "types"]
    lint = d["stages"][0]
    assert lint["status"] == "ok" and lint["note"] == "linted" and lint["duration"] == 1.25
    assert lint["findings"][1] == {"stage": "lint", "severity": "critical", "title": "C1", "endpoint": "GET /a",
                                   "detail": "boom\nline2", "operation": ""}


def test_report_html_summary_counts_and_order(tmp_path):
    write_reports(tmp_path, "s", "b", _results())
    page = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert page.startswith("<!doctype html>")
    summary = re.findall(r"<b>(\d+)</b> (\w+)</span>", page)
    assert summary == [("1", "critical"), ("0", "high"), ("1", "medium"), ("1", "low"), ("0", "info")]


def test_report_html_findings_sorted_by_severity_desc(tmp_path):
    write_reports(tmp_path, "s", "b", _results())
    page = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert page.index(">CRITICAL<") < page.index(">MEDIUM<") < page.index(">LOW<")


def test_report_html_stage_headers_notes_and_tables(tmp_path):
    write_reports(tmp_path, "s", "b", _results())
    page = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "lint <small>[ok] 1.2s" in page or "lint <small>[ok] 1.3s" in page
    assert "3 finding(s)" in page and "zap <small>[skipped] 0.0s &middot; 0 finding(s)" in page
    assert "<p class=note>docker not found</p>" in page
    assert page.count("<table>") == 1  # only stages with findings get a table


def test_report_detail_becomes_details_element_only_when_present(tmp_path):
    write_reports(tmp_path, "s", "b", _results())
    page = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "<details><summary>C1</summary><pre>boom\nline2</pre></details>" in page
    assert "<td>L1</td>" in page and "<summary>L1" not in page


def test_report_html_escapes_everything(tmp_path):
    x = "<script>alert(1)</script>"
    r = [StageResult(x, x, x, [Finding("s", "high", x, x, x)])]
    write_reports(tmp_path, x, x, r)
    page = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "<script>" not in page and page.count("&lt;script&gt;") == 8


def test_report_empty_results(tmp_path):
    write_reports(tmp_path, "s", "", [])
    assert json.loads((tmp_path / "report.json").read_text())["stages"] == []
    page = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "<table>" not in page and "<h2>" not in page and "<b>0</b> critical" in page


def test_report_overwrites_previous(tmp_path):
    write_reports(tmp_path, "first", "", [])
    write_reports(tmp_path, "second", "", [])
    assert json.loads((tmp_path / "report.json").read_text())["spec"] == "second"


def test_report_is_utf8(tmp_path):
    write_reports(tmp_path, "spéc→", "", [StageResult("lint", note="naïve ✓")])
    assert "naïve ✓" in (tmp_path / "report.html").read_text(encoding="utf-8")
    assert json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))["spec"] == "spéc→"
