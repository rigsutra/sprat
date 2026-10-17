"""Live progress parsing for ZAP and Schemathesis."""
import json

from sprat.config import Config
from sprat.stages import zap
from sprat.stages.conformance import _Live

ZAP_LOG = """2026-10-02 10:35:35,757 Starting ZAP
2026-10-02 10:35:48,058 Starting new HTTP connection (1): localhost:43174
2026-10-02 10:37:52,677 Set max pscan alerts
2026-10-02 10:37:54,626 Number of Imported URLs: 8
2026-10-02 10:37:59,761 Active Scan progress %: 21
2026-10-02 10:38:09,790 Active Scan complete
2026-10-02 10:38:09,831 Records to scan...
2026-10-02 10:38:09,839 Passive scanning complete
Total of 39 URLs""".splitlines()


def _collect():
    got = []
    return got, Config(on_progress=got.append)


def test_zap_log_lines_become_progress():
    got, cfg = _collect()
    zap._live(cfg, ZAP_LOG)
    msgs = [g["msg"] for g in got]
    assert msgs == ["ZAP is starting up (usually 1–3 minutes)", "ZAP is up; importing the API definition",
                    "Imported 8 URLs from the spec", "Active scan: attacking the APIs 21%",
                    "Active scan complete 100%", "Passive scan: analysing responses",
                    "Passive scan complete; writing the report", "Finished: 39 URLs checked"]
    assert got[3]["done"] == 21 and got[3]["total"] == 100


class _FakeTail:
    def __init__(self, events):
        self.events = events

    def lines(self):
        out, self.events = [json.dumps(e) for e in self.events], []
        return out


def _scenario(label, phase, method, path, mode, desc, status, failed_check=None):
    checks = [{"name": "not_a_server_error", "status": "success"}]
    if failed_check:
        checks.append({"name": failed_check, "status": "failure", "failure_info": {"failure": {"title": "x"}}})
    return {"ScenarioFinished": {"status": "failure" if failed_check else "success", "phase": phase, "recorder": {
        "label": label,
        "cases": {"c1": {"value": {"method": method, "path": path, "id": "c1", "meta": {
            "generation": {"mode": mode}, "phase": {"data": {"description": desc}}}}}},
        "interactions": {"c1": {"request": {"method": method, "uri": "http://x" + path},
                                "response": {"status_code": status}}},
        "checks": {"c1": checks}}}}


def test_schemathesis_events_become_plain_progress():
    got, cfg = _collect()
    events = [
        {"PhaseStarted": {"phase": {"name": "probing", "is_enabled": True}}},
        {"PhaseStarted": {"phase": {"name": "coverage", "is_enabled": True}}},
        _scenario("POST /items", "coverage", "POST", "/items", "negative", "in_stock: Incorrect type", 200,
                  "negative_data_rejection"),
        {"ScenarioFinished": {"status": "skip", "recorder": {"label": "GET /a"}}},
        _scenario("GET /b", "coverage", "GET", "/b", "positive", "", 200),
        {"PhaseStarted": {"phase": {"name": "stateful", "is_enabled": True}}},
        _scenario("STATEFUL tests", "stateful", "GET", "/b", "positive", "", 200),
    ]
    _Live(cfg, 3, _FakeTail(events)).tick()
    simple = [(g["op"], g["msg"], g["done"], g["level"]) for g in got]
    assert simple[0][0] == "" and simple[0][1].startswith("Now running: Edge cases.")
    assert simple[1] == ("POST /items", "Edge cases: `in_stock` has the wrong type → got HTTP 200. Accepted invalid "
                                        "input (HTTP 200). It should have refused it with a 4xx.", 1, "bad")
    assert simple[2] == ("GET /b", "Edge cases: 1 request sent, all checks passed", 2, "ok")
    assert simple[3][1].startswith("Now running: Request chains.")
    assert simple[4] == ("", "Request chains: 1 request sent, all checks passed", None, "ok")
