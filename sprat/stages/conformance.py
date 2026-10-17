"""Type safety / conformance + fuzzing via Schemathesis."""
from __future__ import annotations

import json
import os
import re
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from ..models import Finding, StageResult
from ..proc import Tail, progress, run_cmd
from ..tls import ca_bundle
from ..explain import (PHASES, blocked_by_auth, describe_case, expected_for, explain_check, failure_body,
                       permission_detail, phase_label, server_said)
from ..testlog import b64_or_text, log_of


def run(spec, cfg, out: Path) -> StageResult:
    res = StageResult("conformance")
    base = cfg.base_url or spec.base_url
    if not base:
        res.status, res.note = "error", "No base URL (pass --base-url)"
        return res
    junit = out / "schemathesis-junit.xml"
    events = out / "schemathesis-events.ndjson"
    if cfg.spec.startswith("http") and not spec.from_page and not spec.filtered and not spec.modified:
        schema_arg = cfg.spec
    else:  # local file, spec embedded in a Swagger UI page, reduced to selected operations, or with saved examples
        schema_arg = str(out / "spec.json")
        (out / "spec.json").write_text(spec.text, encoding="utf-8")
    cmd = [sys.executable, "-m", "schemathesis.cli", "run", schema_arg, "--url", base,
           "--checks", "all", "--max-examples", str(cfg.max_examples),
           "--continue-on-failure", "--no-color",
           "--report", "junit,ndjson", "--report-junit-path", str(junit),
           "--report-ndjson-path", str(events), "--tls-verify", ca_bundle()]
    for k, v in cfg.headers.items():
        cmd += ["-H", f"{k}: {v}"]
    for pat in cfg.exclude_paths:
        cmd += ["--exclude-path-regex", pat]
    # Schemathesis chokes on PYTHONIOENCODING values like "utf-8:surrogateescape" (Windows)
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1",
           "REQUESTS_CA_BUNDLE": ca_bundle()}  # also covers loading the schema from its URL
    if cfg.auth_a is not None:
        # Automatic login: a hooks file gives Schemathesis a token provider that renews the token
        # 30 s before it expires, so long runs don't drift into 401s
        hooks = out / "sprat_auth_hooks.py"
        hooks.write_text(AUTH_HOOKS, encoding="utf-8")
        env["SCHEMATHESIS_HOOKS"] = str(hooks)
        # ${NAME}s are filled in here: the subprocess has no access to the project's secret store.
        # The values live only in that process's environment, never in a file.
        env["SPRAT_LOGIN_A"] = json.dumps(cfg.auth_a.resolved())
    junit.unlink(missing_ok=True)
    events.unlink(missing_ok=True)
    progress(cfg, "conformance", "Starting Schemathesis", total=len(spec.operations))
    live = _Live(cfg, len(spec.operations), Tail(events))
    stats: dict = {}  # per API: refusal checks that "failed" only because the refusal came back as HTTP 200
    try:
        p = run_cmd(cmd, cancel=cfg.cancel, timeout=1800, env=env, on_tick=lambda _lines: live.tick())
    finally:  # also on Stop: log whatever Schemathesis finished
        n = log_scenarios(cfg, events, stats)
        # the raw stream holds the real Authorization/API-key headers; the test log has them masked
        _remove(events)
        progress(cfg, "conformance", f"Logged {n} request(s) to the test log")
    (out / "schemathesis.log").write_text(p.stdout + "\n" + p.stderr, encoding="utf-8")
    root = ET.parse(junit).getroot() if junit.exists() else None
    if root is None or not list(root.iter("testcase")):
        # No test cases means Schemathesis itself failed; never report that as a clean pass
        res.status = "error"
        res.note = "Schemathesis ran no tests: " + (p.stderr or p.stdout).strip()[-600:]
        return res
    res.note = f"{len(list(root.iter('testcase')))} operation(s) tested"
    for case in root.iter("testcase"):
        name = case.get("name", "")
        for el in case.findall("failure") + case.findall("error"):
            res.findings += _split_checks(name, (el.text or el.get("message") or "").strip())
    res.findings = _error_200_findings(res.findings, stats)
    return res


# Checks that expect a refusal. An API that refuses with HTTP 200 and an error body fails them although it
# did refuse: that isn't "accepts invalid input" or "works without login", but one smaller problem.
REFUSAL_CHECKS = {"negative_data_rejection": "schema violating request", "ignored_auth": "authentication",
                  "missing_required_header": "missing header not rejected"}


def _error_200_findings(findings: list[Finding], stats: dict) -> list[Finding]:
    """Drop findings whose every failing case was a refusal sent as HTTP 200; add one finding per API for that."""
    out = []
    for f in findings:
        st = stats.get(f.endpoint) or {}
        check = next((c for c, t in REFUSAL_CHECKS.items() if t in _norm(f.title)), None)
        if check and st.get(check, {}).get("error_200") and not st.get(check, {}).get("real"):
            continue
        out.append(f)
    for op, st in stats.items():
        n = sum(v.get("error_200", 0) for v in st.values())
        if n:
            ex = next((v["example"] for v in st.values() if v.get("example")), "")
            out.append(Finding("conformance", "low", "Reports errors with HTTP 200 instead of 4xx", op,
                               f"{n} request(s) that should have been refused got HTTP 200 with an error in the "
                               f"body. Clients and monitoring read HTTP 200 as success. For example: {ex}"))
    return out


def _remove(path: Path) -> None:
    # After a Stop on Windows the killed process can hold the file for a moment; an error here
    # would also hide the Cancelled/TimeoutExpired being raised
    for _ in range(50):
        try:
            path.unlink(missing_ok=True)
            return
        except PermissionError:
            time.sleep(0.1)


AUTH_HOOKS = '''# Generated by sprat for this run: automatic login for Schemathesis.
import json
import os

import schemathesis

from sprat.auth import LoginConfig, TokenProvider

_provider = TokenProvider(LoginConfig.from_dict(json.loads(os.environ["SPRAT_LOGIN_A"])), "user A")


# refresh_interval=None: ask on every request; the provider itself renews 30 s before expiry.
# retry_on=[]: some tests expect 401 on purpose, so a 401 must not trigger a new login.
@schemathesis.auth(refresh_interval=None, retry_on=[])
class SpratLogin:
    def get(self, case, ctx):
        return _provider.headers()

    def set(self, case, data, ctx):
        case.headers = case.headers or {}
        case.headers.update(data)
'''


def scenario_cases(body: dict):
    """Yield one readable dict per request inside a Schemathesis ScenarioFinished event."""
    rec = body.get("recorder") or {}
    phase = body.get("phase", "")
    cases, inters, checks = rec.get("cases") or {}, rec.get("interactions") or {}, rec.get("checks") or {}
    for cid, inter in inters.items():
        case = (cases.get(cid) or {}).get("value") or {}
        meta = case.get("meta") or {}
        mode = (meta.get("generation") or {}).get("mode", "")
        desc = ((meta.get("phase") or {}).get("data") or {}).get("description") or ""
        rq, rs = inter.get("request") or {}, inter.get("response") or {}
        status = rs.get("status_code")
        ck = checks.get(cid) or []
        resp_body = b64_or_text(rs.get("content"))
        said_200 = failure_body(resp_body) if isinstance(status, int) and 200 <= status < 300 else ""
        failures, failures_raw, refused_200, real = [], [], [], []
        for c in ck:
            if c.get("status") == "failure":
                if said_200 and c.get("name") in REFUSAL_CHECKS:
                    refused_200.append(c.get("name"))  # it did refuse, only with the wrong status code
                    continue
                if c.get("name") in REFUSAL_CHECKS:
                    real.append(c.get("name"))
                f = (c.get("failure_info") or {}).get("failure") or {}
                failures.append(explain_check(c.get("name", ""), status, f))
                failures_raw.append(f"{f.get('title') or c.get('name')}: {(f.get('message') or '').strip()}")
        if failures and status and status >= 500 and server_said(resp_body):
            failures[0] = failures[0].split(" Server said:")[0] + f" Server said: {server_said(resp_body)}"
        sent = {k.lower() for k in (rq.get("headers") or {})}
        blocked = blocked_by_auth(status, mode, desc, bool(sent & {"authorization", "x-api-key", "cookie"}))
        if blocked:
            detail = permission_detail(resp_body)
            blocked += f" ({detail})" if detail else ""
        yield {
            "phase": phase, "mode": mode, "case_id": case.get("id"), "ts": inter.get("timestamp"),
            "operation": f"{(case.get('method') or rq.get('method', '')).upper()} {case.get('path', '')}".strip()
                         if case.get("path") else "",
            "scenario": describe_case(phase, mode, desc), "expected": expected_for(mode, desc),
            "blocked": blocked,
            "request": {"method": rq.get("method", ""), "url": rq.get("uri", ""), "headers": rq.get("headers"),
                        "body": b64_or_text(rq.get("body"))},
            "response": {"status": status, "headers": rs.get("headers"), "body": resp_body,
                         "elapsed_ms": round(rs["elapsed"] * 1000, 1) if rs.get("elapsed") is not None else None}
                        if rs else None,
            "checks": [{"name": c.get("name"), "status": "refused_with_200" if c.get("name") in refused_200
                        else c.get("status")} for c in ck],
            "failures": failures, "failures_raw": failures_raw,
            "error_200": said_200, "refused_200": refused_200, "real_refusal_fails": real,
        }


class _Live:
    """Turns Schemathesis's NDJSON event stream into progress updates people can read."""

    def __init__(self, cfg, total: int, tail: Tail):
        self.cfg, self.total, self.tail = cfg, total, tail
        self.phase, self.done = "", 0

    def tick(self) -> None:
        for line in self.tail.lines():
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if not isinstance(ev, dict) or not ev:
                continue
            kind, body = next(iter(ev.items()))
            if not isinstance(body, dict):
                continue
            if kind == "PhaseStarted":
                name = body.get("phase", {}).get("name", "")
                if body.get("phase", {}).get("is_enabled", True) and name != "probing":
                    self.phase, self.done = name, 0
                    progress(self.cfg, "conformance", f"Now running: {phase_label(name)}. "
                             f"{PHASES.get(name, ('', ''))[1]}", done=0, total=self.total)
            elif kind == "ScenarioFinished":
                label = (body.get("recorder") or {}).get("label", "")
                if not label or body.get("status") == "skip":
                    continue
                cases = list(scenario_cases(body))
                bad = [c for c in cases if c["failures"]]
                blocked = [c for c in cases if c["blocked"] and not c["failures"]]
                lost = [c for c in cases if c["response"] is None and not c["failures"]]
                head = phase_label(self.phase)
                level = "bad" if bad else "ok"
                if bad:
                    c = bad[0]
                    code = (c["response"] or {}).get("status")
                    text = f"{c['scenario']} → got HTTP {code}. {c['failures'][0]}"
                    if len(bad) > 1:
                        text += f" (+{len(bad) - 1} more failing request{'s' if len(bad) > 2 else ''})"
                elif lost:
                    text = (f"{head}: {len(lost)} of {len(cases)} request(s) got no response "
                            "(network error or timeout), so they weren't checked")
                    level = "warn"
                elif blocked and len(blocked) == len(cases):
                    text = f"{head}: all {len(cases)} request(s) were refused before being processed. {blocked[0]['blocked']}"
                    level = "warn"
                else:
                    text = f"{head}: {len(cases)} request{'s' if len(cases) != 1 else ''} sent, all checks passed"
                    if blocked:
                        text += f" ({len(blocked)} refused with 401/403, so not really tested)"
                if not re.match(r"^(GET|PUT|POST|DELETE|PATCH|HEAD|OPTIONS) /", label):
                    progress(self.cfg, "conformance", text, level=level)  # request chains aren't one API
                    continue
                self.done = min(self.done + 1, self.total)
                progress(self.cfg, "conformance", text, op=label, done=self.done, total=self.total, level=level)


def log_scenarios(cfg, events: Path, stats: dict | None = None) -> int:
    """Write every request Schemathesis made (from its NDJSON event stream) to the test log.
    stats, if given, collects per API the refusal checks that failed only because of an HTTP 200 error body."""
    tl = log_of(cfg)
    if tl is None or not events.is_file():
        return 0
    n = 0
    for line in events.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        body = ev.get("ScenarioFinished") if isinstance(ev, dict) else None
        if not body or not isinstance(body, dict):
            continue
        for c in scenario_cases(body):
            code = (c["response"] or {}).get("status")
            if stats is not None and c["operation"]:
                st = stats.setdefault(c["operation"], {})
                for name in c["refused_200"]:
                    x = st.setdefault(name, {"error_200": 0, "real": 0})
                    x["error_200"] += 1
                    x.setdefault("example", f'{c["scenario"]} → HTTP {code}, "{c["error_200"]}"')
                for name in c["real_refusal_fails"]:
                    st.setdefault(name, {"error_200": 0, "real": 0})["real"] += 1
            verdict = "fail" if c["failures"] else "pass"
            if c["failures"]:
                explanation = " ".join(c["failures"])
            elif c["response"] is None:
                explanation, verdict = ("No response came back (network error, timeout or refused connection), "
                                        "so nothing could be checked."), "error"
            elif isinstance(code, int) and code >= 500:
                # Schemathesis reports a repeated failure only once, so later identical crashes
                # (common in request chains) arrive with no failures attached. A 5xx is never a pass.
                explanation, verdict = (f"The server crashed (HTTP {code}). A server error is always a bug. "
                                        "This is a repeat of a crash already reported for this API."), "fail"
            elif c["blocked"]:
                # the checks "passed" only because the 401/403 is documented: nothing was really tested
                explanation, verdict = c["blocked"], "error"
            elif c["error_200"] and (c["mode"] == "negative" or c["refused_200"]):
                explanation = f'Refused, but with HTTP {code} and an error body ("{c["error_200"]}") instead of a 4xx.'
            elif c["error_200"]:
                # a valid request "answered" 200 with an error: the API's logic wasn't really exercised
                explanation, verdict = (f'Not really tested: HTTP {code}, but the body says the request failed '
                                        f'("{c["error_200"]}").'), "error"
            elif c["mode"] == "negative":
                explanation = f"Refused with HTTP {code}, as it should."
            else:
                explanation = f"Answered HTTP {code}; the response matches the Swagger."
            tl.add("conformance", c["scenario"], operation=c["operation"], expected=c["expected"],
                   verdict=verdict, ts=c["ts"], explanation=explanation,
                   request=c["request"], response=c["response"],
                   details={"phase": c["phase"], "phase_meaning": PHASES.get(c["phase"], ("", ""))[1],
                            "generation_mode": c["mode"], "case_id": c["case_id"], "checks": c["checks"],
                            "failures": c["failures"], "tool_messages": c["failures_raw"],
                            "error_200": c["error_200"]})
            n += 1
    return n


# Schemathesis check titles -> severity. Anything unlisted is "medium".
SEVERITY_BY_CHECK = [
    ("server error", "high"),
    ("without authentication", "high"),
    ("missing header not rejected", "high"),
    ("accepts invalid authentication", "high"),
    ("response violates schema", "medium"),
    ("schema-violating request", "medium"),
    ("undocumented content type", "low"),
    ("undocumented http status", "low"),
    ("unsupported method", "low"),
]


def _norm(title: str) -> str:
    """'Undocumented Content-Type' and 'undocumented content type' compare equal."""
    return re.sub(r"[\s_-]+", " ", title.lower())


def _split_checks(endpoint: str, text: str) -> list[Finding]:
    """One <failure> holds several numbered test cases, each listing checks as
    '- <title>' lines. Emit one finding per distinct check title."""
    blocks = re.split(r"(?m)^\d+\. Test Case ID: \S+\s*$", text)
    found: dict[str, list[str]] = {}
    for block in blocks:
        for title in re.findall(r"(?m)^- (.+)$", block):
            found.setdefault(title.strip(), []).append(block.strip())
    if not found and text:
        found["Check failed"] = [text]
    out = []
    for title, examples in found.items():
        sev = next((s for k, s in SEVERITY_BY_CHECK if _norm(k) in _norm(title)), "medium")
        detail = f"{len(examples)} failing case(s). First:\n\n{examples[0][:1500]}"
        out.append(Finding("conformance", sev, title, endpoint, detail))
    return out
