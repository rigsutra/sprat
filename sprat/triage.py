"""Root causes, severities and recommended fixes for findings and failed tests.

A finding (report.json) and a failed test (test log) are both mapped to one root cause, such as "the
server crashes" or "accepts the wrong type". The cause gives the severity of a failed test and the
recommended fix, and lets the report group problems across APIs.

Some causes only say the API and the Swagger disagree ("spec" causes). When the Swagger can't be
trusted (lenient mode), those become "Swagger problems" with severity info, so they're still listed
but don't bury the real bugs or fail the run.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .models import sev_rank


@dataclass(frozen=True)
class Cause:
    title: str
    severity: str
    fix: str
    spec: bool = False  # only means "the API and the Swagger disagree"; the Swagger may be the wrong one


CAUSES: dict[str, Cause] = {
    "server_error": Cause(
        "Crashes with a server error (HTTP 5xx)", "high",
        "Validate input before using it (type, range, required fields) and answer bad input with 400 and a "
        "Problem Details body. A 5xx usually means unvalidated input reached the database, or a null was "
        "dereferenced; the response body or the server log names the line."),
    "wrong_type_accepted": Cause(
        "Accepts values of the wrong type", "medium",
        "Add strict type handling: reject \"1\" for a number and \"true\" or 1 for a boolean with 400. "
        ".NET: don't enable JsonNumberHandling.AllowReadingFromString; validate DTOs. Express: validate the "
        "body with a schema (Zod, express-openapi-validator) instead of coercing values."),
    "null_accepted": Cause(
        "Accepts null where the Swagger doesn't allow it", "medium",
        "Reject null for these fields with 400, or mark them nullable in the Swagger if null is valid. "
        "ASP.NET: enable SupportNonNullableReferenceTypes so the Swagger shows which fields may be null.",
        spec=True),  # Swaggers often leave nullability out, so this is as likely a Swagger gap as a bug
    "error_as_200": Cause(
        "Reports errors with HTTP 200 instead of a 4xx", "low",
        "Answer refused requests with a 4xx status (400 for invalid input, 401/403 for login and permissions) "
        "together with the error body. Clients, retries and monitoring read HTTP 200 as success."),
    "auth_bypass": Cause(
        "Works without a valid login", "critical",
        "Require authentication on this API ([Authorize] in .NET, auth middleware in Express). If it really is "
        "public, mark it `security: []` in the Swagger."),
    "bola": Cause(
        "One user can read another user's data (BOLA)", "critical",
        "Check ownership in the handler: load the resource filtered by the current user's (or tenant's) ID and "
        "answer 404 when it isn't theirs. Being logged in is not enough."),
    "cors": Cause(
        "CORS allows any origin with credentials", "high",
        "Never combine Access-Control-Allow-Origin: * with credentials; allow-list the real front-end origins."),
    "leaks_internals": Cause(
        "Error responses leak internals (stack traces, SQL errors)", "medium",
        "Use a production error handler (UseExceptionHandler in .NET, an error middleware in Express) that "
        "returns Problem Details without stack traces, exception names or SQL."),
    "missing_security_header": Cause(
        "Missing security headers", "low",
        "Send X-Content-Type-Options: nosniff on every response (helmet() in Express, a header middleware in "
        ".NET)."),
    "unsupported_method": Cause(
        "Unsupported HTTP methods don't get 405", "low",
        "Answer a method the path doesn't support with 405 Method Not Allowed and an Allow header. Express: "
        "mount a method-not-allowed middleware after the routes. .NET: check no catch-all route swallows it."),
    "use_after_delete": Cause(
        "Deleted data can still be fetched", "medium",
        "Return 404 for deleted resources: check soft-delete flags in every read query."),
    "created_not_found": Cause(
        "Created data can't be fetched afterwards", "medium",
        "Make a new resource readable straight away at the ID or URL the create call returned."),
    "slow": Cause("Responses are too slow", "low", "Profile the slow APIs; add indexes or paging."),
    "invalid_input_accepted": Cause(
        "Accepts input the Swagger forbids", "medium",
        "Enforce every rule the Swagger declares (required, minimum/maximum, length, pattern, enum) in "
        "validation, or remove rules from the Swagger that the API doesn't really have.", spec=True),
    "valid_input_refused": Cause(
        "Refuses input the Swagger allows", "medium",
        "Declare in the Swagger the rules the server really enforces (required fields, formats, limits), or "
        "relax the validation.", spec=True),
    "missing_required_header": Cause(
        "Doesn't refuse a request missing a required header", "high",
        "Reject requests without the required header with 400, or don't mark the header required in the "
        "Swagger.", spec=True),
    "response_schema": Cause(
        "Response body doesn't match the Swagger", "medium",
        "Make the response match its schema, or fix the schema. Usually a field's nullability, a missing "
        "required field, or a number sent as a string.", spec=True),
    "undocumented_status": Cause(
        "Returns status codes the Swagger doesn't list", "low",
        "Add the status code to the operation's responses in the Swagger ([ProducesResponseType] in .NET), "
        "or stop returning it.", spec=True),
    "content_type": Cause(
        "Content-Type or headers don't match the Swagger", "low",
        "Document the Content-Type and headers the API really returns, or return the documented ones "
        "(application/json; errors as application/problem+json).", spec=True),
    "swagger_rule": Cause(
        "Swagger document breaks OpenAPI rules", "medium",
        "Fix the Swagger document as the rule message says. The Swagger guide (How to use → Swagger guide) "
        "explains each part.", spec=True),
    "zap_alert": Cause(
        "Security scan (ZAP) alerts", "medium",
        "Follow ZAP's solution for the alert (in the alert's details); most come from missing headers, "
        "verbose errors or unescaped input."),
    "other": Cause("Other failed checks", "medium", "See the failed test's explanation."),
}

# Schemathesis check name -> cause
CHECK_CAUSE = {
    "not_a_server_error": "server_error",
    "status_code_conformance": "undocumented_status",
    "content_type_conformance": "content_type",
    "response_headers_conformance": "content_type",
    "response_schema_conformance": "response_schema",
    "negative_data_rejection": "invalid_input_accepted",
    "positive_data_acceptance": "valid_input_refused",
    "missing_required_header": "missing_required_header",
    "unsupported_method": "unsupported_method",
    "ignored_auth": "auth_bypass",
    "use_after_free": "use_after_delete",
    "ensure_resource_availability": "created_not_found",
    "max_response_time": "slow",
}

# finding title (normalized) -> cause; first match wins
TITLE_CAUSE = [
    ("server error", "server_error"),
    ("crashed the server", "server_error"),
    ("accepted wrong types", "wrong_type_accepted"),
    ("accepted null", "null_accepted"),
    ("reports errors with http 200", "error_as_200"),
    ("bola: user b accessed", "bola"),
    ("secured endpoint accepted", "auth_bypass"),
    ("without authentication", "auth_bypass"),
    ("accepts invalid authentication", "auth_bypass"),
    ("cors allows any origin", "cors"),
    ("leaks stack trace", "leaks_internals"),
    ("missing security header", "missing_security_header"),
    ("unsupported method", "unsupported_method"),
    ("schema violating request", "invalid_input_accepted"),
    ("schema compliant request", "valid_input_refused"),
    ("missing header not rejected", "missing_required_header"),
    ("response violates schema", "response_schema"),
    ("undocumented http status", "undocumented_status"),
    ("content type", "content_type"),
    ("use after free", "use_after_delete"),
    ("resource availability", "created_not_found"),
    ("response time", "slow"),
]

# Findings that are notes about the run, not problems with the API
NOTE_TITLES = ("request failed", "skipped", "inconclusive", "bola scenarios skipped")


def _norm(s: str) -> str:
    return re.sub(r"[\s_-]+", " ", (s or "").lower())


def finding_cause(stage: str, title: str, severity: str = "") -> str:
    """Root cause of a report.json finding; "" for notes about the run itself (info)."""
    t = _norm(title)
    if stage == "lint":
        return "swagger_rule"
    if stage == "zap":
        return "zap_alert"
    if severity == "info" and any(n in t for n in NOTE_TITLES):
        return ""
    return next((c for k, c in TITLE_CAUSE if k in t), "other")


def entry_causes(e: dict) -> list[str]:
    """Root causes of one failed test-log entry, most severe first."""
    stage, d = e.get("stage", ""), e.get("details") or {}
    status = (e.get("response") or {}).get("status")
    causes: list[str] = []
    if stage == "lint":
        causes = ["swagger_rule"]
    elif stage == "zap":
        causes = ["zap_alert"]
    elif stage == "conformance":
        causes = [CHECK_CAUSE.get(c.get("name"), "other") for c in d.get("checks") or [] if c.get("status") == "failure"]
    elif stage == "types":
        problem = d.get("problem", "")
        if "crash" in problem:
            causes = ["server_error"]
        elif problem:
            causes = ["null_accepted" if d.get("sent_value") is None else "wrong_type_accepted"]
    elif stage == "authz":
        sc = e.get("scenario", "")
        if sc.startswith("Cross-user"):
            causes = ["bola"]
        elif sc.startswith("Protected API called with") and isinstance(status, int) and 200 <= status < 300:
            causes = ["auth_bypass"]
        for issue in d.get("passive_issues") or []:
            causes.append(finding_cause("authz", issue))
    if isinstance(status, int) and status >= 500 and "server_error" not in causes:
        causes.append("server_error")  # e.g. a repeated crash Schemathesis didn't re-report
    causes = list(dict.fromkeys(c for c in causes if c)) or ["other"]
    return sorted(causes, key=lambda c: -sev_rank(entry_cause_severity(e, c)))


def entry_cause_severity(e: dict, cause: str) -> str:
    d = e.get("details") or {}
    if cause == "swagger_rule":
        return d.get("severity") or CAUSES[cause].severity
    if cause == "zap_alert":
        return d.get("risk") or CAUSES[cause].severity
    if cause == "null_accepted" and not d.get("required"):
        return "low"
    return CAUSES.get(cause, CAUSES["other"]).severity


def is_spec(cause: str) -> bool:
    return CAUSES.get(cause, CAUSES["other"]).spec


def triage_entry(e: dict, lenient: bool = False) -> dict:
    """{cause, causes, severity, fix, spec_issue} for a failed test; {} for anything else."""
    if e.get("verdict") != "fail":
        return {}
    causes = entry_causes(e)
    cause = causes[0]
    sev = entry_cause_severity(e, cause)
    spec_issue = all(is_spec(c) for c in causes)
    if lenient and spec_issue:
        sev = "info"
    fix = CAUSES[cause].fix
    if cause == "zap_alert" and e.get("expected") and e["expected"] != "No issue":
        fix = e["expected"]  # ZAP's own solution for this alert
    return {"cause": cause, "causes": causes, "severity": sev, "fix": fix, "spec_issue": spec_issue}


def triage_finding(f: dict) -> dict:
    """Adds cause, fix and spec_issue to a report.json finding (a copy). Severity is left as the stage set it,
    except that lenient runs already stored it as info (with original_severity)."""
    cause = finding_cause(f.get("stage", ""), f.get("title", ""), f.get("severity", ""))
    out = dict(f)
    out["cause"] = cause
    out["fix"] = CAUSES[cause].fix if cause else ""
    out["spec_issue"] = is_spec(cause) if cause else False
    return out


def enrich_report(report: dict) -> dict:
    """report.json with cause/fix/spec_issue on every finding (old runs don't store them)."""
    if not report:
        return report
    stages = []
    for s in report.get("stages", []):
        stages.append({**s, "findings": [triage_finding({**f, "stage": f.get("stage") or s["name"]})
                                         for f in s.get("findings", [])]})
    return {**report, "stages": stages}


def apply_lenient(results) -> int:
    """Lenient mode: findings that only show a mismatch with the Swagger become info, so they don't fail the
    run. Keeps the original severity in the detail. Returns how many were changed."""
    n = 0
    for r in results:
        for f in r.findings:
            cause = finding_cause(r.name, f.title, f.severity)
            if cause and is_spec(cause) and f.severity != "info":
                f.detail = (f"Swagger problem (lenient mode): would be {f.severity} if the Swagger were trusted.\n\n"
                            + (f.detail or ""))
                f.severity = "info"
                n += 1
    return n


def summarize(entries_by_op: dict[str, list[dict]], lenient: bool = False) -> dict:
    """Priorities for the top of the report: root-cause groups, the APIs with most failed tests, every API
    that crashed, and every API that accepted wrong types."""
    groups: dict[str, dict] = {}
    top, crashes, wrong_types = [], [], []
    for op, entries in entries_by_op.items():
        fails = []
        for e in entries:
            t = triage_entry(e, lenient)
            if t:
                fails.append((e, t))
            elif (e.get("details") or {}).get("error_200") and e.get("verdict") in ("pass", "error"):
                g = groups.setdefault("error_as_200", {"cause": "error_as_200", "title": CAUSES["error_as_200"].title,
                                                       "severity": "low", "fix": CAUSES["error_as_200"].fix,
                                                       "spec_issue": False, "apis": {}, "tests": 0})
                g["tests"] += 1
                g["apis"][op] = g["apis"].get(op, 0) + 1
        if not fails:
            continue
        worst = max((t["severity"] for _, t in fails), key=sev_rank)
        by_cause: dict[str, int] = {}
        for e, t in fails:
            by_cause[t["cause"]] = by_cause.get(t["cause"], 0) + 1
            g = groups.setdefault(t["cause"], {"cause": t["cause"], "title": CAUSES[t["cause"]].title,
                                               "severity": t["severity"], "fix": CAUSES[t["cause"]].fix,
                                               "spec_issue": is_spec(t["cause"]), "apis": {}, "tests": 0})
            g["tests"] += 1
            g["apis"][op] = g["apis"].get(op, 0) + 1
            if sev_rank(t["severity"]) > sev_rank(g["severity"]):
                g["severity"] = t["severity"]
        if op:
            top.append({"operation": op, "fails": len(fails), "worst": worst,
                        "causes": [CAUSES[c].title for c, _ in sorted(by_cause.items(), key=lambda x: -x[1])]})
        crashed = [e for e, t in fails if "server_error" in t["causes"]]
        if crashed and op:
            codes = sorted({(e.get("response") or {}).get("status") for e in crashed} - {None})
            said = next((_said(e) for e in crashed if _said(e)), "")
            crashes.append({"operation": op, "requests": len(crashed), "codes": codes, "server_said": said,
                            "stages": sorted({e["stage"] for e in crashed})})
        wt = [e for e, t in fails if t["cause"] in ("wrong_type_accepted", "null_accepted")]
        if wt and op:
            fields: dict[str, list] = {}
            for e in wt:
                d = e.get("details") or {}
                vals = fields.setdefault(d.get("field") or "?", [])
                v = d.get("sent_value")
                if v not in vals:
                    vals.append(v)
            wrong_types.append({"operation": op, "requests": len(wt), "fields": fields})
    ordered = sorted(groups.values(), key=lambda g: (g["spec_issue"] and lenient, -sev_rank(g["severity"]),
                                                     -len(g["apis"]), -g["tests"]))
    for g in ordered:
        g["apis"] = [{"operation": k, "fails": v} for k, v in sorted(g["apis"].items(), key=lambda x: -x[1])]
    top.sort(key=lambda t: (-t["fails"], -sev_rank(t["worst"]), t["operation"]))
    crashes.sort(key=lambda c: -c["requests"])
    wrong_types.sort(key=lambda w: -w["requests"])
    return {"causes": ordered, "top": top[:10], "crashes": crashes, "wrong_types": wrong_types}


def _said(e: dict) -> str:
    from .explain import server_said
    return server_said((e.get("response") or {}).get("body"))[:200]
