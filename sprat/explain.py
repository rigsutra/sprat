"""Plain-language descriptions of what was tested and why something failed.

Schemathesis and ZAP speak in their own jargon ("negative_data_rejection", "coverage phase").
Everything shown to people goes through here first.
"""
from __future__ import annotations

import re

# Schemathesis phases, as people would say them
PHASES = {
    "probing": ("Capability probe", "Checks a few basics about the server before testing."),
    "examples": ("Swagger examples", "Sends the example values written in the Swagger and checks the API accepts them."),
    "coverage": ("Edge cases", "Deliberately chosen tricky inputs, one at a time: minimum/maximum values, empty "
                               "strings, a missing required field or header, a value of the wrong type, an HTTP "
                               "method the API doesn't support."),
    "fuzzing": ("Random data", "Many randomly generated requests, some valid and some invalid on purpose, to find "
                               "inputs that crash the API or get an answer the Swagger doesn't allow."),
    "stateful": ("Request chains", "Chains of calls that use each other's results (e.g. create something, then "
                                   "fetch it with the returned ID)."),
}

STAGES = {
    "lint": ("Swagger quality", "Checks the Swagger document itself against OpenAPI best-practice rules."),
    "conformance": ("Behaviour vs Swagger", "Sends many requests and checks every response against what the "
                                            "Swagger promises: status codes, response types, no server errors, "
                                            "and that invalid input is rejected."),
    "types": ("Wrong data types", "Takes a valid request and replaces one field at a time with a value of the "
                                  "wrong type (e.g. \"1\" for a number, \"yes\" for true/false). Each must be rejected."),
    "authz": ("Access control", "Calls protected APIs with no token and with a fake token (must be refused), "
                                "checks a second user can't read the first user's data, and looks for leaked "
                                "error details and missing security headers."),
    "zap": ("Security scan (OWASP ZAP)", "Attacks the APIs with common exploits (injection, header tricks, "
                                         "misconfiguration) and reports anything that looks vulnerable."),
}


def phase_label(phase: str) -> str:
    return PHASES.get(phase, (phase.capitalize() if phase else "Test", ""))[0]


def _clean(desc: str) -> str:
    """Make Schemathesis' generated-case descriptions readable."""
    d = desc.strip()
    d = re.sub(r"^- ", "", d, flags=re.M)
    d = d.replace("\n", "; ")
    d = re.sub(r"violates `(\w+)` at /properties/([\w.\-/]+)", lambda m: f"`{m[2]}` breaks its `{m[1]}` rule", d)
    d = re.sub(r"\(was (.+?), became (.+?)\)", r"(changed \1 → \2)", d)
    d = re.sub(r"([\w.\[\]\-]+): Incorrect type", r"`\1` has the wrong type", d)
    d = d.replace("Incorrect type", "has the wrong type")
    return d


def describe_case(phase: str, mode: str, description: str) -> str:
    """One readable line for a generated request."""
    head = phase_label(phase)
    desc = _clean(description or "")
    if desc.lower() in ("positive test case", "") and mode == "positive":
        return f"{head}: valid request"
    if not desc:
        return f"{head}: {'invalid request on purpose' if mode == 'negative' else 'generated request'}"
    if mode == "negative" and phase == "fuzzing":
        return f"{head}: invalid on purpose ({desc})"
    return f"{head}: {desc}"


AUTH_HEADERS = ("authorization", "x-api-key", "api-key", "cookie")


def is_method_probe(description: str) -> bool:
    return "Unspecified HTTP method" in (description or "")


def is_auth_probe(description: str) -> bool:
    """Cases that are *about* credentials (missing/odd Authorization or X-API-Key)."""
    d = (description or "").lower()
    return any(h in d for h in AUTH_HEADERS)


def expected_for(mode: str, description: str = "") -> str:
    if is_method_probe(description):
        m = re.search(r"method: (\w+)", description)
        return (f"405 Method Not Allowed: this API path doesn't define {m[1] if m else 'this method'}, and the "
                "standard answer for that is 405.")
    if mode == "negative":
        return "The API should refuse it with a 4xx error, because the request is invalid on purpose."
    return "The API should accept it without crashing and answer exactly as the Swagger describes."


def permission_detail(body: str | None) -> str:
    """'missing permission read:aggregation' from a 403 body like {"required": ["read:aggregation"], ...}."""
    if not body:
        return ""
    try:
        import json
        doc = json.loads(body)
    except ValueError:
        doc = None
    if isinstance(doc, dict):
        req = doc.get("required") or doc.get("requiredScopes") or doc.get("required_scopes") or doc.get("scopes")
        if isinstance(req, list) and req:
            return "missing permission " + ", ".join(f"`{r}`" for r in req)
    said = server_said(body)
    return f"server said: {said}" if said else ""


def blocked_by_auth(status, mode: str, description: str, has_credentials: bool) -> str:
    """If a request that wasn't about credentials was refused for auth reasons, explain why it
    therefore didn't test anything. Empty string otherwise."""
    if status not in (401, 403) or not has_credentials or is_auth_probe(description) or is_method_probe(description):
        return ""
    what = "the invalid input was never checked" if mode == "negative" else "the API's logic was never reached"
    if status == 403:
        return f"Not really tested: refused with HTTP 403 Forbidden before anything else, so {what}."
    return f"Not really tested: refused with HTTP 401 (login not accepted), so {what}."


CHECKS = {
    "not_a_server_error": lambda s: f"The server crashed (HTTP {s}). A server error is always a bug.",
    "status_code_conformance": lambda s: f"Answered HTTP {s}, which the Swagger doesn't list for this API. "
                                         "Either document it or don't return it.",
    "content_type_conformance": lambda s: "Answered with a Content-Type the Swagger doesn't list.",
    "response_headers_conformance": lambda s: "A response header that the Swagger requires was missing or wrong.",
    "response_schema_conformance": lambda s: "The response body doesn't match the Swagger (a field has the wrong "
                                             "type, is missing, or is null when it shouldn't be).",
    "negative_data_rejection": lambda s: f"Accepted invalid input (HTTP {s}). It should have refused it with a 4xx.",
    "positive_data_acceptance": lambda s: f"Refused a request that is valid according to the Swagger (HTTP {s}).",
    "missing_required_header": lambda s: f"Didn't refuse a request missing a required header (HTTP {s}).",
    "unsupported_method": lambda s: f"Answered an HTTP method this API doesn't support with HTTP {s}; "
                                    "the standard answer is 405 Method Not Allowed.",
    "ignored_auth": lambda s: f"Served the request although authentication was missing or invalid (HTTP {s}).",
    "use_after_free": lambda s: "Something that was deleted could still be fetched.",
    "ensure_resource_availability": lambda s: "Something that was just created couldn't be fetched afterwards.",
    "max_response_time": lambda s: "The response was slower than the allowed limit.",
}


def explain_check(name: str, status, failure: dict | None = None) -> str:
    if name in CHECKS:
        text = CHECKS[name](status if status is not None else "?")
    else:
        title = (failure or {}).get("title") or name.replace("_", " ")
        text = f"{title}."
    if name == "not_a_server_error" and failure:
        detail = _server_error_hint(failure.get("message") or "")
        if detail:
            text += f" Server said: {detail}"
    return text


def _server_error_hint(msg: str) -> str:
    m = re.search(r'"(?:message|detail|error)"\s*:\s*"([^"]{3,160})"', msg)
    return m[1] if m else ""


FINDING_TITLES = {
    "Server error": "The API crashes (HTTP 5xx) on some inputs",
    "Undocumented HTTP status code": "Returns status codes the Swagger doesn't list",
    "Unsupported methods": "Unsupported HTTP methods don't get 405 Method Not Allowed",
    "API accepted schema-violating request": "Accepts invalid input that the Swagger forbids",
    "API rejected schema-compliant request": "Refuses valid input",
    "Response violates schema": "Response body doesn't match the Swagger",
    "API accepts requests without authentication": "Works without login",
    "Missing header not rejected": "Doesn't refuse a request missing a required header",
    "Undocumented Content-Type": "Returns a Content-Type the Swagger doesn't list",
    "Missing Content-Type header": "Response has no Content-Type header",
    "Check failed": "A behaviour check failed",
}


def finding_title(title: str) -> str:
    return FINDING_TITLES.get(title.strip(), title)


FAILED_STATUS = re.compile(r"^(fail|failed|failure|error|unsuccessful|invalid)$", re.I)
SUCCESS_FLAGS = ("success", "succeeded", "issuccess", "issucceeded", "ok")


def failure_body(body: str | None) -> str:
    """For a 2xx response: if the JSON body says the request failed ({"status": "Failed", ...},
    {"success": false, ...}), what it said; else "". Some APIs refuse requests with HTTP 200."""
    if not body or not body.lstrip().startswith("{"):
        return ""
    try:
        import json
        doc = json.loads(body)
    except ValueError:
        return ""
    if not isinstance(doc, dict):
        return ""
    low = {str(k).lower(): v for k, v in doc.items()}
    failed = any(isinstance(low.get(k), str) and FAILED_STATUS.match(low[k].strip())
                 for k in ("status", "result", "outcome"))
    failed = failed or any(low.get(k) is False for k in SUCCESS_FLAGS)
    if not failed:
        return ""
    for k in ("message", "errormessage", "error", "detail", "title", "logmessage"):
        if isinstance(low.get(k), str) and low[k].strip():
            return low[k].strip()[:200]
    return "the response body says the request failed"


# Refusals for access reasons that don't use 401/403 ("400 User is not authorized", "200 API key is required")
ACCESS_TEXT = re.compile(r"not authori[sz]ed|unauthori[sz]ed|forbidden|access (is )?denied|permission|"
                         r"api[ _-]?key|not allowed to|insufficient (scope|privileges)", re.I)


def server_said(body: str | None) -> str:
    """Short 'what the server said' from an error body."""
    if not body:
        return ""
    m = re.search(r'"(?:detail|message|error|title|errorMessage)"\s*:\s*"([^"]{3,200})"', body)
    if m:
        return m[1]
    text = body.strip()
    if text.startswith('"'):  # a bare JSON string, e.g. "API key is required"
        try:
            import json
            v = json.loads(text)
            if isinstance(v, str):
                return v[:160]
        except ValueError:
            pass
    return text[:160]
