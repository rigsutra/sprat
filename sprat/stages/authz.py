"""Custom authorization checks that generic scanners miss.

1. No credentials on an endpoint the spec marks as secured -> must not return 2xx.
2. Garbage credentials on a secured endpoint -> must not return 2xx.
3. BOLA: resources owned by user A requested with user B's credentials.
4. Passive response checks: security headers, stack-trace leaks, wildcard CORS with credentials.
"""
from __future__ import annotations

import re
from pathlib import Path

import httpx

from ..discover import client_for
from ..models import Finding, StageResult
from ..auth import current_headers, has_user
from ..explain import failure_body
from ..proc import check, progress
from ..testlog import log_of

SAFE = {"get", "head", "options"}
LEAK = re.compile(r"(Traceback \(most recent|at [\w.$]+\([\w.]+:\d+\)|System\.\w+Exception|"
                  r"Stack trace|SQLSTATE|ORA-\d{4,}|SequelizeDatabaseError|\bat Object\.<anonymous>)")
HEADERS_EXPECTED = {"x-content-type-options": "nosniff"}


def _url(base: str, path: str, params: dict[str, str]) -> str:
    for k, v in params.items():
        path = path.replace("{" + k + "}", v)
    return base.rstrip("/") + path


def _send(client, op, base, headers):
    kw = {"headers": headers, "params": op.query_params}
    if op.has_body:
        kw["json"] = {}
    return client.request(op.method.upper(), _url(base, op.path, op.path_params), **kw)


def run(spec, cfg, out: Path) -> StageResult:
    res = StageResult("authz")
    base = cfg.base_url or spec.base_url
    if not base:
        res.status, res.note = "error", "No base URL (pass --base-url)"
        return res
    ops = [o for o in spec.operations if not any(re.search(p, o.path) for p in cfg.exclude_paths)]
    if cfg.no_mutating_authz:
        ops = [o for o in ops if o.method in SAFE]
    checked = 0
    seen: set[str] = set()
    with client_for(base, timeout=cfg.timeout, follow_redirects=False) as c:
        total = len(ops) + len(cfg.bola)
        for i, op in enumerate(ops):
            check(cfg)
            try:
                if op.secured:
                    for label, hdrs in (("no credentials", {}),
                                        ("invalid credentials", {"Authorization": "Bearer invalid.token.value"})):
                        progress(cfg, "authz", f"Sending {label}; expecting 401/403", op=op.label, done=i, total=total)
                        r = _send(c, op, base, hdrs)
                        checked += 1
                        said_200 = failure_body(r.text) if 200 <= r.status_code < 300 else ""
                        served = 200 <= r.status_code < 300 and not said_200
                        _log(cfg, f"Protected API called with {label}", r, op.label,
                             "Refused with 401 or 403", "fail" if served else "pass",
                             {"credentials": label, "passive_issues": _passive_issues(r), "error_200": said_200},
                             explanation=(f"Served the request (HTTP {r.status_code}) with {label}: anyone can call "
                                          "this API without logging in." if served else
                                          f'Refused, but with HTTP {r.status_code} and an error body ("{said_200}") '
                                          "instead of 401/403." if said_200 else
                                          f"Refused with HTTP {r.status_code}, as it should."))
                        if served:
                            res.findings.append(Finding(
                                "authz", "critical",
                                f"Secured endpoint accepted {label} (HTTP {r.status_code})",
                                op.label, "The spec declares security on this operation but it was served anyway."))
                            progress(cfg, "authz", f"Accepted {label} (HTTP {r.status_code})", op=op.label,
                                     done=i, total=total, level="bad")
                        _passive(res, op, r, seen)
                elif op.method in SAFE:
                    progress(cfg, "authz", "Public endpoint: checking headers and error leaks", op=op.label,
                             done=i, total=total)
                    r = _send(c, op, base, current_headers(cfg))
                    checked += 1
                    issues = _passive_issues(r)
                    _log(cfg, "Public API: response checked for leaked errors, security headers and CORS", r, op.label,
                         "No leaked internals, X-Content-Type-Options set, no wildcard CORS with credentials",
                         "fail" if issues else "pass", {"passive_issues": issues},
                         explanation="; ".join(issues) + "." if issues else "No problems in the response.")
                    _passive(res, op, r, seen)
                else:
                    progress(cfg, "authz", "Skipped: public write endpoint", op=op.label, done=i, total=total)
            except httpx.HTTPError as e:
                res.findings.append(Finding("authz", "info", "Request failed", op.label, str(e)))
                if log_of(cfg):
                    log_of(cfg).add_error("authz", "Auth check request", op.method.upper(),
                                          _url(base, op.path, op.path_params), str(e), op.label)
        res.findings += _bola(c, cfg, base, done_before=len(ops), total=total)
    res.note = f"{checked} requests sent; {len(cfg.bola)} BOLA scenario(s) configured"
    if not cfg.bola:
        res.note += " (add `bola:` entries to the config to test cross-user access)"
    return res


def _log(cfg, scenario, r, op, expected, verdict, details=None, explanation=""):
    tl = log_of(cfg)
    if tl:
        tl.add_httpx("authz", scenario, r, operation=op, expected=expected, verdict=verdict, details=details,
                     explanation=explanation)


def _passive_issues(r) -> list[str]:
    """Same checks as _passive, per response, for the test log."""
    issues = []
    if r.status_code >= 400 and LEAK.search(r.text[:5000]):
        issues.append("Error response leaks stack trace / internals")
    issues += [f"Missing security header: {h}" for h in HEADERS_EXPECTED if h not in r.headers]
    if r.headers.get("access-control-allow-origin") == "*" and r.headers.get("access-control-allow-credentials") == "true":
        issues.append("CORS allows any origin with credentials")
    return issues


def _passive(res, op, r, seen):
    if "leak" not in seen and r.status_code >= 400 and LEAK.search(r.text[:5000]):
        seen.add("leak")
        res.findings.append(Finding("authz", "medium", "Error response leaks stack trace / internals",
                                    op.label, r.text[:400]))
    for h in HEADERS_EXPECTED:
        if h not in seen and h not in r.headers:
            seen.add(h)
            res.findings.append(Finding("authz", "low", f"Missing security header: {h}", op.label,
                                        "Seen on the first checked response; likely applies API-wide."))
    acao = r.headers.get("access-control-allow-origin")
    acac = r.headers.get("access-control-allow-credentials")
    if "cors" not in seen and acao == "*" and acac == "true":
        seen.add("cors")
        res.findings.append(Finding("authz", "high", "CORS allows any origin with credentials", op.label))


def _bola(c, cfg, base, done_before: int = 0, total: int | None = None) -> list[Finding]:
    out: list[Finding] = []
    if not cfg.bola:
        return out
    if not has_user(cfg, "b"):
        return [Finding("authz", "info", "BOLA scenarios skipped", "",
                        "Pass --header-b with user B's credentials.")]
    for n, sc in enumerate(cfg.bola):
        check(cfg)
        method = sc.get("method", "GET").upper()
        path = sc["path"]
        params = {k: str(v) for k, v in sc.get("params", {}).items()}
        label = f"{method} {path} {params}"
        progress(cfg, "authz", f"BOLA: user A reads its resource, then user B tries the same {params or ''}",
                 op=f"{method} {path.split('?')[0]}", done=done_before + n, total=total)
        url = _url(base, path, params)
        body = {"json": sc["body"]} if "body" in sc else {}
        op = f"{method} {path.split('?')[0]}"
        try:
            a = c.request(method, url, headers=current_headers(cfg, "a"), **body)
            said_a = failure_body(a.text) if 200 <= a.status_code < 300 else ""
            ok_a = 200 <= a.status_code < 300 and not said_a
            _log(cfg, "Cross-user check, step 1: user A (the owner) reads its own data", a, op,
                 "2xx: the owner can access it", "pass" if ok_a else "error",
                 {"scenario_params": params, "user": "A"},
                 explanation=f"User A got HTTP {a.status_code}" + (f' with an error body ("{said_a}")' if said_a else "")
                 + "." + ("" if ok_a else
                             " The owner can't read this resource, so the cross-user check couldn't run. "
                             "Check the IDs in the scenario and user A's token."))
            if not ok_a:
                out.append(Finding("authz", "info", "BOLA scenario inconclusive", label,
                                   f"Owner (user A) got HTTP {a.status_code}; fix the scenario's IDs."))
                continue
            b = c.request(method, url, headers=current_headers(cfg, "b"), **body)
            said_b = failure_body(b.text) if 200 <= b.status_code < 300 else ""
            leaked = 200 <= b.status_code < 300 and not said_b
            _log(cfg, "Cross-user check, step 2: user B tries to read user A's data", b, op,
                 "401, 403 or 404: user B must not see user A's data",
                 "fail" if leaked else "pass", {"scenario_params": params, "user": "B"},
                 explanation=(f"User B got user A's data (HTTP {b.status_code}). Any logged-in user can read other "
                              "users' data by changing the ID." if leaked else
                              f'User B was refused (HTTP {b.status_code}' + (f', with an error body: "{said_b}"'
                                                                              if said_b else "") + "), as it should."))
        except httpx.HTTPError as e:
            out.append(Finding("authz", "info", "BOLA request failed", label, str(e)))
            if log_of(cfg):
                log_of(cfg).add_error("authz", "BOLA request", method, url, str(e), op)
            continue
        if leaked:
            out.append(Finding("authz", "critical", "BOLA: user B accessed user A's resource",
                               label, f"User B got HTTP {b.status_code}; expected 401/403/404."))
            progress(cfg, "authz", f"BOLA: user B got user A's data (HTTP {b.status_code})", op=op,
                     done=done_before + n + 1, total=total, level="bad")
        else:
            progress(cfg, "authz", f"BOLA: user B was blocked (HTTP {b.status_code})", op=op,
                     done=done_before + n + 1, total=total, level="ok")
    return out
