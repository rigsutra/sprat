"""Detailed per-request test log, shared by all stages.

Every request a stage sends (or, for ZAP, every alert instance) becomes one NDJSON line in
`test-log.ndjson`:

    seq, ts, stage, operation ("GET /path" from the spec), scenario (what was tested),
    expected (what a correct API does), verdict (pass | fail | info | error),
    request {method, url, headers, body}, response {status, headers, body, elapsed_ms},
    details {...stage-specific: checks run, failure messages, ZAP attack/evidence...}

Secrets are masked: auth-like headers, and any configured header value wherever it appears.
At the end of a run a CSV summary (`test-log.csv`) is written next to it.
"""
from __future__ import annotations

import base64
import csv
import json
import re
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

BODY_LIMIT = 32 * 1024
JWT = re.compile(r"eyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]{5,}")
SENSITIVE = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key", "x-auth-token"}
CSV_FIELDS = ["seq", "time", "stage", "operation", "scenario", "expected", "verdict", "explanation", "method",
              "url", "status", "elapsed_ms", "request_body", "response_body"]


def _template_regex(path: str) -> re.Pattern:
    parts = re.split(r"({[^}]+})", path)
    return re.compile("^" + "".join("[^/]+" if p.startswith("{") else re.escape(p) for p in parts) + "/?$")


class OpMatcher:
    """Maps a concrete request (method + URL) back to the spec operation it hit."""

    def __init__(self, operations, base_url: str):
        # fewest {params} first, so /items/mine wins over /items/{id} (stable: spec order breaks ties)
        self.ops = [(o.method.upper(), o.label, _template_regex(o.path))
                    for o in sorted(operations, key=lambda o: o.path.count("{"))]
        self.base_path = urlparse(base_url).path.rstrip("/") if base_url else ""

    def __call__(self, method: str, url: str) -> str:
        path = urlparse(url).path if "://" in url else url.split("?")[0]
        if self.base_path and path.startswith(self.base_path):
            path = path[len(self.base_path):] or "/"
        for m, label, rx in self.ops:
            if m == method.upper() and rx.match(path):
                return label
        return ""


class TestLog:
    __test__ = False  # not a pytest class

    def __init__(self, path: Path, secrets: list[str] | None = None, token_sources: list | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("", encoding="utf-8")
        self.secrets = sorted({s for s in (secrets or []) if s and len(s) >= 6}, key=len, reverse=True)
        self.token_sources = token_sources or []  # TokenProviders: their current token is masked too
        self.seq = 0
        self._lock = threading.Lock()

    # ---------- masking ----------
    def _mask_text(self, s: str) -> str:
        for sec in self.secrets + [p.token for p in self.token_sources if getattr(p, "token", None)]:
            if sec in s:
                s = s.replace(sec, "***")
        return JWT.sub("***jwt***", s) if "eyJ" in s else s  # any JWT, e.g. one returned by the API itself

    def _mask_value(self, name: str, value: str) -> str:
        if name.lower() in SENSITIVE:
            scheme, _, rest = value.partition(" ")
            return f"{scheme} ***" if rest and scheme.lower() in ("bearer", "basic", "token") else "***"
        return self._mask_text(value)

    def _mask_obj(self, o):
        if isinstance(o, str):
            return self._mask_text(o)
        if isinstance(o, list):
            return [self._mask_obj(v) for v in o]
        if isinstance(o, dict):
            return {k: self._mask_obj(v) for k, v in o.items()}
        return o

    def _headers(self, headers) -> dict:
        out = {}
        for k, v in (headers or {}).items():
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v)
            out[str(k)] = self._mask_value(str(k), str(v))
        return out

    def _body(self, body) -> str | None:
        if body is None:
            return None
        if isinstance(body, bytes):
            try:
                body = body.decode("utf-8")
            except UnicodeDecodeError:
                return f"<{len(body)} bytes of binary data>"
        if not isinstance(body, str):
            body = json.dumps(body, ensure_ascii=False)
        body = self._mask_text(body)
        if len(body) > BODY_LIMIT:
            body = body[:BODY_LIMIT] + f"\n… [truncated, {len(body)} chars total]"
        return body

    # ---------- writing ----------
    def add(self, stage: str, scenario: str, *, operation: str = "", expected: str = "", verdict: str = "info",
            request: dict | None = None, response: dict | None = None, details: dict | None = None,
            ts: float | None = None, explanation: str = "") -> None:
        req = None
        if request:
            req = {"method": request.get("method", ""), "url": self._mask_text(request.get("url", "")),
                   "headers": self._headers(request.get("headers")), "body": self._body(request.get("body"))}
        resp = None
        if response:
            resp = {"status": response.get("status"), "headers": self._headers(response.get("headers")),
                    "body": self._body(response.get("body")), "elapsed_ms": response.get("elapsed_ms")}
        with self._lock:
            self.seq += 1
            entry = {"seq": self.seq, "ts": ts or time.time(), "stage": stage, "operation": operation,
                     "scenario": self._mask_text(scenario), "expected": expected, "verdict": verdict,
                     "explanation": self._mask_text(explanation), "request": req, "response": resp,
                     "details": self._mask_obj(details or {})}  # ZAP evidence can hold a token
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def add_httpx(self, stage: str, scenario: str, response, *, operation: str = "", expected: str = "",
                  verdict: str = "info", details: dict | None = None, explanation: str = "") -> None:
        """Log an httpx exchange. Never raises: logging must not break a test stage."""
        try:
            rq = response.request
            try:
                req_body = rq.content
            except Exception:  # streaming body
                req_body = None
            try:
                elapsed = round(response.elapsed.total_seconds() * 1000, 1)
            except RuntimeError:  # not available on some transports
                elapsed = None
            self.add(stage, scenario, operation=operation, expected=expected, verdict=verdict, details=details,
                     explanation=explanation,
                     request={"method": rq.method, "url": str(rq.url), "headers": dict(rq.headers),
                              "body": req_body or None},
                     response={"status": response.status_code, "headers": dict(response.headers),
                               "body": response.content, "elapsed_ms": elapsed})
        except Exception as e:  # pragma: no cover - defensive
            self.add(stage, scenario, operation=operation, expected=expected, verdict=verdict,
                     explanation=explanation, details={**(details or {}), "log_error": f"{type(e).__name__}: {e}"})

    def add_error(self, stage: str, scenario: str, method: str, url: str, error: str, operation: str = "") -> None:
        self.add(stage, scenario, operation=operation, verdict="error",
                 explanation=f"The request couldn't be completed ({error}), so this wasn't tested.",
                 request={"method": method, "url": url}, details={"error": error})


def log_of(cfg) -> TestLog | None:
    return getattr(cfg, "testlog", None)


# ---------- reading ----------

def iter_entries(path: Path):
    if not path.is_file():
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except ValueError:
                    continue


def _detail_text(e: dict) -> str:
    d = e.get("details") or {}
    if d.get("failures"):
        return " | ".join(d["failures"])[:500]
    for k in ("error", "attack", "evidence", "message"):
        if d.get(k):
            return f"{k}: {d[k]}"[:500]
    return ""


def _cell(v):
    """Text the target API controls must not run as a spreadsheet formula (CSV injection)."""
    return "'" + v if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


def write_csv(ndjson: Path, csv_path: Path) -> int:
    n = 0
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:  # BOM so Excel detects UTF-8
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        for e in iter_entries(ndjson):
            rq, rs = e.get("request") or {}, e.get("response") or {}
            w.writerow({k: _cell(v) for k, v in {"seq": e["seq"], "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e["ts"])),
                        "stage": e["stage"], "operation": e["operation"], "scenario": e["scenario"],
                        "expected": e["expected"], "verdict": e["verdict"],
                        "explanation": e.get("explanation") or _detail_text(e), "method": rq.get("method", ""),
                        "url": rq.get("url", ""), "status": rs.get("status", ""),
                        "elapsed_ms": rs.get("elapsed_ms", ""),
                        "request_body": (rq.get("body") or "")[:2000],
                        "response_body": (rs.get("body") or "")[:2000]}.items()})
            n += 1
    return n


def b64_or_text(content) -> str | None:
    """Schemathesis stores bodies as {"$base64": "..."} or plain strings."""
    if content is None:
        return None
    if isinstance(content, dict) and "$base64" in content:
        try:
            return base64.b64decode(content["$base64"]).decode("utf-8", "replace")
        except ValueError:
            return None
    return content if isinstance(content, str) else json.dumps(content)
