"""Runs the selected stages and writes reports. Shared by the CLI and the web UI."""
from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from .config import Config
from .models import StageResult, sev_rank
from .proc import Cancelled
from .report import write_reports
from .spec import METHODS, Spec, apply_examples, filter_operations, load_spec
from .stages import authz, conformance, lint, types, zap
from . import coverage, htmlreport, triage
from .auth import current_headers, has_user, make_providers
from .proc import progress
from .testlog import TestLog, write_csv

STAGE_FUNCS = {"lint": lint.run, "conformance": conformance.run, "types": types.run,
               "authz": authz.run, "zap": zap.run}

Emit = Callable[[dict], None]


def run_pipeline(cfg: Config, emit: Emit = lambda e: None) -> list[StageResult]:
    """Run the stages. If cfg.cancel is set mid-run, the current stage is stopped, remaining stages
    are marked cancelled, a partial report is written, and a {"type": "cancelled"} event is emitted."""
    out = Path(cfg.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    emit({"type": "spec_loading", "spec": cfg.spec})
    started = time.time()
    if cfg.login_a or cfg.login_b or cfg.auth_a or cfg.auth_b:
        def on_login(p):
            left = max(0, int(p.expires_at - time.time()))
            progress(cfg, "auth", f"Logged in as {p.label} (login #{p.logins}). Token valid for {left // 60} min "
                     f"{left % 60} s (expiry from {p.expiry_source}); a new one is fetched 30 s before it expires.",
                     level="ok")
        emit({"type": "spec_loading", "spec": cfg.spec, "msg": "Logging in"})
        make_providers(cfg)  # raises LoginError with a readable message
        # on_login is set only now, so the first login (made here or before) is reported once, below
        for p in (cfg.auth_a, cfg.auth_b):
            if p is not None:
                p.on_login = on_login
                if p.logins == 1:
                    on_login(p)
    spec = load_spec(cfg.spec, current_headers(cfg), cfg.timeout)
    if cfg.operations:
        spec = filter_operations(spec, cfg.operations)
    all_ops = list(spec.operations)  # before exclusions, so the report can say what was excluded
    if cfg.exclude_paths:
        # Apply exclusions here, once, so every stage (including ZAP, which scans the whole
        # document it's given) skips them
        keep = [o.label for o in spec.operations if not any(re.search(p, o.path) for p in cfg.exclude_paths)]
        if not keep:
            raise ValueError("Exclude paths removed every operation; nothing to test")
        if len(keep) < len(spec.operations):
            spec = filter_operations(spec, keep)
    if cfg.examples:
        spec = apply_examples(spec, cfg.examples)
    base = cfg.base_url or spec.base_url
    emit({"type": "spec", "version": spec.version, "operations": len(spec.operations), "base_url": base,
          "labels": [o.label for o in spec.operations]})
    cfg.testlog = TestLog(out / "test-log.ndjson", list(cfg.headers.values()) + list(cfg.headers_b.values())
                          + list(cfg.variables.values()),
                          token_sources=[p for p in (cfg.auth_a, cfg.auth_b) if p is not None])

    results: list[StageResult] = []
    cancelled = False
    for name in cfg.stages:
        if cancelled or (cfg.cancel is not None and cfg.cancel.is_set()):
            cancelled = True
            results.append(StageResult(name, "cancelled", "Run stopped before this stage"))
            emit({"type": "stage_end", "stage": name, "status": "cancelled", "findings": 0,
                  "note": "not run", "duration": 0})
            continue
        emit({"type": "stage_start", "stage": name})
        t = time.time()
        try:
            res = STAGE_FUNCS[name](spec, cfg, out)
        except Cancelled:
            cancelled = True
            res = StageResult(name, "cancelled", "Stopped by user")
        except Exception as e:  # a broken stage must not hide the others
            res = StageResult(name, "error", f"{type(e).__name__}: {e}")
        cancelled = cancelled or res.status == "cancelled"  # a stage may stop and still return partial results
        res.duration = time.time() - t
        results.append(res)
        emit({"type": "stage_end", "stage": name, "status": res.status,
              "findings": len(res.findings), "note": res.note, "duration": res.duration})

    annotate(spec, base, results)
    if cfg.lenient_spec:
        triage.apply_lenient(results)
    write_reports(out, cfg.spec, base, results, lenient=cfg.lenient_spec)
    write_csv(out / "test-log.ndjson", out / "test-log.csv")
    settings = {"stages": cfg.stages, "headers": cfg.headers or ({"login": "auto"} if has_user(cfg, "a") else {}),
                "headers_b": cfg.headers_b or ({"login": "auto"} if has_user(cfg, "b") else {}), "bola": cfg.bola,
                "exclude_paths": cfg.exclude_paths, "operations": cfg.operations}
    cov = coverage.build(all_ops, settings, {r.name: {"status": r.status, "note": r.note} for r in results},
                         out / "test-log.ndjson")
    coverage.write(cov, out)
    htmlreport.build(out, {"project_name": cfg.title, "spec": cfg.spec, "status": "cancelled" if cancelled else "done",
                           "started": started, "finished": time.time(), "operations": cfg.operations,
                           "headers": has_user(cfg, "a"), "headers_b": has_user(cfg, "b"),
                           "lenient_spec": cfg.lenient_spec}, cov)
    emit({"type": "cancelled" if cancelled else "done", "report": str(out / "test-report.html")})
    return results


def _template_regex(path: str) -> re.Pattern:
    parts = re.split(r"({[^}]+})", path)
    return re.compile("^" + "".join("[^/]+" if p.startswith("{") else re.escape(p) for p in parts) + "/?$")


def annotate(spec: Spec, base: str, results: list[StageResult]) -> None:
    """Fill Finding.operation ("GET /path") so findings can be shown per API."""
    labels = {o.label for o in spec.operations}
    # fewest {params} first, so /items/mine wins over /items/{id} (stable: spec order breaks ties)
    by_regex = [(o, _template_regex(o.path)) for o in sorted(spec.operations, key=lambda o: o.path.count("{"))]
    base_path = urlparse(base).path.rstrip("/") if base else ""
    for r in results:
        for f in r.findings:
            ep = f.endpoint or ""
            head = ep.split(" ")
            if len(head) >= 2 and head[0].lower() in METHODS:
                cand = f"{head[0].upper()} {head[1]}"
                if cand in labels:
                    f.operation = cand
                    continue
                url_path = urlparse(head[1]).path if head[1].startswith("http") else head[1].split("?")[0]
                if base_path and url_path.startswith(base_path):
                    url_path = url_path[len(base_path):] or "/"
                for o, rx in by_regex:  # concrete URLs (ZAP)
                    if o.method.upper() == head[0].upper() and rx.match(url_path):
                        f.operation = o.label
                        break
            elif ep.startswith("paths/"):  # Spectral JSON path: paths//items/{id}/get/...
                for o in spec.operations:
                    if ep == f"paths/{o.path}/{o.method}" or ep.startswith(f"paths/{o.path}/{o.method}/"):
                        f.operation = o.label
                        break


def failed(cfg: Config, results: list[StageResult]) -> bool:
    threshold = sev_rank(cfg.fail_on)
    return (any(sev_rank(f.severity) >= threshold for r in results for f in r.findings)
            or any(r.status == "error" for r in results))
