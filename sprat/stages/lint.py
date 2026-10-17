"""Spec quality via Spectral (run through npx)."""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from ..models import Finding, StageResult
from ..proc import progress, run_cmd
from ..tls import ca_bundle
from ..testlog import log_of

SEV = {0: "high", 1: "medium", 2: "low", 3: "info"}  # spectral: error, warn, info, hint


def run(spec, cfg, out: Path) -> StageResult:
    res = StageResult("lint")
    npx = shutil.which("npx")
    if not npx:
        res.status, res.note = "skipped", "npx not found (install Node.js to enable Spectral)"
        return res
    # Lint the whole document even when only some operations are selected: a reduced copy
    # would produce bogus "unused component" warnings
    text = spec.full_text or spec.text
    spec_file = out / ("spec-full.json" if text.lstrip().startswith("{") else "spec-full.yaml")
    spec_file.write_text(text, encoding="utf-8")
    ruleset = out / ".spectral.yaml"
    ruleset.write_text('extends: ["spectral:oas"]\n', encoding="utf-8")
    cmd = [npx, "--yes", "--prefer-offline", "@stoplight/spectral-cli", "lint", str(spec_file),
           "--ruleset", str(ruleset), "-f", "json", "--quiet"]
    progress(cfg, "lint", "Checking the Swagger document with Spectral")
    p = run_cmd(cmd, cancel=cfg.cancel, timeout=300, env={**os.environ, "NODE_EXTRA_CA_CERTS": ca_bundle()})
    if p.returncode != 0 and not p.stdout.strip():
        # Spectral also exits non-zero when it found problems, but then it prints them as JSON
        res.status = "error"
        res.note = (p.stderr.strip() or f"Spectral (npx) exited with code {p.returncode} and printed nothing")[-500:]
        return res
    try:
        items = json.loads(p.stdout or "[]")
    except json.JSONDecodeError:
        res.status, res.note = "error", (p.stderr or p.stdout)[-500:]
        return res
    selected = {(o.path, o.method) for o in spec.operations} if spec.filtered else None
    selected_paths = {p for p, _ in selected} if selected is not None else None
    for it in items:
        jp = it.get("path", [])
        if selected is not None and len(jp) >= 2 and jp[0] == "paths":
            # whole spec is linted; keep only findings for the selected operations (and non-path ones)
            if jp[1] not in selected_paths:
                continue
            if len(jp) >= 3 and jp[2] in ("get", "put", "post", "delete", "patch", "head", "options") \
                    and (jp[1], jp[2]) not in selected:
                continue
        sev = SEV.get(it.get("severity", 3), "info")
        path = "/".join(str(x) for x in jp)
        res.findings.append(Finding("lint", sev, f"{it.get('code')}: {it.get('message')}", path))
        tl = log_of(cfg)
        if tl:
            op = ""
            if len(jp) >= 3 and jp[0] == "paths" and jp[2] in METHODS:
                op = f"{jp[2].upper()} {jp[1]}"
            tl.add("lint", f"Swagger rule `{it.get('code')}`", operation=op,
                   expected="The Swagger document follows this OpenAPI rule", verdict="info" if sev == "info" else "fail",
                   explanation=f"{it.get('message')} (at {path or 'document root'}).",
                   details={"message": it.get("message"), "severity": sev, "spec_location": path,
                            "line": (it.get("range") or {}).get("start", {}).get("line")})
    if log_of(cfg) and not res.findings:
        log_of(cfg).add("lint", "Spectral OpenAPI ruleset", expected="No rule violations", verdict="pass")
    return res


METHODS = ("get", "put", "post", "delete", "patch", "head", "options")
