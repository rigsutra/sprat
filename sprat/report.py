from __future__ import annotations

import html
import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from .models import SEVERITIES, StageResult, sev_rank

COLORS = {"critical": "#b91c1c", "high": "#dc2626", "medium": "#d97706", "low": "#2563eb", "info": "#6b7280"}


def write_reports(out: Path, spec_src: str, base: str, results: list[StageResult], lenient: bool = False) -> None:
    (out / "report.json").write_text(
        json.dumps({"spec": spec_src, "base_url": base, "lenient_spec": lenient,
                    "stages": [asdict(r) for r in results]}, indent=2),
        encoding="utf-8")
    e = html.escape
    counts = {s: 0 for s in SEVERITIES}
    for r in results:
        for f in r.findings:
            counts[f.severity] += 1
    rows = []
    for r in results:
        rows.append(f"<h2>{e(r.name)} <small>[{e(r.status)}] {r.duration:.1f}s "
                    f"&middot; {len(r.findings)} finding(s)</small></h2>")
        if r.note:
            rows.append(f"<p class=note>{e(r.note)}</p>")
        if r.findings:
            rows.append("<table><tr><th>Severity</th><th>Finding</th><th>Where</th></tr>")
            for f in sorted(r.findings, key=lambda f: -sev_rank(f.severity)):
                d = f"<details><summary>{e(f.title)}</summary><pre>{e(f.detail)}</pre></details>" if f.detail else e(f.title)
                rows.append(f"<tr><td><b style='color:{COLORS[f.severity]}'>{f.severity.upper()}</b></td>"
                            f"<td>{d}</td><td><code>{e(f.endpoint)}</code></td></tr>")
            rows.append("</table>")
    summary = " ".join(f"<span style='color:{COLORS[s]}'><b>{counts[s]}</b> {s}</span>"
                       for s in reversed(SEVERITIES))
    page = f"""<!doctype html><meta charset=utf-8><title>API test report</title>
<style>body{{font:14px system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem}}
table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid #ddd;padding:6px;text-align:left;vertical-align:top}}
small{{font-weight:400;color:#666}}pre{{white-space:pre-wrap;background:#f6f6f6;padding:8px}}.note{{color:#666}}</style>
<h1>API test report</h1><p><code>{e(spec_src)}</code> &rarr; <code>{e(base)}</code><br>
{datetime.now():%Y-%m-%d %H:%M}</p><p>{summary}</p>{''.join(rows)}"""
    (out / "report.html").write_text(page, encoding="utf-8")
