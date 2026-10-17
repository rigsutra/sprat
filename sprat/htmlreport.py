"""Self-contained HTML report: per API, what was tested, what wasn't (and why), the problems found,
and every test with its input, output and result. One file, no external assets, works offline."""
from __future__ import annotations

import html
import json
import time
from collections import defaultdict
from pathlib import Path

from . import triage
from .explain import PHASES, STAGES, finding_title
from .testlog import iter_entries

BODY_LIMIT = 3000  # per body in the HTML; the NDJSON download keeps up to 32 KB


def _cut(s):
    if s and len(s) > BODY_LIMIT:
        return s[:BODY_LIMIT] + f"\n… [{len(s) - BODY_LIMIT} more characters in the NDJSON download]"
    return s


def build(run_dir: Path, meta: dict, coverage: dict) -> Path:
    report = json.loads((run_dir / "report.json").read_text(encoding="utf-8")) if (run_dir / "report.json").is_file() else {"stages": []}
    lenient = bool(report.get("lenient_spec") or meta.get("lenient_spec"))
    tests, raw = defaultdict(list), defaultdict(list)
    for e in iter_entries(run_dir / "test-log.ndjson"):
        rq, rs = e.get("request") or {}, e.get("response") or {}
        t = triage.triage_entry(e, lenient)
        raw[e.get("operation") or ""].append(e)
        tests[e.get("operation") or ""].append({
            "seq": e["seq"], "stage": e["stage"], "scenario": e["scenario"], "expected": e.get("expected", ""),
            "verdict": e["verdict"], "explanation": e.get("explanation", ""),
            "sev": t.get("severity"), "cause": triage.CAUSES[t["cause"]].title if t else "", "fix": t.get("fix", ""),
            "req": {"method": rq.get("method", ""), "url": rq.get("url", ""), "headers": rq.get("headers") or {},
                    "body": _cut(rq.get("body"))} if rq else None,
            "res": {"status": rs.get("status"), "headers": rs.get("headers") or {}, "body": _cut(rs.get("body")),
                    "ms": rs.get("elapsed_ms")} if rs else None,
        })
    # requests with a method the spec doesn't define (e.g. "TRACE /orders") belong to that path's API
    known = {a["operation"] for a in coverage.get("apis", [])}
    by_path = {}
    for a in coverage.get("apis", []):
        by_path.setdefault(a["path"], a["operation"])
    for key in [k for k in tests if k and k not in known]:
        target = by_path.get(key.split(" ", 1)[-1], "")
        tests[target].extend(tests.pop(key))
        raw[target].extend(raw.pop(key))
    findings = defaultdict(list)
    for s in triage.enrich_report(report).get("stages", []):
        for f in s.get("findings", []):
            findings[f.get("operation") or ""].append({"stage": s["name"], "severity": f["severity"],
                                                       "title": finding_title(f["title"]),
                                                       "detail": (f.get("detail") or "")[:1500],
                                                       "fix": f.get("fix", ""), "spec_issue": f.get("spec_issue")})
    stage_status = {s["name"]: {"status": s["status"], "note": s.get("note", ""), "findings": len(s["findings"]),
                                "duration": s.get("duration", 0)} for s in report.get("stages", [])}
    data = {
        "run": {"id": meta.get("id", run_dir.name), "project": meta.get("project_name") or "",
                "spec": meta.get("spec") or report.get("spec", ""), "base_url": report.get("base_url", ""),
                "status": meta.get("status", ""), "started": meta.get("started"), "finished": meta.get("finished"),
                "selected": meta.get("operations") or [], "stages": stage_status,
                "user_a": bool(meta.get("headers")), "user_b": bool(meta.get("headers_b")),
                "lenient": lenient, "generated": time.time()},
        "summary": triage.summarize(raw, lenient),
        "warnings": coverage.get("warnings", []),
        "apis": coverage.get("apis", []),
        "tests": tests, "findings": findings,
        "stage_info": {k: list(v) for k, v in STAGES.items()},
        "phase_info": {k: list(v) for k, v in PHASES.items() if k != "probing"},
    }
    # every "<" escaped (only possible inside JSON strings): "</script>", "<!--" or "<script" from the target
    # API can then neither close the data block nor switch the HTML parser into a state that never ends it
    blob = json.dumps(data, ensure_ascii=False).replace("<", "\\u003c")
    title = html.escape(f"API test report — {data['run']['project'] or 'sprat'}")
    out = run_dir / "test-report.html"
    out.write_text(TEMPLATE.replace("__TITLE__", title).replace("__DATA__", blob), encoding="utf-8")
    return out


TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%232f5bea'/%3E%3Cpath d='M11.5 16.5l3 3 6-6.5' fill='none' stroke='white' stroke-width='2.6' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
<style>
:root{--bg:#f4f5f7;--panel:#fff;--panel2:#f8f9fb;--border:#dfe2e7;--text:#1b1f24;--muted:#5d6673;--accent:#2f5bea;--code:#eef0f3;
--ok:#1a7f37;--bad:#d1242f;--warn:#b45309;--info:#6b7280;--crit:#a51d2d;--low:#2563eb}
@media (prefers-color-scheme:dark){:root{--bg:#111418;--panel:#1a1e24;--panel2:#20252c;--border:#2e353e;--text:#e6e9ed;--muted:#9aa4b1;
--accent:#5b82ff;--code:#262c34;--ok:#3fb950;--bad:#ff7b72;--warn:#e3a33b;--info:#9aa4b1;--crit:#ff6b78;--low:#6ea8fe}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 20px 80px}a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px}h3{font-size:13px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin:16px 0 6px}
code,pre{font-family:ui-monospace,"Cascadia Code",Consolas,monospace;font-size:12.5px}code{background:var(--code);padding:1px 4px;border-radius:4px;overflow-wrap:anywhere}
pre{background:var(--panel2);border:1px solid var(--border);border-radius:6px;padding:10px;white-space:pre-wrap;word-break:break-word;max-height:340px;overflow:auto;margin:6px 0}
.muted{color:var(--muted)}.panel{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:16px 18px;margin-bottom:14px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:16px 0}
.tile{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:12px 14px}.tile b{display:block;font-size:24px}
.warn{border-left:4px solid var(--warn);background:var(--panel)}.warn li{margin:6px 0}
table{border-collapse:collapse;width:100%}th{text-align:left;font-size:12px;color:var(--muted);font-weight:600;padding:6px 8px;border-bottom:1px solid var(--border)}
td{padding:7px 8px;border-bottom:1px solid var(--border);vertical-align:top}
.m{display:inline-block;min-width:56px;text-align:center;font:700 11px ui-monospace,monospace;padding:2px 4px;border-radius:4px;background:var(--code)}
.m.get{color:var(--ok)}.m.post{color:var(--low)}.m.put,.m.patch{color:var(--warn)}.m.delete{color:var(--bad)}
.badge{display:inline-block;font:700 11px system-ui,sans-serif;text-transform:uppercase;letter-spacing:.03em;padding:2px 8px;border-radius:10px;border:1px solid currentColor;white-space:nowrap}
.b-ok,.s-tested,.v-pass{color:var(--ok)}.b-problems,.v-fail{color:var(--bad)}.b-incomplete,.s-partial,.v-error{color:var(--warn)}
.b-excluded,.s-not_applicable,.s-not_recorded,.v-info{color:var(--info)}.s-not_tested{color:var(--bad)}
.sev-critical{color:var(--crit)}.sev-high{color:var(--bad)}.sev-medium{color:var(--warn)}.sev-low{color:var(--low)}.sev-info{color:var(--info)}
.sevb{display:inline-block;min-width:64px;text-align:center;font:700 10.5px system-ui,sans-serif;text-transform:uppercase;letter-spacing:.03em;padding:2px 7px;border-radius:10px;border:1px solid currentColor}
.fix{margin-top:4px;font-size:12.5px}.fix b{color:var(--ok)}.tag{display:inline-block;font-size:11px;padding:0 7px;border-radius:9px;background:var(--code);color:var(--muted);margin-left:6px;font-weight:600}
.access{border-left:4px solid var(--warn);padding:8px 12px;background:var(--panel2);border-radius:4px;margin:8px 0;font-size:13px}
.access.blocked{border-left-color:var(--bad)}.a-blocked{color:var(--bad)}.a-partial{color:var(--warn)}
.prio h3{margin-top:22px}.prio h3:first-child{margin-top:0}.prio td.n{text-align:right;width:1%;white-space:nowrap}
.apis-list a{white-space:nowrap}.apis-list span{color:var(--muted)}
.dots span{display:inline-block;width:22px;text-align:center;font-weight:700}
.api{scroll-margin-top:12px}.api-head{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.api-head .p{font:600 15px ui-monospace,monospace;overflow-wrap:anywhere}
.filters{display:flex;gap:6px;flex-wrap:wrap;margin:8px 0}.filters button{font:inherit;font-size:12.5px;padding:3px 10px;border-radius:12px;border:1px solid var(--border);background:var(--panel2);color:var(--text);cursor:pointer}
.filters button.on{outline:2px solid var(--accent);outline-offset:-2px}
tr.t{cursor:pointer}tr.t:hover td{background:var(--panel2)}tr.d td{background:var(--panel2)}
.kv th{width:1%;white-space:nowrap;padding:2px 12px 2px 0;border:0;font-weight:600}.kv td{padding:2px 0;border:0;font-family:ui-monospace,monospace;font-size:12px;overflow-wrap:anywhere}
details>summary{cursor:pointer;font-weight:600}.legend dt{font-weight:700;margin-top:8px}.legend dd{margin:2px 0 0 0;color:var(--muted)}
.top{position:fixed;right:18px;bottom:18px;background:var(--accent);color:#fff;border-radius:20px;padding:6px 12px;font-weight:600}
@media print{.filters,.top{display:none}pre{max-height:none}}
</style></head><body><main id="app"></main><a class="top" href="#top">↑ Top</a>
<script type="application/json" id="data">__DATA__</script>
<script>
const D = JSON.parse(document.getElementById("data").textContent);
const E = (tag, attrs = {}, ...kids) => { const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) { if (k === "class") el.className = v; else if (k === "html") el.innerHTML = v; else if (k.startsWith("on")) el.addEventListener(k.slice(2), v); else el.setAttribute(k, v); }
  for (const k of kids.flat(Infinity)) if (k != null && k !== false) el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  return el; };
const fmt = (t) => t ? new Date(t * 1000).toLocaleString() : "";
const STATUS = { tested: ["✓", "Tested"], partial: ["◐", "Partly tested"], not_tested: ["✕", "Not tested"], not_applicable: ["–", "Not applicable"], not_recorded: ["?", "Not recorded"] };
const VERDICT = { ok: "No problems", problems: "Problems found", incomplete: "Not fully tested", excluded: "Excluded" };
const method = (m) => E("span", { class: "m " + m.toLowerCase() }, m.toUpperCase());
const slug = (s) => "api-" + s.replace(/[^a-z0-9]+/gi, "-");
const app = document.getElementById("app");
const r = D.run;

app.append(E("a", { id: "top" }), E("h1", {}, "API test report", r.project ? ` — ${r.project}` : ""),
  E("div", { class: "muted" }, `Spec ${r.spec} → ${r.base_url} · ${fmt(r.started)}${r.finished ? " – " + fmt(r.finished) : ""} · run ${r.status}`
    + (r.selected.length ? ` · ${r.selected.length} selected API(s)` : " · all APIs")));

const counts = { ok: 0, problems: 0, incomplete: 0, excluded: 0 };
D.apis.forEach((a) => counts[a.verdict] = (counts[a.verdict] || 0) + 1);
const allTests = Object.values(D.tests).flat();
const tv = (v) => allTests.filter((t) => t.verdict === v).length;
app.append(E("div", { class: "tiles" },
  E("div", { class: "tile" }, E("b", {}, D.apis.length), "APIs in this run"),
  E("div", { class: "tile b-problems" }, E("b", {}, counts.problems), "APIs with problems"),
  E("div", { class: "tile b-incomplete" }, E("b", {}, counts.incomplete), "APIs not fully tested"),
  E("div", { class: "tile b-ok" }, E("b", {}, counts.ok), "APIs with no problems"),
  E("div", { class: "tile" }, E("b", {}, allTests.length), `tests · ${tv("pass")} passed · ${tv("fail")} failed`),
  ...(() => {
    const blocked = D.apis.filter((a) => (a.access || {}).status === "blocked").length;
    const partial = D.apis.filter((a) => (a.access || {}).status === "partial").length;
    return blocked || partial ? [E("div", { class: "tile a-blocked" }, E("b", {}, blocked + partial),
      `APIs not tested due to access${partial ? ` (${blocked} fully, ${partial} partly)` : ""}`)] : [];
  })()));

if (D.warnings.length) app.append(E("div", { class: "panel warn" }, E("b", {}, "Read this first"), E("ul", {}, D.warnings.map((w) => E("li", {}, w)))));

/* priorities: what to fix first */
const sevBadge = (s) => s ? E("span", { class: "sevb sev-" + s }, s) : "";
const apiLink = (op) => op ? E("a", { href: "#" + slug(op) }, op) : E("i", {}, "whole Swagger / not tied to one API");
const apisList = (list, max = 5) => E("div", { class: "apis-list" },
  list.slice(0, max).map((x, i) => [i ? ", " : "", apiLink(x.operation), E("span", {}, ` (${x.fails})`)]),
  list.length > max ? E("span", {}, ` and ${list.length - max} more`) : null);
const S = D.summary || { causes: [], top: [], crashes: [], wrong_types: [] };
const ACCESS = { blocked: "Not tested: access issue", partial: "Partly not tested: access issue" };
const prio = E("div", { class: "panel prio" });
const accessApis = D.apis.filter((a) => a.access && a.access.status !== "ok");
if (accessApis.length) prio.append(E("h3", {}, `APIs not tested due to access issues (${accessApis.length})`),
  E("table", {}, E("thead", {}, E("tr", {}, E("th", {}, "API"), E("th", {}, "Status"), E("th", {}, "Why"))),
    E("tbody", {}, accessApis.map((a) => E("tr", {}, E("td", { style: "white-space:nowrap" }, apiLink(a.operation)),
      E("td", { class: "a-" + a.access.status, style: "white-space:nowrap" }, E("b", {}, ACCESS[a.access.status])),
      E("td", {}, a.access.reason))))));
const causeTable = (list) => E("table", {}, E("thead", {}, E("tr", {}, E("th", {}, "Severity"), E("th", {}, "Problem"),
    E("th", {}, "APIs"), E("th", {}, "Failed tests"), E("th", {}, "Recommended fix"))),
  E("tbody", {}, list.map((g) => E("tr", {}, E("td", {}, sevBadge(g.severity)),
    E("td", {}, E("b", {}, g.title), g.spec_issue && !r.lenient ? E("span", { class: "tag", title: "The API and the Swagger disagree. Either one may be wrong." }, "API vs Swagger") : null,
      apisList(g.apis)),
    E("td", { class: "n" }, g.apis.length), E("td", { class: "n" }, g.tests), E("td", { class: "fix" }, g.fix)))));
const bugs = S.causes.filter((g) => !(r.lenient && g.spec_issue));
const specProblems = S.causes.filter((g) => r.lenient && g.spec_issue);
if (bugs.length) prio.append(E("h3", {}, "Problems by root cause, most severe first"), causeTable(bugs));
if (specProblems.length) prio.append(E("h3", {}, "Swagger problems (lenient mode: the Swagger isn't trusted, so these don't fail the run)"),
  causeTable(specProblems));
if (S.top.length) prio.append(E("h3", {}, `Top ${S.top.length} APIs by failed tests`),
  E("table", {}, E("thead", {}, E("tr", {}, E("th", {}, "#"), E("th", {}, "API"), E("th", {}, "Failed tests"), E("th", {}, "Worst"), E("th", {}, "Main problems"))),
    E("tbody", {}, S.top.map((t, i) => E("tr", {}, E("td", { class: "n muted" }, i + 1), E("td", {}, apiLink(t.operation)),
      E("td", { class: "n" }, t.fails), E("td", {}, sevBadge(t.worst)), E("td", {}, t.causes.slice(0, 3).join(" · ")))))));
if (S.crashes.length) prio.append(E("h3", {}, `APIs that crash with a server error (${S.crashes.length})`),
  E("table", {}, E("thead", {}, E("tr", {}, E("th", {}, "API"), E("th", {}, "Crashing requests"), E("th", {}, "HTTP"), E("th", {}, "Server said"))),
    E("tbody", {}, S.crashes.map((c) => E("tr", {}, E("td", {}, apiLink(c.operation)), E("td", { class: "n" }, c.requests),
      E("td", {}, c.codes.join(", ")), E("td", { class: "muted" }, c.server_said || "—"))))));
if (S.wrong_types.length) prio.append(E("h3", {}, `APIs that accept wrong data types (${S.wrong_types.length})`),
  E("table", {}, E("thead", {}, E("tr", {}, E("th", {}, "API"), E("th", {}, "Accepted"), E("th", {}, "Fields and the wrong values they accepted"))),
    E("tbody", {}, S.wrong_types.map((w) => E("tr", {}, E("td", {}, apiLink(w.operation)), E("td", { class: "n" }, w.requests),
      E("td", {}, Object.entries(w.fields).map(([f, vals], i) => [i ? E("br") : null, E("code", {}, f), " ← ",
        vals.map((v) => JSON.stringify(v)).join(", ")])))))));
if (prio.childNodes.length) app.append(E("h2", {}, "Fix these first"), prio);

const leg = E("details", { class: "panel" }, E("summary", {}, "What each test does"), E("dl", { class: "legend" },
  Object.entries(D.stage_info).map(([k, [n, d]]) => [E("dt", {}, n), E("dd", {}, d)]),
  E("dt", {}, "Behaviour vs Swagger: the kinds of requests sent"),
  Object.entries(D.phase_info).map(([k, [n, d]]) => E("dd", {}, E("b", {}, n + ": "), d)),
  E("dt", {}, "Status"), Object.values(STATUS).map(([i, n]) => E("dd", {}, `${i} ${n}`))));
app.append(leg);

/* index */
const stages = Object.keys(r.stages);
const idx = E("table", {}, E("thead", {}, E("tr", {}, E("th", {}, "API"), E("th", {}, "Result"),
  ...stages.map((s) => E("th", { title: (D.stage_info[s] || [s])[0] }, (D.stage_info[s] || [s])[0])), E("th", {}, "Failed tests"))));
const tb = E("tbody");
D.apis.forEach((a) => {
  const cells = stages.map((s) => {
    const items = a.tests.filter((t) => t.stage === s);
    const worst = ["not_tested", "partial", "not_recorded", "tested", "not_applicable"].find((st) => items.some((i) => i.status === st));
    const [icon, label] = STATUS[worst] || ["", ""];
    return E("td", { class: "dots s-" + (worst || ""), title: items.map((i) => `${i.test}: ${STATUS[i.status][1]}. ${i.reason}`).join("\n") }, E("span", {}, icon));
  });
  tb.append(E("tr", {}, E("td", {}, method(a.method), " ", E("a", { href: "#" + slug(a.operation) }, E("code", {}, a.path))),
    E("td", {}, E("span", { class: "badge b-" + a.verdict }, VERDICT[a.verdict]),
      a.access && a.access.status !== "ok" ? [" ", E("span", { class: "badge a-" + a.access.status, title: a.access.reason },
        a.access.status === "blocked" ? "access: not tested" : "access: partly")] : null),
    ...cells, E("td", {}, a.counts.fail || 0)));
});
idx.append(tb);
app.append(E("h2", {}, "All APIs"), E("div", { class: "panel" }, idx, E("p", { class: "muted" }, "Hover a symbol to see why. Click an API for its details.")));

/* per API */
const testRow = (t) => {
  const tr = E("tr", { class: "t" }, E("td", { class: "muted" }, t.seq), E("td", {}, sevBadge(t.sev)), E("td", {}, (D.stage_info[t.stage] || [t.stage])[0]),
    E("td", {}, t.scenario, t.verdict !== "pass" && t.explanation ? E("div", { class: "v-" + t.verdict, style: "font-size:12.5px" }, t.explanation) : null),
    E("td", {}, t.res ? String(t.res.status ?? "") : ""), E("td", {}, E("span", { class: "badge v-" + t.verdict }, t.verdict)));
  tr.addEventListener("click", () => {
    if (tr.nextSibling && tr.nextSibling.classList && tr.nextSibling.classList.contains("d")) { tr.nextSibling.remove(); return; }
    const kv = (h) => Object.keys(h || {}).length ? E("table", { class: "kv" }, Object.entries(h).map(([k, v]) => E("tr", {}, E("th", {}, k), E("td", {}, v)))) : E("div", { class: "muted" }, "none");
    const pretty = (s) => { try { return JSON.stringify(JSON.parse(s), null, 2); } catch { return s; } };
    tr.after(E("tr", { class: "d" }, E("td", { colspan: 6 },
      E("h3", {}, "What was tested"), E("div", {}, t.scenario),
      E("h3", {}, "Expected"), E("div", {}, t.expected || "—"),
      E("h3", {}, "Result"), E("div", { class: "v-" + t.verdict }, t.explanation || t.verdict),
      t.sev ? [E("h3", {}, "Severity and root cause"), E("div", {}, sevBadge(t.sev), " ", t.cause),
               E("h3", {}, "Recommended fix"), E("div", {}, t.fix)] : null,
      t.req ? [E("h3", {}, "Input (request)"), E("div", {}, E("code", {}, `${t.req.method} ${t.req.url}`)), kv(t.req.headers),
               t.req.body ? E("pre", {}, pretty(t.req.body)) : null] : null,
      t.res ? [E("h3", {}, `Output (response) — HTTP ${t.res.status ?? ""}${t.res.ms != null ? ` · ${t.res.ms} ms` : ""}`), kv(t.res.headers),
               t.res.body ? E("pre", {}, pretty(t.res.body)) : E("div", { class: "muted" }, "Empty body")] : null)));
  });
  return tr;
};

const testsTable = (list) => {
  const box = E("div");
  let mode = list.some((t) => t.verdict === "fail") ? "fail" : "all";
  const draw = () => {
    box.innerHTML = "";
    const shown = mode === "all" ? list : list.filter((t) => t.verdict === mode);
    const fb = E("div", { class: "filters" }, ["fail", "pass", "error", "info", "all"].map((m) => {
      const n = m === "all" ? list.length : list.filter((t) => t.verdict === m).length;
      return n || m === "all" ? E("button", { class: mode === m ? "on" : "", onclick: () => { mode = m; draw(); } }, `${m === "all" ? "All" : m} (${n})`) : null;
    }));
    const LIMIT = 300;
    const t = E("table", {}, E("thead", {}, E("tr", {}, E("th", {}, "#"), E("th", {}, "Severity"), E("th", {}, "Test"), E("th", {}, "What was tested / what went wrong"), E("th", {}, "HTTP"), E("th", {}, "Result"))),
      E("tbody", {}, shown.slice(0, LIMIT).map(testRow)));
    box.append(fb, t, shown.length > LIMIT ? E("p", { class: "muted" }, `Showing ${LIMIT} of ${shown.length}. The CSV/NDJSON downloads have all of them.`) : null);
  };
  draw();
  return box;
};

app.append(E("h2", {}, "Details per API"));
D.apis.forEach((a) => {
  const sec = E("section", { class: "panel api", id: slug(a.operation) },
    E("div", { class: "api-head" }, method(a.method), E("span", { class: "p" }, a.path), E("span", { class: "badge b-" + a.verdict }, VERDICT[a.verdict]),
      a.secured ? E("span", { class: "muted" }, "🔒 needs login") : E("span", { class: "muted" }, "public")),
    a.summary ? E("div", { class: "muted" }, a.summary) : null,
    a.access && a.access.status !== "ok" ? E("div", { class: "access " + a.access.status }, E("b", { class: "a-" + a.access.status },
      ACCESS[a.access.status] + ". "), a.access.reason.replace(/^[^:]+: (.)/, (_, c) => c.toUpperCase())) : null,
    E("h3", {}, "What was tested"),
    E("table", {}, E("tbody", {}, a.tests.map((t) => E("tr", {}, E("td", { style: "width:220px" }, t.test),
      E("td", { style: "width:150px", class: "s-" + t.status }, STATUS[t.status][0] + " " + STATUS[t.status][1]), E("td", {}, t.reason))))));
  const fs = D.findings[a.operation] || [];
  if (fs.length) sec.append(E("h3", {}, `Problems found (${fs.length})`), E("table", {}, E("tbody", {}, fs.map((f) =>
    E("tr", {}, E("td", { style: "width:90px" }, sevBadge(f.severity)), E("td", {}, f.title,
      f.spec_issue ? E("span", { class: "tag", title: "The API and the Swagger disagree. Either one may be wrong." }, r.lenient ? "Swagger problem" : "API vs Swagger") : null,
      f.fix ? E("div", { class: "fix" }, E("b", {}, "How to fix: "), f.fix) : null,
      f.detail ? E("details", {}, E("summary", { class: "muted", style: "font-weight:400" }, "details"), E("pre", {}, f.detail)) : null))))));
  const ts = D.tests[a.operation] || [];
  if (ts.length) sec.append(E("h3", {}, `Every test sent to this API (${ts.length}) — click a row for the full input and output`), testsTable(ts));
  app.append(sec);
});
const global = [...(D.tests[""] || [])];
const gf = D.findings[""] || [];
if (global.length || gf.length) {
  const sec = E("section", { class: "panel" }, E("h2", { style: "margin-top:0" }, "Not tied to one API"),
    E("div", { class: "muted" }, "Whole-Swagger checks, scan summaries and requests to URLs that aren't in the Swagger."));
  if (gf.length) sec.append(E("h3", {}, `Problems (${gf.length})`), E("ul", {}, gf.map((f) => E("li", {}, E("b", { class: "sev-" + f.severity }, f.severity.toUpperCase() + " "), f.title))));
  if (global.length) sec.append(testsTable(global));
  app.append(sec);
}
app.append(E("p", { class: "muted" }, `Generated by sprat · ${fmt(D.run.generated)} · tokens and API keys are masked.`));
</script></body></html>
"""
