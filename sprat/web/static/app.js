"use strict";

/* ================= utilities ================= */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const SEVS = ["critical", "high", "medium", "low", "info"];
const METHOD_ORDER = ["get", "post", "put", "patch", "delete", "head", "options"];
const STAGE_INFO = {
  lint: "Spec quality: missing schemas, bad refs, naming (Spectral)",
  conformance: "Responses match the declared types; fuzzing, 500s, undocumented status codes (Schemathesis)",
  types: "Each request-body field gets wrong data types (\"1\" for int, \"true\"/1 for bool…); must be rejected",
  authz: "No/invalid tokens on secured endpoints, cross-user (BOLA) access, stack-trace leaks, headers",
  zap: "OWASP ZAP API scan: injection, misconfiguration (Docker)",
};

let env = { stages: Object.keys(STAGE_INFO), available: {}, reasons: {} };
let timer = null;           // the current page's poll timer
let pageToken = 0;          // bumps on navigation so stale async renders are dropped

async function api(path, opts = {}) {
  const r = await fetch(path, { headers: { "Content-Type": "application/json" }, ...opts });
  const ct = r.headers.get("content-type") || "";
  const body = ct.includes("json") ? await r.json() : await r.text();
  if (!r.ok) throw new Error(typeof body === "string" ? body : body.detail || JSON.stringify(body));
  return body;
}
const post = (path, data) => api(path, { method: "POST", body: JSON.stringify(data ?? {}) });

function toast(msg, err = false) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast" + (err ? " err" : "");
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => (t.hidden = true), err ? 6000 : 2500);
}

function fmtTime(t) { return t ? new Date(t * 1000).toLocaleString() : ""; }
function fmtAgo(t) {
  if (!t) return "";
  const s = Date.now() / 1000 - t;
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(t * 1000).toLocaleDateString();
}
function fmtDur(s) { return s == null ? "" : s < 60 ? `${s.toFixed(1)}s` : `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`; }
function methodBadge(m) { return `<span class="method ${esc(m)}">${esc(m.toUpperCase())}</span>`; }
function miniCounts(c) {
  if (!c) return "";
  const parts = SEVS.filter((s) => c[s] && s !== "info").map((s) => `<span class="${s}" title="${s}">${c[s]} ${s[0].toUpperCase()}</span>`);
  return parts.length ? `<span class="mini">${parts.join("")}</span>` : `<span class="mini"><span class="low" style="color:var(--ok)">clean</span></span>`;
}

function dialog(title, bodyHtml, buttons) {
  const d = $("#dialog");
  $("#dialogTitle").textContent = title;
  $("#dialogBody").innerHTML = bodyHtml;
  const acts = $("#dialogActions");
  acts.innerHTML = "";
  return new Promise((resolve) => {
    for (const b of buttons) {
      const el = document.createElement("button");
      el.className = b.cls || "secondary";
      el.textContent = b.label;
      el.addEventListener("click", () => { if (b.onClick) b.onClick(); d.close(); resolve(b.value); });
      acts.appendChild(el);
    }
    d.addEventListener("close", () => resolve(undefined), { once: true });
    d.showModal();
  });
}
const confirmDialog = (title, html, label = "Delete") =>
  dialog(title, html, [{ label, cls: "danger", value: true }, { label: "Cancel", value: false }]);

function crumbs(items) {
  $("#crumbs").innerHTML = items.map(([label, href]) => href ? `<a href="${href}">${esc(label)}</a>` : `<b>${esc(label)}</b>`).join(" › ");
}

/* ================= router ================= */

function route() {
  clearTimeout(timer);
  pageToken++;
  const h = location.hash.replace(/^#/, "") || "/";
  let m;
  if (h === "/") return pageProjects();
  if (h === "/new") return pageProjectForm(null);
  if ((m = h.match(/^\/p\/([\w-]+)(?:\/(\w+))?$/))) return pageProject(m[1], m[2] || "apis");
  if ((m = h.match(/^\/r\/([\w-]+)(?:\?(.*))?$/))) return pageRun(m[1], Object.fromEntries(new URLSearchParams(m[2] || "")));
  location.hash = "#/";
}

/* ================= projects list ================= */

async function pageProjects() {
  const tok = pageToken;
  crumbs([["Projects"]]);
  const view = $("#view");
  let projects;
  try { projects = await api("/api/projects"); } catch (e) { view.innerHTML = `<p class="error">${esc(e.message)}</p>`; return; }
  if (tok !== pageToken) return;
  if (!projects.length) {
    view.innerHTML = `<div class="empty panel"><h2>No projects yet</h2>
      <p>A project is one API application: its Swagger, base URL, test users and settings.<br>
      Enter the app's URL and sprat finds its Swagger and lists every API.</p>
      <button class="primary" onclick="location.hash='#/new'">+ New project</button></div>`;
    return;
  }
  view.innerHTML = `
    <div class="page-head"><div><h1>Projects</h1><div class="meta">${projects.length} project${projects.length === 1 ? "" : "s"}</div></div>
      <button class="primary" onclick="location.hash='#/new'">+ New project</button></div>
    <div class="cards">${projects.map(projectCard).join("")}</div>`;
  $$("[data-run-all]").forEach((b) => b.addEventListener("click", async () => {
    startProjectRun(b.dataset.runAll, []);
  }));
  $$("[data-stop]").forEach((b) => b.addEventListener("click", () => stopRun(b.dataset.stop).then(pageProjects)));
  if (projects.some((p) => p.running)) timer = setTimeout(() => tok === pageToken && pageProjects(), 3000);
}

function projectCard(p) {
  const si = p.spec_info || {};
  const last = p.last_run;
  const lastHtml = p.running
    ? `<span class="live">Running</span> <a href="#/r/${esc(p.running)}">view</a>`
    : last ? `<span class="status ${esc(last.status)}" style="font-size:11.5px;padding:1px 8px">${esc(last.status)}</span>
        ${miniCounts(last.counts)} <span class="muted">${esc(fmtAgo(last.started))}${last.partial ? " · selected APIs" : ""}</span>
        <a href="#/r/${esc(last.id)}">results</a>`
    : `<span class="muted">Never run</span>`;
  return `<div class="card">
    <h3><a href="#/p/${esc(p.id)}">${esc(p.name)}</a></h3>
    ${p.description ? `<div class="desc">${esc(p.description)}</div>` : ""}
    <div class="meta">${esc(si.title || "")} ${esc(si.api_version || "")} · <b>${p.operations - (p.excluded || 0)}</b> APIs tested${p.excluded ? ` · ${p.excluded} excluded` : ""}</div>
    <div class="spec">${esc(p.spec)}</div>
    <div class="last">${lastHtml}</div>
    <div class="toolbar">
      ${p.running ? `<button class="stop small" data-stop="${esc(p.running)}">■ Stop</button>`
                  : `<button class="primary small" data-run-all="${esc(p.id)}">▶ Run all APIs</button>`}
      <button class="secondary small" onclick="location.hash='#/p/${esc(p.id)}'">Open</button>
    </div></div>`;
}

/** Start a run; if the server says no token is set for APIs that need login, ask first. */
async function startProjectRun(pid, operations, force = false, stages = null) {
  try {
    const { id } = await post(`/api/projects/${pid}/runs`, stages ? { operations, force, stages } : { operations, force });
    location.hash = `#/r/${id}`;
  } catch (e) {
    let info = null;
    try { info = JSON.parse(e.message); } catch { /* plain error */ }
    if (info?.code !== "NO_TOKEN") return toast(e.message, true);
    const choice = await dialog("No token set", `<p>${esc(info.message)}</p>
      <p>Add user A's token under <b>Settings → Test users</b>, then run again.</p>`, [
      { label: "Open Settings", cls: "primary", value: "settings" },
      { label: "Run anyway", value: "force" },
      { label: "Cancel", value: null },
    ]);
    if (choice === "settings") location.hash = `#/p/${pid}/settings`;
    else if (choice === "force") startProjectRun(pid, operations, true, stages);
  }
}

async function stopRun(runId) {
  try { await post(`/api/runs/${runId}/cancel`); toast("Stopping…"); }
  catch (e) { toast(e.message, true); }
}

/* ================= project form (new + settings) ================= */

function stageChecks(selected) {
  return env.stages.map((s) => {
    const avail = env.available[s] !== false;
    const checked = (!selected || selected.includes(s));
    return `<label class="stage-opt ${avail ? "" : "disabled"}" title="${esc(env.reasons[s] || "")}">
      <input type="checkbox" name="stage" value="${s}" ${checked ? "checked" : ""}>
      <b>${s}</b><span>${esc(avail ? STAGE_INFO[s] : `${STAGE_INFO[s]}. Unavailable right now: ${env.reasons[s]}, so it will be reported as skipped.`)}</span></label>`;
  }).join("");
}

function pathParams(path) { return [...path.matchAll(/{(\w+)}/g)].map((m) => m[1]); }

function bolaRow(container, ops, sc = { method: "GET", path: "", params: {} }) {
  const row = document.createElement("div");
  row.className = "bola-row";
  row.innerHTML = `
    <select class="b-method">${["GET", "PUT", "PATCH", "DELETE", "POST"].map((m) => `<option ${m === sc.method ? "selected" : ""}>${m}</option>`).join("")}</select>
    <input class="b-path" list="opPaths" placeholder="/orders/{orderId}" value="${esc(sc.path)}">
    <button type="button" class="icon" title="Remove">✕</button>
    <div class="params"></div>`;
  const renderParams = () => {
    const box = $(".params", row);
    const prev = Object.fromEntries($$("input", box).map((i) => [i.dataset.k, i.value]));
    box.innerHTML = pathParams($(".b-path", row).value).map((k) =>
      `<label>${esc(k)} <input data-k="${esc(k)}" placeholder="owned by user A" value="${esc(prev[k] ?? sc.params?.[k] ?? "")}"></label>`).join("");
  };
  $(".b-path", row).addEventListener("input", renderParams);
  $(".b-path", row).addEventListener("change", (e) => {
    const op = ops.find((o) => o.path === e.target.value && o.method !== "post");
    if (op) $(".b-method", row).value = op.method.toUpperCase();
  });
  $(".icon", row).addEventListener("click", () => row.remove());
  container.appendChild(row);
  renderParams();
}

function readBola(container) {
  return $$(".bola-row", container).map((row) => ({
    method: $(".b-method", row).value,
    path: $(".b-path", row).value.trim(),
    params: Object.fromEntries($$(".params input", row).map((i) => [i.dataset.k, i.value.trim()])),
  })).filter((b) => b.path);
}

function apiListPreview(ops) {
  if (!ops?.length) return `<div class="none">This document has no operations.</div>`;
  return `<table class="apis">${groupOps(ops).map(([tag, list]) => `
    <tr class="group"><td colspan="3">${esc(tag)} <span class="count">${list.length}</span></td></tr>
    ${list.map((o) => `<tr class="op"><td style="width:70px">${methodBadge(o.method)}</td>
      <td class="path">${esc(o.path)}</td><td class="summ">${esc(o.summary)} ${o.secured ? '<span class="lock">🔒</span>' : ""}</td></tr>`).join("")}`).join("")}</table>`;
}

function groupOps(ops) {
  const groups = new Map();
  for (const o of ops) {
    const tag = o.tags?.[0] || (o.path.split("/").filter(Boolean)[0] ?? "/") ;
    if (!groups.has(tag)) groups.set(tag, []);
    groups.get(tag).push(o);
  }
  for (const list of groups.values())
    list.sort((a, b) => a.path.localeCompare(b.path) || METHOD_ORDER.indexOf(a.method) - METHOD_ORDER.indexOf(b.method));
  return [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]));
}

/* ---------- test users: paste headers, or log in automatically ---------- */

function userAuthHtml(k, title, who, headers, login) {
  const L = login || {};
  const auto = !!(login && login.url);
  const n = (x) => `${k}_${x}`;
  const sel = (name, opts, cur) => `<select name="${n(name)}">${opts.map(([v, l]) =>
    `<option value="${v}" ${v === cur ? "selected" : ""}>${esc(l)}</option>`).join("")}</select>`;
  return `<fieldset class="user-auth" data-user="${k}">
    <legend>${esc(title)} <small>${esc(who)}</small></legend>
    <div class="seg">
      <label><input type="radio" name="${n("mode")}" value="paste" ${auto ? "" : "checked"}> Paste a token / headers</label>
      <label><input type="radio" name="${n("mode")}" value="login" ${auto ? "checked" : ""}> Log in automatically</label>
    </div>
    <div data-mode="paste" ${auto ? "hidden" : ""}>
      <label class="field">Headers <small>one <code>Name: value</code> per line</small>
        <textarea name="${k === "a" ? "headers" : "headers_b"}" rows="2" placeholder="Authorization: Bearer \${TOKEN_${k.toUpperCase()}}">${esc(headers)}</textarea></label>
    </div>
    <div data-mode="login" ${auto ? "" : "hidden"}>
      <div class="grid-login">
        <label class="field">Method ${sel("method", [["POST", "POST"], ["GET", "GET"], ["PUT", "PUT"]], L.method || "POST")}</label>
        <label class="field">Login API URL <input name="${n("url")}" value="${esc(L.url || "")}" placeholder="https://auth.example.com/api/auth/login"></label>
      </div>
      <label class="field">Request body <small>write the password as a name like <code>\${NTT_PASSWORD}</code>; its value goes in Secrets below</small>
        <textarea name="${n("body")}" rows="3" placeholder='{"email": "qa-user@example.com", "password": "\${QA_PASSWORD}"}'>${esc(L.body || "")}</textarea></label>
      <div class="grid2">
        <label class="field">Body format ${sel("body_type", [["json", "JSON"], ["form", "Form (a=1&b=2)"], ["raw", "Raw text"]], L.body_type || "json")}</label>
        <label class="field">Extra login headers <small>optional, one per line</small>
          <textarea name="${n("lheaders")}" rows="1" placeholder="X-Tenant-Id: 42">${esc(Object.entries(L.headers || {}).map(([a, b]) => `${a}: ${b}`).join("\n"))}</textarea></label>
      </div>
      <details class="box" ${auto ? "" : "open"}><summary>Pick the token from a sample response</summary>
        <p class="hint">Paste one login response here and click the field that holds the token. The sample stays in your browser; it's never sent or saved.</p>
        <textarea data-sample="${k}" rows="4" placeholder='{"success": true, "data": {"accessToken": "eyJ…"}}'></textarea>
        <div data-fields="${k}" class="fields"></div>
      </details>
      <div class="grid2">
        <label class="field">Token is at <small>path in the response</small>
          <input name="${n("token_path")}" value="${esc(L.token_path || "")}" placeholder="data.accessToken"></label>
        <label class="field">Send the token as ${sel("token_type", [["bearer", "Bearer token (Authorization: Bearer …)"], ["header", "Custom header"], ["cookie", "Cookie"]], L.token_type || "bearer")}</label>
      </div>
      <div class="grid2" data-show="${k}-tokname">
        <label class="field" data-for="header">Header name <input name="${n("header_name")}" value="${esc(L.header_name && L.header_name !== "Authorization" ? L.header_name : "")}" placeholder="X-API-Key"></label>
        <label class="field" data-for="cookie">Cookie name <input name="${n("cookie_name")}" value="${esc(L.cookie_name || "")}" placeholder="session"></label>
      </div>
      <div class="grid2">
        <label class="field">Token expires ${sel("expiry", [["jwt", "Automatically, from the token (JWT exp)"], ["field", "From a field in the response"], ["fixed", "After a fixed time"]], L.expiry || "jwt")}</label>
        <label class="field" data-exp="field">Expiry field <small>seconds, or a date/time</small>
          <input name="${n("expiry_path")}" value="${esc(L.expiry_path || "")}" placeholder="data.expiresIn"></label>
        <label class="field" data-exp="fixed">Minutes <input type="number" min="1" name="${n("fixed_minutes")}" value="${L.fixed_minutes || 15}"></label>
      </div>
    </div>
    <div class="vars" data-vars="${k}"></div>
    <div data-mode="login" ${auto ? "" : "hidden"}>
      <div class="login-test"><button type="button" class="secondary small" data-act="testlogin">Test login</button>
        <span data-out="loginres"></span></div>
      <p class="hint">sprat logs in when a run starts and fetches a new token 30 seconds before the current one expires.</p>
    </div>
  </fieldset>`;
}

function readLogin(form, k) {
  const v = (x) => form.elements[`${k}_${x}`]?.value ?? "";
  if ((form.querySelector(`input[name=${k}_mode]:checked`) || {}).value !== "login") return null;
  const headers = {};
  v("lheaders").split("\n").forEach((line) => { const i = line.indexOf(":"); if (i > 0) headers[line.slice(0, i).trim()] = line.slice(i + 1).trim(); });
  const type = v("token_type");
  return {
    url: v("url").trim(), method: v("method"), body: v("body"), body_type: v("body_type"), headers,
    token_path: v("token_path").trim(), token_type: type,
    header_name: type === "header" ? (v("header_name").trim() || "Authorization") : "Authorization",
    cookie_name: type === "cookie" ? v("cookie_name").trim() : "",
    expiry: v("expiry"), expiry_path: v("expiry_path").trim(), fixed_minutes: parseInt(v("fixed_minutes"), 10) || 15,
  };
}

function jwtInfo(s) {
  if (typeof s !== "string" || !/^eyJ[\w-]+\.[\w-]+\.[\w-]*$/.test(s)) return null;
  try {
    const c = JSON.parse(atob(s.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    return c;
  } catch { return null; }
}

function leafPaths(o, prefix = "", out = []) {
  if (o && typeof o === "object") {
    if (Array.isArray(o)) o.slice(0, 20).forEach((v, i) => leafPaths(v, `${prefix}[${i}]`, out));
    else Object.entries(o).forEach(([k, v]) => leafPaths(v, prefix ? `${prefix}.${k}` : k, out));
  } else out.push([prefix, o]);
  return out;
}

function setupLogin(form, k, pid, pendingSecrets) {
  const box = form.querySelector(`fieldset[data-user=${k}]`);
  const el = (x) => form.elements[`${k}_${x}`];
  const sync = () => {
    const mode = (box.querySelector(`input[name=${k}_mode]:checked`) || {}).value;
    box.querySelectorAll("[data-mode=paste]").forEach((d) => (d.hidden = mode !== "paste"));
    box.querySelectorAll("[data-mode=login]").forEach((d) => (d.hidden = mode !== "login"));
    const tt = el("token_type").value;
    box.querySelector("[data-for=header]").hidden = tt !== "header";
    box.querySelector("[data-for=cookie]").hidden = tt !== "cookie";
    box.querySelector(`[data-show=${k}-tokname]`).hidden = tt === "bearer";
    const ex = el("expiry").value;
    box.querySelector("[data-exp=field]").hidden = ex !== "field";
    box.querySelector("[data-exp=fixed]").hidden = ex !== "fixed";
  };
  box.addEventListener("change", sync);
  sync();

  /* ${NAME} values: project secrets, stored encrypted by sprat and never shown again */
  const varsBox = box.querySelector(`[data-vars=${k}]`);
  const usedNames = () => {
    const mode = (box.querySelector(`input[name=${k}_mode]:checked`) || {}).value;
    const texts = mode === "login" ? [el("url").value, el("body").value, el("lheaders").value]
      : [form.elements[k === "a" ? "headers" : "headers_b"].value];
    const names = [];
    texts.forEach((t) => [...(t || "").matchAll(/\$\{(\w+)\}/g)].forEach((m) => names.includes(m[1]) || names.push(m[1])));
    return names;
  };
  let varsKey = null;
  const drawVars = async (force = false) => {
    const names = usedNames();
    const key = names.join(",");
    if (!force && key === varsKey) return;
    varsKey = key;
    if (!names.length) { varsBox.innerHTML = ""; return; }
    let st = [];
    try { st = await api(`/api/vars?${new URLSearchParams({ names: key, project: pid })}`); }
    catch (e) { varsBox.innerHTML = `<p class="error">${esc(e.message)}</p>`; return; }
    const label = (v) => v.error ? [esc(v.error), "error"]
      : pendingSecrets[v.name] ? ["● will be saved when you create the project", "muted"]
      : v.source === "project" ? ["✓ saved in this project (encrypted)", "ok-text"]
      : v.source === "environment" ? ["✓ taken from the server's environment variable", "ok-text"]
      : ["✕ no value yet", "error"];
    varsBox.innerHTML = `<h4>Secrets</h4>
      <p class="hint">Enter the value for each name used above. It's stored encrypted with this project and never shown again;
        it isn't included in exports, reports or logs.</p>
      <table class="vars-t">${st.map((v) => {
        const [text, cls] = label(v);
        const has = v.source === "project" || pendingSecrets[v.name];
        return `<tr data-var="${esc(v.name)}">
        <td><code>\${${esc(v.name)}}</code></td><td class="vs ${cls}">${text}</td>
        <td><input type="password" autocomplete="new-password" placeholder="${has ? "type a new value to replace it" : "value"}" ${v.error ? "disabled" : ""}></td>
        <td class="nowrap"><button type="button" class="primary small" data-setvar ${v.error ? "disabled" : ""}>${pid ? "Save" : "Keep"}</button>
          ${has ? `<button type="button" class="secondary small" data-clearvar>Remove</button>` : ""}</td></tr>`;
      }).join("")}</table>`;
  };
  ["url", "body", "lheaders"].forEach((x) => el(x)?.addEventListener("input", () => drawVars()));
  form.elements[k === "a" ? "headers" : "headers_b"].addEventListener("input", () => drawVars());
  box.addEventListener("change", (e) => { if (e.target.name === `${k}_mode`) drawVars(); });
  varsBox.addEventListener("click", async (e) => {
    const tr = e.target.closest("tr[data-var]");
    if (!tr) return;
    const name = tr.dataset.var;
    try {
      if (e.target.closest("[data-setvar]")) {
        const input = $("input[type=password]", tr);
        if (!input.value) return toast("Type the value first", true);
        if (pid) {
          await api(`/api/projects/${encodeURIComponent(pid)}/secrets/${encodeURIComponent(name)}`,
            { method: "PUT", body: JSON.stringify({ value: input.value }) });
          toast(`${name} saved (encrypted)`);
        } else {
          pendingSecrets[name] = input.value;  // new project: saved with "Create project"
          toast(`${name} will be saved when you create the project`);
        }
        input.value = "";
      } else if (e.target.closest("[data-clearvar]")) {
        if (pid) {
          await api(`/api/projects/${encodeURIComponent(pid)}/secrets/${encodeURIComponent(name)}`, { method: "DELETE" });
        }
        delete pendingSecrets[name];
        toast(`${name} removed`);
      } else return;
      drawVars(true);
    } catch (err) { toast(err.message, true); }
  });
  varsBox.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && e.target.type === "password") { e.preventDefault(); e.target.closest("tr").querySelector("[data-setvar]").click(); }
  });
  drawVars();

  const sample = box.querySelector(`[data-sample=${k}]`);
  const fields = box.querySelector(`[data-fields=${k}]`);
  sample.addEventListener("input", () => {
    let doc;
    try { doc = JSON.parse(sample.value); } catch { fields.innerHTML = sample.value.trim() ? `<p class="error">That isn't valid JSON yet.</p>` : ""; return; }
    const rows = leafPaths(doc);
    const now = Date.now() / 1000;
    fields.innerHTML = `<table class="pick">${rows.map(([path, val]) => {
      const j = jwtInfo(val);
      const looksExp = /exp|expire|ttl|valid/i.test(path) && (typeof val === "number" || /^\d+$|^\d{4}-\d\d-\d\d/.test(String(val)));
      const preview = j ? `JWT${j.exp ? ` · expires ${j.exp > now ? `in ${Math.round((j.exp - now) / 60)} min` : `${Math.round((now - j.exp) / 60)} min ago`}` : " · no exp"}${j.type ? ` · type ${esc(j.type)}` : ""}`
        : typeof val === "string" ? (val.length > 40 ? `“${esc(val.slice(0, 12))}…” (${val.length} chars)` : `“${esc(val)}”`) : esc(String(val));
      return `<tr><td><code>${esc(path)}</code></td><td class="muted">${preview}</td><td class="act">
        ${typeof val === "string" && val.length >= 16 ? `<button type="button" class="${j && j.type !== "refresh" ? "primary" : "secondary"} small" data-pick="${esc(path)}">Use as token</button>` : ""}
        ${looksExp ? `<button type="button" class="secondary small" data-pickexp="${esc(path)}">Use as expiry</button>` : ""}</td></tr>`;
    }).join("")}</table>`;
  });
  fields.addEventListener("click", (e) => {
    const b = e.target.closest("[data-pick],[data-pickexp]");
    if (!b) return;
    if (b.dataset.pick) {
      el("token_path").value = b.dataset.pick;
      const val = leafPaths(JSON.parse(sample.value)).find(([p]) => p === b.dataset.pick)?.[1];
      if (jwtInfo(val)?.exp) el("expiry").value = "jwt";
      toast(`Token path set to ${b.dataset.pick}`);
    } else {
      el("expiry").value = "field";
      el("expiry_path").value = b.dataset.pickexp;
      toast(`Expiry read from ${b.dataset.pickexp}`);
    }
    sync();
  });

  const res = box.querySelector("[data-out=loginres]");
  box.querySelector("[data-act=testlogin]").addEventListener("click", async () => {
    const login = readLogin(form, k);
    res.className = "muted"; res.textContent = "Logging in…";
    try {
      const r = await post("/api/login/test", { login, project_id: pid, secrets: pendingSecrets });
      const at = new Date(r.expires_at * 1000).toLocaleTimeString();
      const ref = new Date(r.refresh_at * 1000).toLocaleTimeString();
      res.className = "ok-text";
      res.textContent = `✓ Logged in (${r.header}: ${r.token_preview}). Token expires at ${at}, in ${Math.round(r.expires_in / 60)} min ` +
        `(from ${r.expiry_source}); sprat would renew it at ${ref}.`;
    } catch (e) { res.className = "error"; res.textContent = e.message; }
  });
}

/**
 * Renders the project form into `root`. `project` = null for a new project.
 * onSaved(id) is called after a successful save.
 */
function renderProjectForm(root, project, onSaved) {
  const isNew = !project;
  const p = project || { name: "", description: "", spec: "", base_url: "", headers: "", headers_b: "", stages: null,
    max_examples: 50, fail_on: "high", no_mutating_authz: false, lenient_spec: false, exclude_paths: [], bola: [], operations: [] };
  let ops = p.operations || [];
  let chosenSpec = p.spec;

  root.innerHTML = `<form class="form" autocomplete="off">
    <section class="panel">
      <h2 class="step"><span class="step-n">1</span> Find the APIs</h2>
      <label class="field">Application URL, Swagger UI page, or Swagger/OpenAPI JSON URL
        <div class="row"><input name="discover" placeholder="https://orders-staging.example.com" value="${esc(p.spec)}">
        <button type="button" class="primary" data-act="discover">Discover</button></div></label>
      <p class="hint">For an app root, sprat tries the usual locations: <code>/swagger/v1/swagger.json</code> (ASP.NET Core),
        <code>/openapi/v1.json</code> (.NET 9), <code>/api-docs</code> (swagger-ui-express), <code>/openapi.json</code>, <code>/v3/api-docs</code>, and more.</p>
      <div data-out="found"></div>
    </section>

    <section class="panel">
      <h2 class="step"><span class="step-n">2</span> Project</h2>
      <div class="grid2">
        <label class="field">Name <input name="name" required value="${esc(p.name)}" placeholder="Orders API"></label>
        <label class="field">Base URL <small>blank = from the spec</small>
          <input name="base_url" value="${esc(p.base_url)}" placeholder="${esc(p.spec_info?.base_url || "https://orders-staging.example.com")}"></label>
      </div>
      <label class="field">Description <input name="description" value="${esc(p.description)}" placeholder="Optional"></label>
      <label class="field">Spec URL <small>picked in step 1; you can also type it</small>
        <input name="spec" required value="${esc(p.spec)}"></label>
    </section>

    <section class="panel">
      <h2 class="step"><span class="step-n">3</span> Test users</h2>
      ${userAuthHtml("a", "User A", "the main test user", p.headers, p.login_a)}
      ${userAuthHtml("b", "User B", "a second, ordinary user from another organisation, for cross-user (BOLA) checks", p.headers_b, p.login_b)}
      <p class="hint">Write a name like <code>\${NTT_PASSWORD}</code> wherever a password, API key or token goes, then enter its value in the
        <b>Secrets</b> box that appears. Values are stored encrypted with this project.</p>
      <details class="box"><summary>Cross-user (BOLA) scenarios <span class="count" data-out="bolaCount">${p.bola.length}</span></summary>
        <p class="hint">Resources owned by <b>user A</b>. The tester checks A can access them, then replays the request as user B and flags any success.</p>
        <div data-out="bola"></div><datalist id="opPaths"></datalist>
        <button type="button" class="secondary small" data-act="addBola">+ Add scenario</button>
      </details>
    </section>

    <section class="panel">
      <h2 class="step"><span class="step-n">4</span> Tests</h2>
      <div class="stages">${stageChecks(p.stages)}</div>
      <details class="box"><summary>Advanced</summary>
        <div class="grid2">
          <label class="field">Fuzz examples per API <input name="max_examples" type="number" min="1" max="1000" value="${p.max_examples}"></label>
          <label class="field">Fail threshold <select name="fail_on">${["critical", "high", "medium", "low"].map((s) => `<option ${s === p.fail_on ? "selected" : ""}>${s}</option>`).join("")}</select></label>
        </div>
        <label class="check"><input name="no_mutating_authz" type="checkbox" ${p.no_mutating_authz ? "checked" : ""}> Auth checks: only send GET / HEAD / OPTIONS</label>
        <label class="check"><input name="lenient_spec" type="checkbox" ${p.lenient_spec ? "checked" : ""}> The Swagger isn't reliable (lenient mode)</label>
        <p class="hint" style="margin-top:-6px">Crashes, wrong types accepted, missing login checks, cross-user leaks and security alerts are still reported as usual.
          Mismatches with the Swagger (undocumented status codes, response shape, validation rules) are listed as <b>Swagger problems</b>
          with severity info, so they don't bury the real bugs or fail the run.</p>
        <label class="field">Exclude paths <small>regex, one per line</small>
          <textarea name="exclude_paths" rows="2" placeholder="^/internal/">${esc((p.exclude_paths || []).join("\n"))}</textarea></label>
      </details>
      <div class="warn">Run against <b>staging</b> only. Fuzzing and scans send thousands of requests, including POST/PUT/DELETE with junk data.</div>
    </section>

    <div class="actions">
      <button type="submit" class="primary">${isNew ? "Create project" : "Save settings"}</button>
      ${isNew ? `<button type="button" class="secondary" onclick="location.hash='#/'">Cancel</button>` : ""}
    </div>
    <p class="error" data-out="error" hidden></p>
  </form>`;

  const form = $("form", root);
  const f = (n) => form.elements[n];
  const pendingSecrets = {};  // typed in a new project's form; saved (encrypted) when it's created
  setupLogin(form, "a", project?.id || "", pendingSecrets);
  setupLogin(form, "b", project?.id || "", pendingSecrets);
  const bolaBox = $("[data-out=bola]", root);
  const setOpPaths = () => {
    $("#opPaths").innerHTML = [...new Set(ops.filter((o) => o.path_params.length).map((o) => o.path))].map((x) => `<option value="${esc(x)}">`).join("");
  };
  setOpPaths();
  (p.bola || []).forEach((b) => bolaRow(bolaBox, ops, b));
  $("[data-act=addBola]", root).addEventListener("click", () => {
    bolaRow(bolaBox, ops);
    $("[data-out=bolaCount]", root).textContent = $$(".bola-row", bolaBox).length;
  });

  async function doDiscover() {
    const url = f("discover").value.trim();
    if (!url) return;
    const out = $("[data-out=found]", root);
    out.innerHTML = `<p class="muted">Looking for Swagger/OpenAPI documents…</p>`;
    try {
      const res = await post("/api/discover", { url, headers: f("headers").value });
      if (!res.specs.length) {
        out.innerHTML = `<p class="error">${esc(res.message)}</p>
          <p class="hint">Check the app is running and reachable from this machine. If the spec lives somewhere unusual, paste its exact URL.
          If the spec itself needs a token, fill in User A headers (step 3) first and discover again.</p>`;
        return;
      }
      out.innerHTML = `<p class="hint">Found ${res.specs.length} document${res.specs.length > 1 ? "s" : ""}. Pick the one this project tests${res.specs.length > 1 ? " (create one project per document if you want to test several)" : ""}.</p>
        <div class="found">${res.specs.map((s, i) => `
          <label class="found-item"><input type="radio" name="pick" value="${i}" ${i === 0 ? "checked" : ""}>
            <span><b>${esc(s.title || "Untitled API")}</b> ${esc(s.api_version)} · ${s.spec_version === "swagger2" ? "Swagger 2.0" : "OpenAPI 3"}${s.embedded ? " · embedded in Swagger UI page" : ""}</span>
            <span><b>${s.operations}</b> APIs</span>
            <span class="u">${esc(s.url)}${s.error ? ` <span class="error">${esc(s.error)}</span>` : ""}</span></label>`).join("")}</div>
        <div class="preview" data-out="preview"></div>`;
      const pick = (i) => {
        const s = res.specs[i];
        chosenSpec = s.url;
        ops = s.ops || [];
        f("spec").value = s.url;
        if (!f("name").value && s.title) f("name").value = s.title;
        f("base_url").placeholder = s.base_url || "Not in the spec: required";
        $("[data-out=preview]", root).innerHTML = apiListPreview(ops);
        setOpPaths();
      };
      $$("input[name=pick]", out).forEach((r) => r.addEventListener("change", () => pick(+r.value)));
      pick(0);
    } catch (e) {
      out.innerHTML = `<p class="error">${esc(e.message)}</p>`;
    }
  }
  $("[data-act=discover]", root).addEventListener("click", doDiscover);
  f("discover").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); doDiscover(); } });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const err = $("[data-out=error]", root);
    err.hidden = true;
    const body = {
      name: f("name").value.trim(), description: f("description").value.trim(),
      spec: f("spec").value.trim() || chosenSpec, base_url: f("base_url").value.trim(),
      headers: f("headers").value, headers_b: f("headers_b").value,
      stages: $$("input[name=stage]:checked", form).map((i) => i.value),
      max_examples: parseInt(f("max_examples").value, 10) || 50, fail_on: f("fail_on").value,
      no_mutating_authz: f("no_mutating_authz").checked, lenient_spec: f("lenient_spec").checked,
      exclude_paths: f("exclude_paths").value.split("\n").map((s) => s.trim()).filter(Boolean),
      bola: readBola(bolaBox),
      login_a: readLogin(form, "a"), login_b: readLogin(form, "b"),
      secrets: pendingSecrets,
    };
    if (!body.spec) { err.textContent = "Pick or enter a spec URL (step 1)."; err.hidden = false; return; }
    if (!body.stages.length) { err.textContent = "Select at least one test."; err.hidden = false; return; }
    const btn = $("button[type=submit]", form);
    btn.disabled = true;
    try {
      const id = isNew ? (await post("/api/projects", body)).id
        : (await api(`/api/projects/${project.id}`, { method: "PUT", body: JSON.stringify(body) }), project.id);
      onSaved(id);
    } catch (ex) {
      err.textContent = ex.message; err.hidden = false;
    } finally { btn.disabled = false; }
  });
}

function pageProjectForm() {
  crumbs([["Projects", "#/"], ["New project"]]);
  const view = $("#view");
  view.innerHTML = `<div class="page-head"><div><h1>New project</h1>
    <div class="meta">One project = one API application and its Swagger document.</div></div></div><div data-out="form"></div>`;
  renderProjectForm($("[data-out=form]", view), null, (id) => { toast("Project created"); location.hash = `#/p/${id}`; });
}

/* ================= project page ================= */

const reportCache = new Map();
async function getReport(runId) {
  if (!reportCache.has(runId)) reportCache.set(runId, api(`/api/runs/${runId}`).then((r) => r.report));
  return reportCache.get(runId);
}

async function pageProject(pid, tab) {
  const tok = pageToken;
  const view = $("#view");
  let p;
  try { p = await api(`/api/projects/${pid}`); } catch (e) { view.innerHTML = `<p class="error">${esc(e.message)}</p>`; return; }
  if (tok !== pageToken) return;
  crumbs([["Projects", "#/"], [p.name]]);
  const si = p.spec_info || {};
  const testable = p.operations.filter((o) => !o.excluded);
  const nExcluded = p.operations.length - testable.length;
  const selected = new Set(JSON.parse(sessionStorage.getItem(`sel.${pid}`) || "[]").filter((l) => testable.some((o) => o.label === l)));
  const saveSel = () => sessionStorage.setItem(`sel.${pid}`, JSON.stringify([...selected]));

  view.innerHTML = `
    <div class="page-head">
      <div><h1>${esc(p.name)}</h1>
        <div class="meta">${p.description ? esc(p.description) + " · " : ""}${esc(si.title || "")} ${esc(si.api_version || "")} ·
          ${si.version === "swagger2" ? "Swagger 2.0" : "OpenAPI 3"} · <b>${p.operations.length}</b> APIs${nExcluded
            ? ` · <b>${nExcluded}</b> excluded in <a href="#/p/${esc(pid)}/settings">Settings</a>` : ""}</div>
        <div class="meta">Spec <code>${esc(p.spec)}</code> → <code>${esc(p.base_url || si.base_url || "no base URL")}</code>
          · API list refreshed ${esc(fmtAgo(p.refreshed))}</div></div>
      <div class="toolbar">
        <button class="secondary small" data-act="refresh" title="Reload the Swagger and update the API list">↻ Refresh APIs</button>
        <button class="secondary small" data-act="yaml">Export CLI config</button>
        <button class="danger small" data-act="delete">Delete</button>
      </div>
    </div>
    <div class="runbar" data-out="runbar"></div>
    <div class="tabs" role="tablist">
      ${[["apis", `APIs <span class="count">${p.operations.length}</span>`], ["runs", "Runs"], ["settings", "Settings"]]
        .map(([k, l]) => `<button class="tab ${tab === k ? "active" : ""}" onclick="location.hash='#/p/${esc(pid)}/${k}'">${l}</button>`).join("")}
    </div>
    <div data-out="tab"></div>`;

  const runbar = $("[data-out=runbar]", view);
  // Stages the run buttons use. Starts as the project's stages; changing it here affects only the runs
  // started from this tab, not the project settings.
  const projStages = env.stages.filter((s) => (p.stages?.length ? p.stages : env.stages).includes(s));
  let runStages = null;
  try { runStages = JSON.parse(sessionStorage.getItem(`stages.${pid}`) || "null"); } catch { /* default */ }
  runStages = Array.isArray(runStages) ? env.stages.filter((s) => runStages.includes(s)) : [...projStages];
  const isDefault = () => runStages.join() === projStages.join();
  const saveStages = () => {
    try {
      if (isDefault()) sessionStorage.removeItem(`stages.${pid}`);
      else sessionStorage.setItem(`stages.${pid}`, JSON.stringify(runStages));
    } catch { /* storage unavailable: the choice lasts until the page is left */ }
  };
  const startRun = async (operations) => {
    if (!runStages.length) return toast("Pick at least one test stage.", true);
    await startProjectRun(pid, operations, false, runStages);
  };
  const stageChips = () => `<div class="stage-pick" role="group" aria-label="Tests to run">
      <span class="meta">Tests:</span>
      ${env.stages.map((s) => {
        const on = runStages.includes(s), off = env.available[s] === false;
        return `<label class="chip ${on ? "on" : ""} ${off ? "unavail" : ""}"
          title="${esc(STAGE_INFO[s] + (off ? `. Unavailable right now: ${env.reasons[s]}, so it will be reported as skipped.` : ""))}">
          <input type="checkbox" data-stage="${s}" ${on ? "checked" : ""}>${on ? "✓ " : ""}${s}</label>`;
      }).join("")}
      ${isDefault() ? "" : `<button class="link small" data-act="resetStages" title="Use the stages from Settings: ${esc(projStages.join(", "))}">Reset</button>`}
    </div>`;
  const renderRunbar = () => {
    const n = runStages.length;
    const what = n === env.stages.length ? "" : n === 1 ? ` (${runStages[0]} only)` : n ? ` (${n} tests)` : "";
    runbar.innerHTML = p.running
      ? `<span class="live">Test running</span> <a href="#/r/${esc(p.running)}">Watch progress</a><span class="grow"></span>
         <button class="stop" data-act="stop">■ Stop</button>`
      : `<button class="${selected.size ? "secondary" : "primary"}" data-act="runAll" ${testable.length && n ? "" : "disabled"}>▶ Run all ${testable.length} API${testable.length === 1 ? "" : "s"}${esc(what)}</button>
         ${nExcluded ? `<span class="meta">${nExcluded} excluded</span>` : ""}
         <button class="${selected.size ? "primary" : "secondary"}" data-act="runSel" ${selected.size && n ? "" : "disabled"}>▶ Run selected (${selected.size})${esc(what)}</button>
         <span class="grow"></span>${stageChips()}`;
    $("[data-act=runAll]", runbar)?.addEventListener("click", () => startRun([]));
    $("[data-act=runSel]", runbar)?.addEventListener("click", () => startRun([...selected]));
    $("[data-act=stop]", runbar)?.addEventListener("click", () => stopRun(p.running).then(() => route()));
    $("[data-act=resetStages]", runbar)?.addEventListener("click", () => { runStages = [...projStages]; saveStages(); renderRunbar(); });
  };
  runbar.addEventListener("change", (e) => {
    const st = e.target.dataset.stage;
    if (!st) return;
    runStages = env.stages.filter((s) => (s === st ? e.target.checked : runStages.includes(s)));
    saveStages();
    renderRunbar();
  });
  renderRunbar();

  $("[data-act=refresh]", view).addEventListener("click", async () => {
    try { const r = await post(`/api/projects/${pid}/refresh`); toast(`API list updated: ${r.operations} APIs`); route(); }
    catch (e) { toast(e.message, true); }
  });
  $("[data-act=yaml]", view).addEventListener("click", async () => {
    const text = await api(`/api/projects/${pid}/yaml`);
    dialog("CLI config", `<p class="hint">Save as <code>${esc(pid)}.yaml</code> and run <code>sprat run --config ${esc(pid)}.yaml</code>.
      <code>\${VAR}</code> values are read from the environment; replace <code>&lt;set me&gt;</code> or pass tokens with <code>-H</code>.</p>
      <textarea rows="18" readonly>${esc(text)}</textarea>`,
      [{ label: "Copy", cls: "primary", onClick: () => navigator.clipboard.writeText(text) }, { label: "Close" }]);
  });
  $("[data-act=delete]", view).addEventListener("click", async () => {
    if (await confirmDialog(`Delete “${p.name}”?`, `<p>This deletes the project and <b>all of its test runs</b> from disk. It doesn't touch the API itself.</p>`)) {
      try { await api(`/api/projects/${pid}`, { method: "DELETE" }); toast("Project deleted"); location.hash = "#/"; }
      catch (e) { toast(e.message, true); }
    }
  });

  const tabBox = $("[data-out=tab]", view);
  if (tab === "settings") {
    renderProjectForm(tabBox, p, () => { toast("Settings saved"); route(); });
  } else if (tab === "runs") {
    renderRunsTab(tabBox, pid);
  } else {
    renderApisTab(tabBox, p, selected, () => { saveSel(); renderRunbar(); }, startRun);
  }
  if (p.running) {  // refresh the page state when the run finishes
    timer = setTimeout(async function check() {
      if (tok !== pageToken) return;
      try {
        const r = await api(`/api/runs/${p.running}`);
        if (!["running", "stopping"].includes(r.status)) { reportCache.clear(); return route(); }
      } catch { /* ignore */ }
      timer = setTimeout(check, 3000);
    }, 3000);
  }
}

function renderApisTab(root, p, selected, onSelChange, startRun) {
  const ops = p.operations;
  if (!ops.length) {
    root.innerHTML = `<div class="none">The spec has no operations. Use <b>Refresh APIs</b> after the app's Swagger is fixed.</div>`;
    return;
  }
  root.innerHTML = `
    <div class="api-filter">
      <input type="search" placeholder="Filter by path, method, summary…" data-out="q">
      <label class="check" style="margin:0"><input type="checkbox" data-out="onlyIssues"> Only APIs with issues</label>
    </div>
    <table class="apis"><thead><tr>
      <th class="c"><input type="checkbox" data-act="all" title="Select all"></th><th style="width:76px">Method</th><th>Path</th>
      <th class="res">Last result</th><th class="act"></th></tr></thead><tbody data-out="rows"></tbody></table>
    <p class="hint">Last result = for each test stage, its newest result on that API (stages can come from different runs).
      <b>*</b> = some of the project's stages haven't run on it yet, or a run was stopped early. Click a result to see its findings.</p>`;
  const tbody = $("[data-out=rows]", root);
  const q = $("[data-out=q]", root), onlyIssues = $("[data-out=onlyIssues]", root);

  const notRun = (s) => (p.stages || []).filter((x) => !s.stages?.[x]);
  const resCell = (o) => {
    const s = p.op_status[o.label];
    if (!s) return `<span class="untested">not tested yet</span>`;
    const n = Object.entries(s.counts).filter(([k]) => k !== "info").reduce((a, [, v]) => a + v, 0);
    const missing = notRun(s);
    const title = `Tested by: ${Object.keys(s.stages || {}).join(", ")}${missing.length ? `. Not run yet: ${missing.join(", ")}` : ""}`;
    return n ? `<button class="res-btn ${s.max}" data-detail="${esc(o.label)}" title="${esc(title)}">${n} issue${n > 1 ? "s" : ""} · ${s.max}${s.partial ? "*" : ""}</button>`
             : `<button class="res-btn clean" data-detail="${esc(o.label)}" title="${esc(title)}">✓ clean${s.partial ? "*" : ""}</button>`;
  };

  const render = () => {
    const term = q.value.toLowerCase();
    const shown = ops.filter((o) => (!term || `${o.method} ${o.path} ${o.summary} ${o.tags.join(" ")}`.toLowerCase().includes(term))
      && (!onlyIssues.checked || Object.keys(p.op_status[o.label]?.counts || {}).some((k) => k !== "info")));
    const allSel = (list) => list.some((o) => !o.excluded) && list.filter((o) => !o.excluded).every((o) => selected.has(o.label));
    tbody.innerHTML = groupOps(shown).map(([tag, list]) => `
      <tr class="group"><td class="c"><input type="checkbox" data-group="${esc(tag)}" ${allSel(list) ? "checked" : ""} ${list.every((o) => o.excluded) ? "disabled" : ""}></td>
        <td colspan="4">${esc(tag)} <span class="count">${list.length}</span></td></tr>
      ${list.map((o) => `<tr class="op ${o.deprecated ? "deprecated" : ""} ${o.excluded ? "excluded" : ""}" data-label="${esc(o.label)}">
        <td class="c"><input type="checkbox" data-op="${esc(o.label)}" ${selected.has(o.label) ? "checked" : ""} ${o.excluded ? "disabled" : ""}></td>
        <td>${methodBadge(o.method)}</td>
        <td><div class="path">${esc(o.path)} ${o.secured ? '<span class="lock" title="Spec says this needs auth">🔒</span>' : ""}
          ${o.excluded ? `<span class="tag-excluded" title="Matches Exclude paths in Settings; never tested">excluded</span>` : ""}
          ${p.examples?.[o.label] ? `<span class="tag-example" title="Tests start from your saved working request">example</span>` : ""}</div>
          ${o.summary ? `<div class="summ">${esc(o.summary)}</div>` : ""}</td>
        <td class="res">${o.excluded && !p.op_status[o.label] ? `<span class="untested">excluded</span>` : resCell(o)}</td>
        <td class="act"><button class="icon" data-example="${esc(o.label)}" title="Working example: the request this API's tests start from">✎</button>
          <button class="secondary small" data-run1="${esc(o.label)}" ${p.running || o.excluded ? "disabled" : ""}
          title="${o.excluded ? "Excluded in Settings" : "Test only this API"}">▶ Run</button></td>
      </tr>`).join("")}`).join("") || `<tr><td colspan="5" class="none">No APIs match.</td></tr>`;
    $("[data-act=all]", root).checked = allSel(shown);
  };
  render();
  q.addEventListener("input", render);
  onlyIssues.addEventListener("change", render);

  root.addEventListener("change", (e) => {
    const t = e.target;
    if (t.dataset.op) { t.checked ? selected.add(t.dataset.op) : selected.delete(t.dataset.op); }
    else if (t.dataset.group != null) {
      const list = groupOps(ops).find(([g]) => g === t.dataset.group)?.[1] || [];
      list.filter((o) => !o.excluded).forEach((o) => (t.checked ? selected.add(o.label) : selected.delete(o.label)));
    } else if (t.dataset.act === "all") {
      $$("tr.op:not(.excluded)", tbody).forEach((tr) => (t.checked ? selected.add(tr.dataset.label) : selected.delete(tr.dataset.label)));
    } else return;
    onSelChange();
    render();
  });
  root.addEventListener("click", async (e) => {
    const run1 = e.target.closest("[data-run1]");
    if (run1) return startRun([run1.dataset.run1]);
    const exb = e.target.closest("[data-example]");
    if (exb) return editExample(p, ops.find((o) => o.label === exb.dataset.example), () => route());
    const det = e.target.closest("[data-detail]");
    if (!det) return;
    const label = det.dataset.detail;
    const tr = det.closest("tr");
    if (tr.nextElementSibling?.classList.contains("detail")) { tr.nextElementSibling.remove(); return; }
    const s = p.op_status[label];
    const detail = document.createElement("tr");
    detail.className = "detail";
    detail.innerHTML = `<td colspan="5"><p class="muted">Loading…</p></td>`;
    tr.after(detail);
    const bySt = Object.entries(s.stages || {});
    const reps = new Map(await Promise.all([...new Set(bySt.map(([, r]) => r.run_id))].map(async (id) => [id, await getReport(id)])));
    const list = bySt.flatMap(([stage, r]) => (reps.get(r.run_id).stages.find((st) => st.name === stage)?.findings || [])
      .filter((f) => f.operation === label).map((f) => ({ ...f, stage })));
    const missing = notRun(s);
    $("td", detail).innerHTML = `<div class="meta stage-src" style="padding:8px 0">
        ${bySt.map(([stage, r]) => `<span><b>${esc(stage)}</b> <a href="#/r/${esc(r.run_id)}">${esc(fmtTime(r.started))}</a></span>`).join("")}
        ${missing.length ? `<span>Not run yet: ${esc(missing.join(", "))}</span>` : ""}
        <a href="#/r/${esc(s.run_id)}?${new URLSearchParams({ view: "log", op: label })}">Every test sent in the newest run →</a></div>
      ${findingsHtml(list) || `<div class="none">No findings for this API.</div>`}`;
  });
}

/** The working request an API's tests start from (instead of the Swagger's example). */
async function editExample(p, o, onChange, draft = null) {
  let info;
  try { info = await api(`/api/projects/${p.id}/example?${new URLSearchParams({ op: o.label })}`); }
  catch (e) { return toast(e.message, true); }
  const saved = info.saved, last = info.last;
  const pretty = (v) => v == null ? "" : JSON.stringify(v, null, 2);
  const start = draft || {
    body: pretty(saved ? saved.body : last?.body),
    path: pretty(saved?.path || (o.path_params.length ? Object.fromEntries(o.path_params.map((n) => [n, ""])) : null)),
    query: pretty(saved?.query || null),
  };
  const lastHtml = last ? `<div class="${last.accepted ? "hint" : "warn"}">The last run (${esc(fmtTime(last.started))}) sent the body below
      ${last.accepted ? `and the API <b>accepted</b> it (HTTP ${esc(last.status)}).` :
        `and the API <b>refused</b> it: HTTP ${esc(last.status)}${last.said ? ` — “${esc(last.said)}”` : ""}. Fix the values and save.`}
      <div class="muted" style="margin-top:4px"><code>${esc(last.url)}</code></div></div>` : "";
  const html = `<p class="hint">The wrong-type tests start from this request, and the behaviour tests send it as an example.
      Use values that really exist on the test environment (real IDs, a site name that exists). Your Swagger isn't changed.</p>
    ${saved ? `<p class="hint"><b>Saved.</b> Runs use this instead of the Swagger's example.</p>` : lastHtml}
    <label class="field">Request body (JSON)${o.has_body ? "" : " <small>this API has no body</small>"}
      <textarea rows="12" data-x="body" spellcheck="false" placeholder='{"name": "…"}'>${esc(start.body)}</textarea></label>
    <div class="grid2">
      <label class="field">Path parameters (JSON) <textarea rows="3" data-x="path" spellcheck="false" placeholder='{"id": "123"}'>${esc(start.path)}</textarea></label>
      <label class="field">Query parameters (JSON) <textarea rows="3" data-x="query" spellcheck="false" placeholder='{"siteId": "1"}'>${esc(start.query)}</textarea></label>
    </div>`;
  const read = () => Object.fromEntries(["body", "path", "query"].map((k) => [k, $(`#dialog [data-x=${k}]`).value]));
  let typed = null;
  const choice = await dialog(`Working example · ${o.label}`, html, [
    { label: "Save", cls: "primary", value: "save", onClick: () => (typed = read()) },
    ...(saved ? [{ label: "Remove", cls: "danger", value: "remove" }] : []),
    { label: "Cancel", value: null },
  ]);
  if (choice === "remove") {
    try { await api(`/api/projects/${p.id}/example?${new URLSearchParams({ op: o.label })}`, { method: "DELETE" }); toast("Example removed"); onChange(); }
    catch (e) { toast(e.message, true); }
    return;
  }
  if (choice !== "save") return;
  const parse = (k, what) => {
    const t = typed[k].trim();
    if (!t) return k === "body" ? null : {};
    const v = JSON.parse(t);
    if (k !== "body" && (typeof v !== "object" || Array.isArray(v) || v === null)) throw new Error(`${what} must be a JSON object like {"id": "123"}`);
    return k === "body" ? v : Object.fromEntries(Object.entries(v).filter(([, x]) => x !== "" && x != null).map(([n, x]) => [n, String(x)]));
  };
  let body;
  try { body = { op: o.label, body: parse("body", "Request body"), path: parse("path", "Path parameters"), query: parse("query", "Query parameters") }; }
  catch (e) { toast(`Not valid JSON: ${e.message}`, true); return editExample(p, o, onChange, typed); }
  try { await api(`/api/projects/${p.id}/example`, { method: "PUT", body: JSON.stringify(body) }); toast("Example saved. The next run starts from it."); onChange(); }
  catch (e) { toast(e.message, true); return editExample(p, o, onChange, typed); }
}

async function renderRunsTab(root, pid) {
  root.innerHTML = `<p class="muted">Loading…</p>`;
  const runs = await api(`/api/projects/${pid}/runs`);
  if (!runs.length) { root.innerHTML = `<div class="none">No runs yet. Use <b>Run all APIs</b> above.</div>`; return; }
  root.innerHTML = `<table class="runs"><thead><tr><th>Started</th><th>Scope</th><th>Tests</th><th>Status</th><th>Findings</th><th>Duration</th></tr></thead><tbody>
    ${runs.map((r) => `<tr data-run="${esc(r.id)}"><td>${esc(fmtTime(r.started))}</td>
      <td>${r.operations?.length ? `${r.operations.length} selected API${r.operations.length > 1 ? "s" : ""}` : "All APIs"}</td>
      <td class="meta">${esc((r.stages || []).join(", "))}</td>
      <td><span class="status ${esc(r.status)}" style="font-size:11.5px;padding:1px 8px">${esc(r.status)}</span></td>
      <td>${miniCounts(r.counts)}</td><td>${r.finished ? fmtDur(r.finished - r.started) : ""}</td></tr>`).join("")}</tbody></table>`;
  $$("tr[data-run]", root).forEach((tr) => tr.addEventListener("click", () => (location.hash = `#/r/${tr.dataset.run}`)));
}

/* ================= run page ================= */

function findingsHtml(list) {
  return list.slice(0, 500).map((f) => `
    <div class="finding"><details>
      <summary><span class="sev ${f.severity}">${f.severity}</span>
        <span>${esc(f.title)}<span class="stage-tag">${esc(f.stage)}</span>${f.spec_issue
          ? `<span class="stage-tag spec" title="The API and the Swagger disagree. Either one may be wrong.">API vs Swagger</span>` : ""}
          ${f.fix ? `<div class="fix"><b>How to fix:</b> ${esc(f.fix)}</div>` : ""}</span>
        <span class="where">${esc(f.endpoint)}</span></summary>
      <pre>${esc(f.detail || "No further detail.")}</pre>
    </details></div>`).join("") + (list.length > 500 ? `<div class="none">Showing 500 of ${list.length}. Narrow the filter.</div>` : "");
}

async function pageRun(runId, params = {}) {
  const tok = pageToken;
  const view = $("#view");
  const filter = { sev: null, stage: "all", op: params.op || "", q: "" };
  const logFilter = { stage: "", op: params.op || "", verdict: params.verdict || "", q: "" };
  let resultView = params.view === "log" ? "log" : "findings";
  let logTotal = null;
  let run;

  // Layout is built once; while the run is live only meta/toolbar/progress are updated in place,
  // so the Stop button isn't replaced under the user's cursor every poll.
  let shownStatus = null;
  const draw = () => {
    if (!$("[data-out=progress]", view)) {
      const proj = run.project_id ? [[run.project_name || run.project_id, `#/p/${run.project_id}`]] : [];
      crumbs([["Projects", "#/"], ...proj, [`Run ${fmtTime(run.started)}`]]);
      view.innerHTML = `
        <div class="page-head">
          <div><h1>${esc(run.project_name || "Test run")}</h1><div class="meta" data-out="meta"></div></div>
          <div class="toolbar" data-out="toolbar"></div>
        </div>
        <ol class="progress" data-out="progress"></ol>
        <div data-out="activity"></div>
        <div class="exports" data-out="exports"></div>
        <div class="tabs" data-out="viewtabs" role="tablist"></div>
        <div data-out="results"></div>
        <div data-out="log" hidden></div>`;
      drawExports();
      if (resultView === "log") drawLog();
    }
    const live = ["running", "stopping"].includes(run.status);
    const si = run.spec_info;
    const elapsed = (run.finished || Date.now() / 1000) - run.started;
    $("[data-out=meta]", view).innerHTML = `${run.operations?.length ? `<b>${run.operations.length}</b> selected API${run.operations.length > 1 ? "s" : ""}` : "All APIs"}
      · started ${esc(fmtTime(run.started))} · ${fmtDur(elapsed)}${si ? ` · ${si.operations} API${si.operations === 1 ? "" : "s"} ${live ? "in this run" : "tested"} → <code>${esc(si.base_url)}</code>` : ""}
      ${run.error ? `<div class="error">${esc(run.error)}</div>` : ""}`;
    if (shownStatus !== run.status) {
      shownStatus = run.status;
      $("[data-out=toolbar]", view).innerHTML = `<span class="status ${esc(run.status)}">${run.status === "stopping" ? "stopping…" : esc(run.status)}</span>
        ${run.status === "running" ? `<button class="stop" data-act="stop">■ Stop</button>` : ""}
        ${!live && run.project_id ? `<button class="secondary small" data-act="rerun">↻ Run again</button>` : ""}`;
      $("[data-act=stop]", view)?.addEventListener("click", async (e) => { e.target.disabled = true; await stopRun(runId); poll(); });
      $("[data-act=rerun]", view)?.addEventListener("click", async () => {
        startProjectRun(run.project_id, run.operations || []);
      });
    }
    $("[data-out=progress]", view).innerHTML = run.stages_requested.map((s) => {
        const st = run.stages[s] || { status: "pending" };
        const label = st.status === "running" ? "running…" : st.status === "pending" ? (run.status === "stopping" ? "will not run" : "waiting")
          : `${st.status}${st.findings != null && st.status !== "cancelled" ? ` · ${st.findings} finding${st.findings === 1 ? "" : "s"}` : ""}`;
        const dur = st.status === "running" && st.started ? Date.now() / 1000 - st.started : st.duration;
        return `<li class="${esc(st.status)}"><div class="name">${s}<small>${fmtDur(dur)}</small></div>
          <div class="st">${esc(label)}</div>${st.note ? `<div class="note">${esc(String(st.note).slice(0, 220))}</div>` : ""}</li>`;
      }).join("");
    drawActivity(live);
    drawViewTabs();
    $("[data-out=results]", view).hidden = resultView !== "findings";
    $("[data-out=log]", view).hidden = resultView !== "log";
    if (run.report) drawResults();
    else if (live) $("[data-out=results]", view).innerHTML = `<p class="muted">Findings appear here when the run finishes.
      The <b>Test log</b> tab already shows every request sent so far. You can leave this page; the test keeps running.</p>`;
  };

  const drawExports = () => {
    const u = (k) => `/api/runs/${encodeURIComponent(runId)}/download/${k}`;
    const done = !["running", "stopping"].includes(run.status);
    $("[data-out=exports]", view).innerHTML = `${done ? `<a class="btn-link primary-link" href="${u("view")}" target="_blank" rel="noopener"
        title="Per API: what was tested, what wasn't and why, problems found, every input and output">📄 Open HTML report</a>
      <a class="btn-link" href="${u("html")}" download>⬇ HTML report</a>` : ""}
      <span class="meta">Download</span>
      <a class="btn-link" href="${u("zip")}" download title="HTML report, test log, findings, spec and every tool's raw output">⬇ Everything (ZIP)</a>
      <a class="btn-link" href="${u("csv")}" download title="One row per test; opens in Excel">⬇ Test log (CSV)</a>
      <a class="btn-link" href="${u("ndjson")}" download title="One JSON object per test, with full requests and responses">⬇ Test log (NDJSON)</a>`;
  };

  const drawViewTabs = () => {
    const nFind = run.report ? all().length : null;
    $("[data-out=viewtabs]", view).innerHTML = [
      ["findings", `Findings ${nFind != null ? `<span class="count">${nFind}</span>` : ""}`],
      ["log", `Test log ${logTotal != null ? `<span class="count">${logTotal}</span>` : ""}`],
    ].map(([k, l]) => `<button class="tab ${resultView === k ? "active" : ""}" data-view="${k}" role="tab">${l}</button>`).join("");
    $$("[data-view]", view).forEach((b) => b.addEventListener("click", () => {
      resultView = b.dataset.view;
      $("[data-out=results]", view).hidden = resultView !== "findings";
      $("[data-out=log]", view).hidden = resultView !== "log";
      if (resultView === "log") drawLog();
      drawViewTabs();
    }));
  };

  /* ---------- test log ---------- */
  let logItems = [];
  const logQuery = (offset) => new URLSearchParams({ ...logFilter, offset, limit: 100 }).toString();

  const drawLog = async (append = false) => {
    const box = $("[data-out=log]", view);
    let res;
    try { res = await api(`/api/runs/${runId}/log?${logQuery(append ? logItems.length : 0)}`); }
    catch (e) { box.innerHTML = `<p class="error">${esc(e.message)}</p>`; return; }
    if (tok !== pageToken) return;
    if (!res.available) {
      box.innerHTML = `<div class="none">No test log for this run yet${["running", "stopping"].includes(run.status) ? ". It starts once the spec is loaded." : " (runs made before this feature don't have one)."}</div>`;
      return;
    }
    logItems = append ? logItems.concat(res.items) : res.items;
    const filtered = logFilter.stage || logFilter.op || logFilter.verdict || logFilter.q;
    if (!filtered) logTotal = res.total;
    drawViewTabs();
    const live = ["running", "stopping"].includes(run.status);
    const stageTotal = Object.values(res.stages).reduce((a, b) => a + b, 0);
    if (!append) {
      box.innerHTML = `
        <div class="filters">
          <div class="tabs">${[["", "all", stageTotal], ...Object.entries(res.stages).map(([s, n]) => [s, s, n])].map(([k, l, n]) =>
            `<button class="tab ${logFilter.stage === k ? "active" : ""}" data-lstage="${esc(k)}">${esc(l)} <span class="count">${n}</span></button>`).join("")}</div>
          <div class="right">
            <select data-out="lop"><option value="">All APIs</option><option value="-" ${logFilter.op === "-" ? "selected" : ""}>Not tied to one API</option>
              ${[...new Set([...res.operations, logFilter.op].filter((o) => o && o !== "-"))].sort().map((o) => `<option ${logFilter.op === o ? "selected" : ""}>${esc(o)}</option>`).join("")}</select>
            <input type="search" placeholder="Search requests, bodies…" data-out="lq" value="${esc(logFilter.q)}">
          </div>
        </div>
        <div class="summary">${["fail", "pass", "error", "info"].map((v) =>
          `<button class="pill v-${v} ${res.verdicts[v] ? "" : "zero"} ${logFilter.verdict === v ? "active" : ""}" data-lverdict="${v}"><b>${res.verdicts[v] || 0}</b>${v}</button>`).join("")}
          ${live ? `<button class="secondary small" data-act="lrefresh">↻ Refresh</button>` : ""}</div>
        <table class="log"><thead><tr><th>#</th><th>Severity</th><th>Stage</th><th>API</th><th>Scenario tested</th><th>Status</th><th>Verdict</th></tr></thead>
          <tbody data-out="lrows"></tbody></table>
        <div data-out="lmore"></div>`;
      $$("[data-lstage]", box).forEach((b) => b.addEventListener("click", () => { logFilter.stage = b.dataset.lstage; drawLog(); }));
      $$("[data-lverdict]", box).forEach((b) => b.addEventListener("click", () => {
        logFilter.verdict = logFilter.verdict === b.dataset.lverdict ? "" : b.dataset.lverdict; drawLog(); }));
      $("[data-out=lop]", box).addEventListener("change", (e) => { logFilter.op = e.target.value; drawLog(); });
      let deb;
      $("[data-out=lq]", box).addEventListener("input", (e) => {
        clearTimeout(deb); deb = setTimeout(() => { logFilter.q = e.target.value; drawLog().then(() => {
          const i = $("[data-out=lq]", box); i.focus(); i.setSelectionRange(i.value.length, i.value.length); }); }, 350);
      });
      $("[data-act=lrefresh]", box)?.addEventListener("click", () => drawLog());
      $("[data-out=lrows]", box).addEventListener("click", (e) => {
        const tr = e.target.closest("tr[data-seq]");
        if (tr) toggleEntry(tr);
      });
    }
    $("[data-out=lrows]", box).insertAdjacentHTML("beforeend", res.items.map(logRow).join("") ||
      (append ? "" : `<tr><td colspan="7" class="none">No tests match.</td></tr>`));
    $("[data-out=lmore]", box).innerHTML = logItems.length < res.total
      ? `<div class="actions"><button class="secondary" data-act="lmore">Load more (${logItems.length} of ${res.total})</button></div>`
      : `<p class="hint">${res.total} test${res.total === 1 ? "" : "s"} shown.</p>`;
    $("[data-act=lmore]", box)?.addEventListener("click", () => drawLog(true));
  };

  const logRow = (e) => `<tr data-seq="${e.seq}" class="lr v-${esc(e.verdict)}">
    <td class="n">${e.seq}</td><td class="sv">${e.severity ? `<span class="sev ${esc(e.severity)}" title="${esc(e.cause || "")}">${esc(e.severity)}</span>` : ""}</td>
    <td class="st">${esc(e.stage)}</td>
    <td class="op">${e.operation ? opLabel(e.operation) : `<span class="muted">${esc(e.method || "")}</span>`}</td>
    <td class="sc"><div>${esc(e.scenario)}</div>${e.verdict !== "pass" && (e.explanation || e.problem)
      ? `<div class="pr v-${esc(e.verdict)}">${esc(e.explanation || e.problem)}</div>` : ""}</td>
    <td class="code">${e.status ?? ""}</td><td><span class="verdict v-${esc(e.verdict)}">${esc(e.verdict)}</span></td></tr>`;

  const kv = (obj) => obj && Object.keys(obj).length
    ? `<table class="kv">${Object.entries(obj).map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`).join("")}</table>` : `<span class="muted">none</span>`;
  const pretty = (s) => { if (s == null || s === "") return ""; try { return JSON.stringify(JSON.parse(s), null, 2); } catch { return s; } };

  const toggleEntry = async (tr) => {
    if (tr.nextElementSibling?.classList.contains("ldetail")) { tr.nextElementSibling.remove(); return; }
    const d = document.createElement("tr");
    d.className = "ldetail";
    d.innerHTML = `<td colspan="7"><p class="muted">Loading…</p></td>`;
    tr.after(d);
    const e = await api(`/api/runs/${runId}/log/${tr.dataset.seq}`);
    const rq = e.request, rs = e.response, det = { ...e.details };
    const failures = det.failures; delete det.failures;
    $("td", d).innerHTML = `<div class="entry">
      <div class="grid2">
        <div><h4>Scenario</h4><p>${esc(e.scenario)}</p><h4>Expected</h4><p>${esc(e.expected || "—")}</p></div>
        <div><h4>Result</h4><p><span class="verdict v-${esc(e.verdict)}">${esc(e.verdict)}</span> · ${esc(new Date(e.ts * 1000).toLocaleString())}</p>
          ${e.explanation ? `<p class="v-${esc(e.verdict)}">${esc(e.explanation)}</p>` : ""}
          ${failures?.length > 1 ? `<h4>Every failed check</h4><ul class="fails">${failures.map((f) => `<li>${esc(f)}</li>`).join("")}</ul>` : ""}
          ${e.triage?.severity ? `<h4>Severity</h4><p><span class="sev ${esc(e.triage.severity)}">${esc(e.triage.severity)}</span>
            ${e.triage.spec_issue ? `<span class="muted">· the API and the Swagger disagree</span>` : ""}</p>
            <h4>Recommended fix</h4><p>${esc(e.triage.fix)}</p>` : ""}</div>
      </div>
      ${rq ? `<h4>Request</h4><p><code>${esc(rq.method)} ${esc(rq.url)}</code></p>${kv(rq.headers)}
        ${rq.body ? `<pre>${esc(pretty(rq.body))}</pre>` : ""}` : ""}
      ${rs ? `<h4>Response <span class="muted">HTTP ${esc(rs.status)}${rs.elapsed_ms != null ? ` · ${rs.elapsed_ms} ms` : ""}</span></h4>${kv(rs.headers)}
        ${rs.body ? `<pre>${esc(pretty(rs.body))}</pre>` : `<p class="muted">Empty body</p>`}` : ""}
      ${Object.keys(det).length ? `<h4>Details</h4><pre>${esc(JSON.stringify(det, null, 2))}</pre>` : ""}
    </div>`;
  };

  const opLabel = (op) => {
    if (!op) return "";
    const [m, ...rest] = op.split(" ");
    if (!METHOD_ORDER.includes(m.toLowerCase())) return esc(op);
    return `${methodBadge(m.toLowerCase())} <code>${esc(rest.join(" "))}</code>`;
  };
  const feedHtml = (feed) => feed.slice().reverse().map((f) => `
    <li class="lv-${esc(f.level || "info")}"><span class="t">${esc(new Date(f.t * 1000).toLocaleTimeString())}</span>
      <span class="s">${esc(f.stage)}</span><span class="o">${opLabel(f.op)}</span><span class="m">${esc(f.msg)}</span></li>`).join("");

  const drawActivity = (live) => {
    const box = $("[data-out=activity]", view);
    const feed = run.feed || [];
    if (!live) {  // finished: keep the log, collapsed
      box.innerHTML = feed.length ? `<details class="box activity-log"><summary>Activity log <span class="count">${feed.length}</span></summary>
        <ol class="feed">${feedHtml(feed)}</ol></details>` : "";
      return;
    }
    const a = run.activity;
    const pct = a && a.total ? Math.min(100, Math.round((a.done || 0) / a.total * 100)) : null;
    const counter = a && a.total ? (a.stage === "zap" ? `${a.done ?? 0}%` : `${a.done ?? 0} / ${a.total} APIs done`) : "";
    const since = a ? Math.max(0, Math.round(Date.now() / 1000 - a.t)) : 0;
    const scroll = $(".feed", box)?.scrollTop || 0;
    requestAnimationFrame(() => { const f = $(".feed", box); if (f) f.scrollTop = scroll; });
    box.innerHTML = `<section class="activity panel">
      <div class="now">
        <div class="now-head"><span class="live">${run.status === "stopping" ? "Stopping" : "Now"}</span>
          ${a ? `<b>${esc(a.stage)}</b>${a.op ? ` · ${opLabel(a.op)}` : ""}` : `<span class="muted">Loading the spec…</span>`}</div>
        ${a ? `<div class="now-msg">${esc(a.msg)}${since > 20 ? ` <span class="muted">(no update for ${since}s; the tool is still working)</span>` : ""}</div>` : ""}
        ${pct != null ? `<div class="bar"><div style="width:${pct}%"></div></div><div class="meta">${esc(counter)}</div>` : ""}
      </div>
      ${feed.length ? `<h2>Activity</h2><ol class="feed">${feedHtml(feed.slice(-40))}</ol>` : ""}
    </section>`;
  };

  const all = () => run.report.stages.flatMap((s) => s.findings.map((f) => ({ ...f, stage: s.name })));

  const drawResults = () => {
    const box = $("[data-out=results]", view);
    const list = all();
    const counts = Object.fromEntries(SEVS.map((s) => [s, list.filter((f) => f.severity === s).length]));
    const ops = [...new Set(list.map((f) => f.operation).filter(Boolean))].sort();
    box.innerHTML = `
      ${run.status === "cancelled" ? `<div class="warn" style="margin:0 0 12px">Stopped early. Results below are only from the tests that finished.</div>` : ""}
      ${run.access?.length ? `<details class="box access-box" open><summary>APIs not tested due to access issues <span class="count">${run.access.length}</span></summary>
        <table class="access-tbl">${run.access.map((a) => `<tr><td class="op">${opLabel(a.operation)}</td>
          <td class="a-${esc(a.status)}"><b>${a.status === "blocked" ? "Not tested" : "Partly not tested"}</b></td>
          <td>${esc(a.reason.replace(/^[^:]+: (.)/, (_, c) => c.toUpperCase()))}</td></tr>`).join("")}</table></details>` : ""}
      ${run.lenient_spec ? `<p class="hint">Lenient mode: mismatches with the Swagger are listed with severity <b>info</b> and tagged
        <i>API vs Swagger</i>, so they don't fail the run.</p>` : ""}
      <div class="summary">${SEVS.map((s) => `<button class="pill ${s} ${counts[s] ? "" : "zero"} ${filter.sev === s ? "active" : ""}" data-sev="${s}"><b>${counts[s]}</b>${s}</button>`).join("")}</div>
      <div class="filters">
        <div class="tabs">${["all", ...run.report.stages.map((s) => s.name)].map((s) => {
          const n = s === "all" ? list.length : list.filter((f) => f.stage === s).length;
          return `<button class="tab ${filter.stage === s ? "active" : ""}" data-stage="${s}">${s} <span class="count">${n}</span></button>`;
        }).join("")}</div>
        <div class="right">
          <select data-out="op"><option value="">All APIs</option><option value="-" ${filter.op === "-" ? "selected" : ""}>Not tied to one API</option>
            ${ops.map((o) => `<option ${filter.op === o ? "selected" : ""}>${esc(o)}</option>`).join("")}</select>
          <input type="search" placeholder="Filter findings…" data-out="q" value="${esc(filter.q)}">
        </div>
      </div>
      <div data-out="list"></div>
      <div class="files">Raw output: ${run.files.map((f) => `<a href="/api/runs/${encodeURIComponent(run.id)}/files/${encodeURIComponent(f)}" target="_blank" rel="noopener">${esc(f)}</a>`).join(" ")}</div>`;
    const drawList = () => {
      const q = filter.q.toLowerCase();
      const shown = list
        .filter((f) => !filter.sev || f.severity === filter.sev)
        .filter((f) => filter.stage === "all" || f.stage === filter.stage)
        .filter((f) => !filter.op || (filter.op === "-" ? !f.operation : f.operation === filter.op))
        .filter((f) => !q || `${f.title} ${f.endpoint} ${f.detail}`.toLowerCase().includes(q))
        .sort((a, b) => SEVS.indexOf(a.severity) - SEVS.indexOf(b.severity));
      $("[data-out=list]", box).innerHTML = shown.length ? findingsHtml(shown)
        : `<div class="none">${list.length ? "No findings match the filter." : "No findings. 🎉"}</div>`;
    };
    drawList();
    $$("[data-sev]", box).forEach((b) => b.addEventListener("click", () => { filter.sev = filter.sev === b.dataset.sev ? null : b.dataset.sev; drawResults(); }));
    $$("[data-stage]", box).forEach((b) => b.addEventListener("click", () => { filter.stage = b.dataset.stage; drawResults(); }));
    $("[data-out=op]", box).addEventListener("change", (e) => { filter.op = e.target.value; drawList(); });
    $("[data-out=q]", box).addEventListener("input", (e) => { filter.q = e.target.value; drawList(); });
  };

  async function poll() {
    try { run = await api(`/api/runs/${runId}`); }
    catch (e) { view.innerHTML = `<p class="error">${esc(e.message)}</p>`; return; }
    if (tok !== pageToken) return;
    const live = ["running", "stopping"].includes(run.status);
    // don't wipe an expanded finding or filter input on every poll once results exist
    if (live || !view.dataset.final || view.dataset.final !== runId) draw();
    if (live) { clearTimeout(timer); timer = setTimeout(poll, 1500); }
    else {
      if (view.dataset.wasLive === runId) {
        drawExports();  // the HTML report exists now
        if (resultView === "log") drawLog();  // pick up the last entries
      }
      view.dataset.final = runId; reportCache.delete(runId);
    }
    if (live) view.dataset.wasLive = runId;
  }
  view.dataset.final = "";
  view.innerHTML = `<p class="muted">Loading…</p>`;
  poll();
}

/* ================= init ================= */

(async function init() {
  try { env = await api("/api/env"); } catch { /* keep defaults */ }
  window.addEventListener("hashchange", route);
  route();
})();
