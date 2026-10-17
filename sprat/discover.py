"""Find the OpenAPI/Swagger document(s) of a running application.

Accepts any of:
  * the spec itself                     https://host/swagger/v1/swagger.json
  * a Swagger UI page                   https://host/swagger, https://host/api-docs
  * the application root / a base path  https://host, https://host/api

For a root URL the well-known locations of common frameworks are probed. For a Swagger UI
page the spec URL(s) are read from its config, or the spec embedded in swagger-ui-express's
init script is extracted.
"""
from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse

import httpx
import yaml

from .tls import explain, ssl_context

SPEC_PATHS = [
    "/swagger/v1/swagger.json",      # ASP.NET Core Swashbuckle / NSwag
    "/swagger/v2/swagger.json",
    "/openapi/v1.json",              # ASP.NET Core 9+ Microsoft.AspNetCore.OpenApi
    "/swagger.json",
    "/openapi.json",                 # FastAPI, many Node setups
    "/openapi.yaml",
    "/api-docs.json",
    "/api-docs/swagger.json",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/v1/swagger.json",
    "/docs/swagger.json",
    "/swagger/docs/v1",              # .NET Framework Swashbuckle 5
    "/v3/api-docs",                  # Spring springdoc
    "/v2/api-docs",                  # Spring springfox
]
UI_PATHS = ["/swagger", "/swagger/index.html", "/api-docs", "/api-docs/", "/docs", "/api/docs",
            "/swagger-ui/index.html", "/swagger-ui.html"]
UI_SCRIPTS = ["swagger-initializer.js", "swagger-ui-init.js", "index.js"]


def same_site(a, b) -> bool:
    """May a request to `b` carry credentials meant for `a`? Same host and port, or an http -> https
    upgrade of the same host."""
    ua, ub = httpx.URL(str(a)), httpx.URL(str(b))
    if ua.host.lower() != ub.host.lower():
        return False
    if ua.scheme == ub.scheme:
        return ua.port == ub.port
    return ua.scheme == "http" and ub.scheme == "https" and ua.port in (None, 80) and ub.port in (None, 443)


def client_for(url: str, **kw) -> httpx.Client:
    """httpx client; for localhost it binds IPv4 so Windows doesn't spend ~2s per connection
    trying ::1 first (most dev servers listen on 127.0.0.1 only). HTTPS trusts the OS
    certificate store as well as certifi (see tls.py). The client's own headers (the user's
    credentials) are only sent to `url`'s host: httpx strips just Authorization on a redirect
    elsewhere, not X-Api-Key and the like."""
    kw.setdefault("verify", ssl_context())
    if urlparse(url).hostname == "localhost":
        kw["transport"] = httpx.HTTPTransport(local_address="0.0.0.0", verify=kw["verify"])
    names = {k.lower() for k in kw.get("headers") or {}}
    if names:
        def strip_elsewhere(request: httpx.Request) -> None:
            if not same_site(url, request.url):
                for k in names:
                    request.headers.pop(k, None)
        hooks = dict(kw.get("event_hooks") or {})
        hooks["request"] = [*hooks.get("request", []), strip_elsewhere]
        kw["event_hooks"] = hooks
    return httpx.Client(**kw)


def parse_spec(text: str) -> dict | None:
    try:
        doc = json.loads(text)
    except ValueError:
        try:
            doc = yaml.safe_load(text)
        except (yaml.YAMLError, ValueError):  # ValueError: an impossible date such as 2024-02-30
            return None
    if isinstance(doc, dict) and ("openapi" in doc or "swagger" in doc) and isinstance(doc.get("paths", {}), dict):
        return doc
    return None


def _extract_object(text: str, start: int) -> str | None:
    """Return the balanced {...} JSON object starting at text[start] (string-aware)."""
    depth, in_str, esc = 0, False, False
    for i in range(start, len(text)):
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def from_ui_text(page_url: str, text: str) -> tuple[dict | None, list[str]]:
    """Look inside Swagger UI HTML/JS for an embedded spec or for spec URLs."""
    m = re.search(r'"swaggerDoc"\s*:\s*\{', text)  # swagger-ui-express inlines the document
    if m:
        obj = _extract_object(text, m.end() - 1)
        if obj:
            doc = parse_spec(obj)
            if doc:
                return doc, []
    urls = []
    for m in re.finditer(r'(?<![\w$])url\s*:\s*["\']([^"\']+\.(?:json|ya?ml)[^"\']*|[^"\']*api-docs[^"\']*|[^"\']*swagger[^"\']*)["\']', text):
        urls.append(urljoin(page_url, m.group(1)))
    for m in re.finditer(r'"url"\s*:\s*"([^"]+)"', text):  # Swashbuckle: "urls":[{"url":"/swagger/v1/swagger.json",...}]
        u = m.group(1)
        if not u.startswith(("http://", "https://", "/", "./")) and not re.search(r"\.(json|ya?ml)\b", u):
            continue
        urls.append(urljoin(page_url, u))
    seen, out = set(), []
    for u in urls:
        if u not in seen and not u.endswith((".js", ".css", ".png")):
            seen.add(u)
            out.append(u)
    return None, out


def resolve_page(client: httpx.Client, page_url: str, text: str) -> tuple[dict | None, list[str]]:
    """Given a Swagger UI page, return (embedded spec, spec URLs), also checking its init scripts."""
    doc, urls = from_ui_text(page_url, text)
    if doc or urls:
        return doc, urls
    base = page_url if page_url.endswith("/") else page_url + "/"
    scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', text)
    candidates = [urljoin(page_url, s) for s in scripts if any(s.endswith(n) for n in UI_SCRIPTS)]
    candidates += [urljoin(base, n) for n in UI_SCRIPTS]
    for js_url in dict.fromkeys(candidates):
        try:
            r = client.get(js_url)
        except httpx.HTTPError:
            continue
        if r.status_code == 200:
            doc, urls = from_ui_text(page_url, r.text)
            if doc or urls:
                return doc, urls
    return None, []


def _summary(url: str, doc: dict, embedded: bool) -> dict:
    ops = sum(1 for item in (doc.get("paths") or {}).values() if isinstance(item, dict)
              for m in item if m in ("get", "put", "post", "delete", "patch", "head", "options"))
    info = doc.get("info", {})
    return {"url": url, "embedded": embedded, "title": info.get("title", ""), "api_version": info.get("version", ""),
            "spec_version": "swagger2" if "swagger" in doc else "openapi3", "operations": ops}


def discover(url: str, headers: dict[str, str] | None = None, timeout: float = 15.0) -> dict:
    """Return {"specs": [...], "tried": n, "errors": n, "error": first connection error or ""}.
    Each spec: url, title, api_version, spec_version, operations."""
    url = url.strip()
    if not re.match(r"^https?://", url):
        url = "http://" + url
    found: dict[str, dict] = {}
    tried: list[str] = []
    errors: list[str] = []
    with client_for(url, headers=headers or {}, timeout=timeout, follow_redirects=True) as c:

        def probe(u: str) -> None:
            tried.append(u)
            try:
                try:
                    r = c.get(u)
                except httpx.TimeoutException:  # slow servers: one more try
                    r = c.get(u)
            except httpx.HTTPError as e:
                errors.append(explain(e))
                return
            if r.status_code != 200:
                return
            doc = parse_spec(r.text)
            if doc:
                found.setdefault(str(r.url), _summary(str(r.url), doc, False))
                return
            if "html" in r.headers.get("content-type", "") or "<html" in r.text[:500].lower():
                emb, urls = resolve_page(c, str(r.url), r.text)
                if emb:
                    found.setdefault(str(r.url), _summary(str(r.url), emb, True))
                for su in urls:
                    try:
                        rr = c.get(su)
                    except httpx.HTTPError:
                        continue
                    d = parse_spec(rr.text) if rr.status_code == 200 else None
                    if d:
                        found.setdefault(str(rr.url), _summary(str(rr.url), d, False))

        probe(url)
        if not found:
            u = urlparse(url)
            root = f"{u.scheme}://{u.netloc}"
            prefix = u.path.rstrip("/")
            bases = [root + prefix, root] if prefix else [root]
            cands = [c for c in dict.fromkeys(b + p for b in bases for p in SPEC_PATHS + UI_PATHS)
                     if c != url]  # already probed above
            with ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(probe, cands))
    return {"specs": sorted(found.values(), key=lambda s: -s["operations"]), "tried": len(tried),
            "errors": len(errors), "error": errors[0] if errors else ""}


def not_found_message(res: dict) -> str:
    """Why discovery found nothing, in plain language."""
    if res.get("errors") and res["errors"] >= res["tried"]:
        return f"Couldn't connect to the server ({res['tried']} locations tried). {res['error']}"
    msg = f"No Swagger/OpenAPI document found ({res['tried']} locations tried)."
    if res.get("errors"):
        msg += f" {res['errors']} of them failed to connect: {res['error']}"
    return msg
