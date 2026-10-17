"""Finding a running application's OpenAPI document (sprat.discover)."""
import json
import ssl
import threading

import httpx
import pytest
import yaml

import sprat.discover as discover
from sprat.discover import (SPEC_PATHS, UI_PATHS, UI_SCRIPTS, _extract_object, _summary, from_ui_text,
                              not_found_message, parse_spec, resolve_page)

CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
OK = {"responses": {"200": {"description": "ok"}}}


def oas(n=1, title="T", version="1.0", **kw):
    return {"openapi": "3.0.1", "info": {"title": title, "version": version},
            "paths": {f"/p{i}": {"get": OK} for i in range(n)}, **kw}


class Web:
    """Fake server: routes[url] = Response | callable(request) | Exception. Everything else is 404."""

    def __init__(self):
        self.routes, self.seen, self.headers = {}, [], []
        self.lock = threading.Lock()

    def __setitem__(self, url, r):
        self.routes[url] = r

    def __call__(self, request):
        url = str(request.url)
        with self.lock:
            self.seen.append(url)
            self.headers.append(dict(request.headers))
        r = self.routes.get(url)
        if r is None:
            return httpx.Response(404, text="Not Found")
        if isinstance(r, Exception):
            raise r
        return r(request) if callable(r) else r


@pytest.fixture
def web(monkeypatch):
    w = Web()
    real = httpx.Client

    def fake_client(*a, **kw):
        kw["transport"] = httpx.MockTransport(w)
        return real(*a, **kw)
    monkeypatch.setattr(httpx, "Client", fake_client)
    monkeypatch.setattr(discover, "ssl_context", lambda: CTX)
    return w


def _cands(url):
    """The probe list discover() should use for a URL without a spec."""
    from urllib.parse import urlparse
    u = urlparse(url)
    root, prefix = f"{u.scheme}://{u.netloc}", u.path.rstrip("/")
    bases = [root + prefix, root] if prefix else [root]
    return list(dict.fromkeys(b + p for b in bases for p in SPEC_PATHS + UI_PATHS))


# ---------- direct hits ----------

def test_spec_url_itself(web):
    web["http://h.test/swagger/v1/swagger.json"] = httpx.Response(200, json=oas(3, "Shop", "2.1"))
    res = discover.discover("http://h.test/swagger/v1/swagger.json")
    assert res == {"specs": [{"url": "http://h.test/swagger/v1/swagger.json", "embedded": False, "title": "Shop",
                              "api_version": "2.1", "spec_version": "openapi3", "operations": 3}],
                   "tried": 1, "errors": 0, "error": ""}
    assert web.seen == ["http://h.test/swagger/v1/swagger.json"]


def test_yaml_spec_url(web):
    doc = {"swagger": "2.0", "info": {"title": "Y"}, "paths": {"/a": {"get": OK, "post": OK}}}
    web["http://h.test/openapi.yaml"] = httpx.Response(200, text=yaml.safe_dump(doc))
    [s] = discover.discover("http://h.test/openapi.yaml")["specs"]
    assert s["spec_version"] == "swagger2" and s["operations"] == 2 and s["api_version"] == ""


@pytest.mark.parametrize("given", ["h.test/openapi.json", "  http://h.test/openapi.json\n", "h.test/openapi.json "])
def test_scheme_added_and_whitespace_stripped(web, given):
    web["http://h.test/openapi.json"] = httpx.Response(200, json=oas())
    assert [s["url"] for s in discover.discover(given)["specs"]] == ["http://h.test/openapi.json"]


def test_https_kept(web):
    web["https://h.test/openapi.json"] = httpx.Response(200, json=oas())
    assert discover.discover("https://h.test/openapi.json")["specs"][0]["url"] == "https://h.test/openapi.json"


def test_headers_and_timeout_are_used(web, monkeypatch):
    web["http://h.test/openapi.json"] = httpx.Response(200, json=oas())
    real = httpx.Client
    kws = []

    def recording(*a, **kw):
        kws.append(kw)
        return real(*a, **kw)
    monkeypatch.setattr(httpx, "Client", recording)
    discover.discover("http://h.test/openapi.json", headers={"Authorization": "Bearer t"}, timeout=4)
    assert web.headers[0]["authorization"] == "Bearer t"
    assert kws[0]["timeout"] == 4 and kws[0]["follow_redirects"] is True and kws[0]["verify"] is CTX


# ---------- probing well-known locations ----------

def test_root_probes_every_well_known_location(web):
    res = discover.discover("http://h.test")
    expected = ["http://h.test"] + _cands("http://h.test")
    assert res["tried"] == len(expected) == 1 + len(SPEC_PATHS) + len(UI_PATHS)
    assert sorted(web.seen) == sorted(expected) and res["specs"] == [] and res["errors"] == 0


def test_well_known_list_contents():
    for p in ("/openapi.json", "/swagger.json", "/v3/api-docs", "/v2/api-docs", "/swagger/v1/swagger.json",
              "/openapi.yaml", "/openapi/v1.json"):
        assert p in SPEC_PATHS
    for p in ("/swagger-ui/index.html", "/swagger-ui.html", "/docs", "/swagger"):
        assert p in UI_PATHS
    assert len(set(SPEC_PATHS + UI_PATHS)) == len(SPEC_PATHS + UI_PATHS)


@pytest.mark.parametrize("url", ["http://h.test/api", "http://h.test/api/", "http://h.test/api/v1///"])
def test_base_path_probes_under_prefix_and_root_without_duplicates(web, url):
    res = discover.discover(url)
    cands = _cands(url.strip())
    assert len(cands) == len(set(cands))
    assert res["tried"] == 1 + len(cands) and sorted(web.seen) == sorted([url] + cands)
    prefix = url.split("h.test")[1].rstrip("/")
    assert f"http://h.test{prefix}/v3/api-docs" in web.seen and "http://h.test/v3/api-docs" in web.seen


def test_api_prefix_overlaps_are_probed_once(web):
    discover.discover("http://h.test/api")
    assert web.seen.count("http://h.test/api/swagger.json") == 1
    assert web.seen.count("http://h.test/api/docs") == 1


@pytest.mark.parametrize("path", SPEC_PATHS)
def test_each_spec_location_is_found(web, path):
    web[f"http://h.test{path}"] = httpx.Response(200, json=oas())
    assert [s["url"] for s in discover.discover("http://h.test/")["specs"]] == [f"http://h.test{path}"]


def test_port_is_kept(web):
    web["http://h.test:8080/v3/api-docs"] = httpx.Response(200, json=oas())
    assert discover.discover("http://h.test:8080/app")["specs"][0]["url"] == "http://h.test:8080/v3/api-docs"


def test_multiple_specs_sorted_by_operation_count(web):
    web["http://h.test/swagger/v1/swagger.json"] = httpx.Response(200, json=oas(2, "v1"))
    web["http://h.test/swagger/v2/swagger.json"] = httpx.Response(200, json=oas(9, "v2"))
    web["http://h.test/openapi.json"] = httpx.Response(200, json=oas(5, "other"))
    res = discover.discover("http://h.test")
    assert [s["title"] for s in res["specs"]] == ["v2", "other", "v1"]
    assert [s["operations"] for s in res["specs"]] == [9, 5, 2]


def test_same_document_behind_redirects_is_listed_once(web):
    web["http://h.test/openapi.json"] = httpx.Response(200, json=oas(4))
    for p in ("/swagger.json", "/api-docs.json", "/v3/api-docs"):
        web[f"http://h.test{p}"] = httpx.Response(302, headers={"Location": "/openapi.json"})
    res = discover.discover("http://h.test")
    assert [s["url"] for s in res["specs"]] == ["http://h.test/openapi.json"]


def test_root_redirect_to_spec(web):
    web["http://h.test"] = httpx.Response(301, headers={"Location": "http://h.test/v3/api-docs"})
    web["http://h.test/"] = web.routes["http://h.test"]
    web["http://h.test/v3/api-docs"] = httpx.Response(200, json=oas())
    res = discover.discover("http://h.test")
    assert [s["url"] for s in res["specs"]] == ["http://h.test/v3/api-docs"] and res["tried"] == 1


def test_non_200_and_non_spec_responses_ignored(web):
    web["http://h.test/openapi.json"] = httpx.Response(200, json={"status": "ok"})
    web["http://h.test/swagger.json"] = httpx.Response(401, json=oas())
    web["http://h.test/v3/api-docs"] = httpx.Response(500, json=oas())
    web["http://h.test/openapi.yaml"] = httpx.Response(200, text="key: [unclosed")
    res = discover.discover("http://h.test")
    assert res["specs"] == [] and res["tried"] == 1 + len(_cands("http://h.test"))


# ---------- Swagger UI pages ----------

def test_ui_page_spec_url(web):
    web["http://h.test/swagger-ui/index.html"] = httpx.Response(
        200, html='<html><script>SwaggerUIBundle({url: "/v3/api-docs", dom_id: "#ui"})</script></html>')
    web["http://h.test/v3/api-docs"] = httpx.Response(200, json=oas(2))
    res = discover.discover("http://h.test/swagger-ui/index.html")
    assert [(s["url"], s["embedded"]) for s in res["specs"]] == [("http://h.test/v3/api-docs", False)]
    assert res["tried"] == 1  # found from the page: no probing


def test_ui_page_detected_without_html_content_type(web):
    web["http://h.test/docs"] = httpx.Response(200, text='<!doctype html><HTML><script>ui({url: "/s.json"})</script>',
                                               headers={"content-type": "text/plain"})
    web["http://h.test/s.json"] = httpx.Response(200, json=oas())
    assert discover.discover("http://h.test/docs")["specs"][0]["url"] == "http://h.test/s.json"


def test_non_html_page_is_not_parsed_for_links(web):
    web["http://h.test/docs"] = httpx.Response(200, text='config = {url: "/s.json"}',
                                               headers={"content-type": "application/javascript"})
    web["http://h.test/s.json"] = httpx.Response(200, json=oas())
    discover.discover("http://h.test/docs")
    assert "http://h.test/s.json" not in web.seen


def test_ui_page_with_several_definitions(web):
    page = ('<html><script>var c = {"urls":[{"url":"/swagger/v1/swagger.json","name":"V1"},'
            '{"url":"/swagger/v2/swagger.json","name":"V2"},{"url":"/swagger/v3/missing.json","name":"V3"},'
            '{"url":"/swagger/v4/boom.json","name":"V4"}]};</script></html>')
    web["http://h.test/swagger/index.html"] = httpx.Response(200, html=page)
    web["http://h.test/swagger/v1/swagger.json"] = httpx.Response(200, json=oas(1, "one"))
    web["http://h.test/swagger/v2/swagger.json"] = httpx.Response(200, json=oas(2, "two"))
    web["http://h.test/swagger/v4/boom.json"] = httpx.ConnectError("reset")
    res = discover.discover("http://h.test/swagger/index.html")
    assert [s["title"] for s in res["specs"]] == ["two", "one"] and res["errors"] == 0


def test_ui_page_found_while_probing_and_spec_found_directly_are_merged(web):
    web["http://h.test/docs"] = httpx.Response(200, html='<script>SwaggerUIBundle({url: "/openapi.json"})</script>')
    web["http://h.test/openapi.json"] = httpx.Response(200, json=oas(3))
    res = discover.discover("http://h.test")
    assert [s["url"] for s in res["specs"]] == ["http://h.test/openapi.json"]


def test_embedded_swagger_ui_express_spec(web):
    doc = oas(4, "Embedded")
    js = 'window.onload = function() {\n  var options = {\n  "swaggerDoc": ' + json.dumps(doc, indent=2) + \
         ',\n  "customOptions": {}\n};'
    web["http://h.test/api-docs/"] = httpx.Response(
        200, html='<html><head><script src="./swagger-ui-init.js"></script></head></html>')
    web["http://h.test/api-docs/swagger-ui-init.js"] = httpx.Response(200, text=js)
    res = discover.discover("http://h.test/api-docs/")
    assert res["specs"] == [{"url": "http://h.test/api-docs/", "embedded": True, "title": "Embedded",
                             "api_version": "1.0", "spec_version": "openapi3", "operations": 4}]


def test_init_script_guessed_when_page_has_no_script_tags(web):
    web["http://h.test/swagger"] = httpx.Response(200, html="<html><div id='swagger-ui'></div></html>")
    web["http://h.test/swagger/swagger-initializer.js"] = httpx.Response(
        200, text='window.ui = SwaggerUIBundle({ url: "https://h.test/v1/openapi.yaml" })')
    web["https://h.test/v1/openapi.yaml"] = httpx.Response(200, text=yaml.safe_dump(oas(2)))
    res = discover.discover("http://h.test/swagger")
    assert [s["url"] for s in res["specs"]] == ["https://h.test/v1/openapi.yaml"]


# ---------- errors ----------

def test_all_connections_fail(web):
    for u in ["http://down.test"] + _cands("http://down.test"):
        web[u] = httpx.ConnectError("[Errno 111] Connection refused")
    res = discover.discover("http://down.test")
    assert res["specs"] == [] and res["errors"] == res["tried"] == 1 + len(_cands("http://down.test"))
    assert res["error"] == "ConnectError: [Errno 111] Connection refused"
    assert not_found_message(res) == (f"Couldn't connect to the server ({res['tried']} locations tried). "
                                      "ConnectError: [Errno 111] Connection refused")


def test_some_connections_fail(web):
    web["http://h.test/swagger.json"] = httpx.RemoteProtocolError("Server disconnected")
    web["http://h.test/openapi.json"] = httpx.RemoteProtocolError("Server disconnected")
    res = discover.discover("http://h.test")
    assert res["errors"] == 2 and res["error"] == "RemoteProtocolError: Server disconnected"
    assert not_found_message(res) == (f"No Swagger/OpenAPI document found ({res['tried']} locations tried). "
                                      "2 of them failed to connect: RemoteProtocolError: Server disconnected")


def test_tls_errors_are_explained(web):
    web["https://h.test/openapi.json"] = httpx.ConnectError(
        "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate "
        "(_ssl.c:1028)")
    res = discover.discover("https://h.test/openapi.json")
    assert res["error"].startswith("The server's HTTPS certificate was rejected") and "SPRAT_CA_BUNDLE" in res["error"]


def test_timeout_is_retried_once(web):
    calls = []

    def flaky(r):
        calls.append(1)
        if len(calls) == 1:
            raise httpx.ReadTimeout("timed out")
        return httpx.Response(200, json=oas())
    web["http://slow.test/openapi.json"] = flaky
    res = discover.discover("http://slow.test/openapi.json")
    assert len(calls) == 2 and res["specs"] and res["errors"] == 0 and res["tried"] == 1


def test_timeout_twice_counts_as_error(web):
    web["http://slow.test/app/spec.json"] = httpx.ConnectTimeout("timed out")
    res = discover.discover("http://slow.test/app/spec.json")
    assert web.seen.count("http://slow.test/app/spec.json") == 2
    assert res["error"] == "ConnectTimeout: timed out" and res["errors"] == 1


def test_non_timeout_errors_are_not_retried(web):
    web["http://h.test/app/spec.json"] = httpx.ConnectError("refused")
    res = discover.discover("http://h.test/app/spec.json")
    assert web.seen.count("http://h.test/app/spec.json") == 1 and res["errors"] == 1


def test_given_url_is_not_probed_twice(web):
    web["http://h.test/openapi.json"] = httpx.ConnectError("refused")
    res = discover.discover("http://h.test/openapi.json")
    assert web.seen.count("http://h.test/openapi.json") == 1 and res["errors"] == 1


def test_localhost_discovery(web):
    web["http://localhost:8000/openapi.json"] = httpx.Response(200, json=oas())
    assert discover.discover("localhost:8000")["specs"][0]["url"] == "http://localhost:8000/openapi.json"


@pytest.mark.parametrize("res,msg", [
    ({"tried": 24, "errors": 24, "error": "E"}, "Couldn't connect to the server (24 locations tried). E"),
    ({"tried": 24, "errors": 0, "error": ""}, "No Swagger/OpenAPI document found (24 locations tried)."),
    ({"tried": 24, "errors": 3, "error": "E"},
     "No Swagger/OpenAPI document found (24 locations tried). 3 of them failed to connect: E"),
    ({"tried": 0, "errors": 0, "error": ""}, "No Swagger/OpenAPI document found (0 locations tried)."),
    ({"tried": 1}, "No Swagger/OpenAPI document found (1 locations tried)."),
])
def test_not_found_message_exact(res, msg):
    assert not_found_message({"specs": [], **res}) == msg


# ---------- parse_spec ----------

@pytest.mark.parametrize("text,ok", [
    (json.dumps(oas()), True),
    (yaml.safe_dump(oas()), True),
    (json.dumps({"swagger": "2.0"}), True),            # paths are optional here
    (json.dumps({"openapi": "3.0.0", "paths": []}), False),
    (json.dumps({"info": {}, "paths": {}}), False),
    ("[]", False), ("null", False), ("42", False), ("", False), ("plain words", False),
    ("a: [b", False), ("<html><body>hi</body></html>", False),
    ("﻿" + json.dumps(oas()), True),
])
def test_parse_spec(text, ok):
    assert (parse_spec(text) is not None) is ok


# ---------- from_ui_text ----------

@pytest.mark.parametrize("text,urls", [
    ('SwaggerUIBundle({url: "https://petstore.test/v2/swagger.json"})', ["https://petstore.test/v2/swagger.json"]),
    ("SwaggerUIBundle({ url : './openapi.yaml' })", ["http://h.test/docs/openapi.yaml"]),
    ('ui({url: "/v3/api-docs"})', ["http://h.test/v3/api-docs"]),
    ('ui({url: "/v3/api-docs/swagger-config"})', ["http://h.test/v3/api-docs/swagger-config"]),
    ('ui({url: "/spec.yml?v=2"})', ["http://h.test/spec.yml?v=2"]),
    ('ui({urls: [{url: "/a.json", name: "A"}, {url: "/b.json", name: "B"}]})',
     ["http://h.test/a.json", "http://h.test/b.json"]),
    ('{"urls":[{"url":"/swagger/v1/swagger.json","name":"v1"}]}', ["http://h.test/swagger/v1/swagger.json"]),
    ('{"url":"v1/swagger.json"}', ["http://h.test/docs/v1/swagger.json"]),
    ('{"url":"https://other.test/x"}', ["https://other.test/x"]),
    ('{"url":"relative-no-extension"}', []),
    ('ui({configUrl: "/swagger-config.json"})', []),       # configUrl isn't a spec
    ('$url: "/x.json"', []),
    ('ui({url: "/swagger-ui.css"}); ui({url: "/swagger-ui-bundle.js"}); x({url: "/logo.png"})', []),
    ('ui({url: "/a.json"}); ui({url: "/a.json"})', ["http://h.test/a.json"]),
    ("no config here", []),
])
def test_from_ui_text_urls(text, urls):
    assert from_ui_text("http://h.test/docs/", text) == (None, urls)


def test_from_ui_text_embedded_doc_with_tricky_strings():
    doc = oas(1, title='braces } { and "quotes" and \\ backslash')
    text = f'var options = {{"swaggerDoc": {json.dumps(doc)}, "customOptions": {{}}}}; url: "/ignored.json"'
    assert from_ui_text("http://h.test/", text) == (doc, [])


@pytest.mark.parametrize("text", ['"swaggerDoc": {"openapi": "3.0.0", "paths": {', '"swaggerDoc": {"not": "a spec"},'
                                  ' url: "/fallback.json"'])
def test_from_ui_text_broken_embedded_doc_falls_back_to_urls(text):
    doc, urls = from_ui_text("http://h.test/", text)
    assert doc is None and urls == (["http://h.test/fallback.json"] if "fallback" in text else [])


# ---------- resolve_page ----------

def _client(web):
    return httpx.Client(transport=httpx.MockTransport(web))


def test_resolve_page_prefers_page_config(web):
    with _client(web) as c:
        assert resolve_page(c, "http://h.test/docs", 'ui({url: "/s.json"})') == (None, ["http://h.test/s.json"])
    assert web.seen == []


def test_resolve_page_reads_referenced_and_guessed_scripts(web):
    page = ('<script src="/static/swagger-ui-bundle.js"></script><script src="/static/swagger-initializer.js">'
            '</script><script src=\'other.js\'></script>')
    web["http://h.test/static/swagger-initializer.js"] = httpx.Response(200, text='x({url: "/v2/api-docs"})')
    with _client(web) as c:
        assert resolve_page(c, "http://h.test/ui", page) == (None, ["http://h.test/v2/api-docs"])
    assert web.seen == ["http://h.test/static/swagger-initializer.js"]  # the bundle and other.js are skipped


def test_resolve_page_tries_all_candidates_then_gives_up(web):
    web["http://h.test/ui/swagger-initializer.js"] = httpx.ConnectError("reset")
    web["http://h.test/ui/swagger-ui-init.js"] = httpx.Response(200, text="nothing useful")
    with _client(web) as c:
        assert resolve_page(c, "http://h.test/ui", "<html></html>") == (None, [])
    assert web.seen == [f"http://h.test/ui/{n}" for n in UI_SCRIPTS]


def test_resolve_page_dedupes_script_candidates(web):
    page = '<script src="./index.js"></script>'
    with _client(web) as c:
        resolve_page(c, "http://h.test/ui/", page)
    assert web.seen.count("http://h.test/ui/index.js") == 1 and len(web.seen) == len(UI_SCRIPTS)


def test_resolve_page_embedded_in_index_js(web):
    doc = oas(2)
    web["http://h.test/ui/index.js"] = httpx.Response(200, text='init({"swaggerDoc": ' + json.dumps(doc) + "})")
    with _client(web) as c:
        assert resolve_page(c, "http://h.test/ui/", "<html></html>") == (doc, [])


# ---------- helpers ----------

def test_extract_object():
    t = 'x = {"a": {"b": "}"}, "c": "\\"{"} tail'
    assert _extract_object(t, t.index("{")) == '{"a": {"b": "}"}, "c": "\\"{"}'
    assert _extract_object('{"a": 1', 0) is None
    assert _extract_object("{}", 0) == "{}"


def test_summary_counts_only_operations():
    doc = {"swagger": "2.0", "paths": {"/a": {"get": OK, "parameters": [], "x-ext": {}, "summary": "s", "trace": {}},
                                       "/b": {"put": OK, "patch": OK, "head": OK, "options": OK, "delete": OK,
                                              "post": OK}, "/c": None, "/d": "junk"}}
    assert _summary("u", doc, True) == {"url": "u", "embedded": True, "title": "", "api_version": "",
                                        "spec_version": "swagger2", "operations": 7}
    assert _summary("u", {"openapi": "3.1.0", "paths": None}, False)["operations"] == 0
