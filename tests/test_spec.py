"""Loading Swagger 2.0 / OpenAPI 3.x documents (sprat.spec) from files and URLs, and what is extracted."""
import json
import ssl

import httpx
import pytest
import yaml

import sprat.discover as discover
from sprat.spec import METHODS, Operation, Spec, filter_operations, load_spec, resolve

CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
OK = {"responses": {"200": {"description": "ok"}}}


def oas(paths=None, **kw):
    return {"openapi": "3.0.3", "info": {"title": "T", "version": "1"}, "paths": paths or {}, **kw}


def sw2(paths=None, **kw):
    return {"swagger": "2.0", "info": {"title": "T", "version": "1"}, "paths": paths or {}, **kw}


@pytest.fixture
def web(monkeypatch):
    """routes: url (or path) -> httpx.Response | callable(request). Unknown URLs are 404."""
    routes, seen = {}, []

    def handler(request):
        seen.append(str(request.url))
        r = routes.get(str(request.url), routes.get(request.url.path))
        if r is None:
            return httpx.Response(404, text="not found")
        return r(request) if callable(r) else r
    real = httpx.Client

    def fake_client(*a, **kw):
        kw["transport"] = httpx.MockTransport(handler)
        return real(*a, **kw)
    monkeypatch.setattr(httpx, "Client", fake_client)
    monkeypatch.setattr(discover, "ssl_context", lambda: CTX)
    routes["_seen"] = seen
    return routes


def _file(tmp_path, doc, name="openapi.json", fmt="json"):
    p = tmp_path / name
    p.write_text(json.dumps(doc) if fmt == "json" else yaml.safe_dump(doc, allow_unicode=True), encoding="utf-8")
    return str(p)


def _ops(spec):
    return {o.label: o for o in spec.operations}


# ---------- files ----------

def test_json_file(tmp_path):
    doc = oas({"/a": {"get": OK}}, servers=[{"url": "https://api.test/v1/"}])
    path = _file(tmp_path, doc)
    s = load_spec(path)
    assert isinstance(s, Spec) and s.version == "openapi3" and s.source == path
    assert s.base_url == "https://api.test/v1" and s.raw == doc
    assert s.text == s.full_text == json.dumps(doc) and not s.filtered and not s.from_page
    assert [o.label for o in s.operations] == ["GET /a"]


@pytest.mark.parametrize("name", ["openapi.yaml", "openapi.yml", "spec.txt"])
def test_yaml_file_any_extension(tmp_path, name):
    s = load_spec(_file(tmp_path, sw2({"/a": {"post": OK}}, host="h.test"), name, fmt="yaml"))
    assert s.version == "swagger2" and s.base_url == "https://h.test" and _ops(s)["POST /a"]


def test_yaml_specific_syntax(tmp_path):
    p = tmp_path / "s.yaml"
    p.write_text("openapi: 3.1.0\ninfo: {title: T, version: '1'}\npaths:\n  /a:\n    get: &op\n"
                 "      responses: {'200': {description: ok}}\n  /b:\n    get: *op\n", encoding="utf-8")
    s = load_spec(str(p))
    assert set(_ops(s)) == {"GET /a", "GET /b"} and s.version == "openapi3"


def test_unicode_file(tmp_path):
    doc = oas({"/città/{id}": {"get": {"summary": "Ünïcödé 日本語 🚀", **OK}}}, info={"title": "Ünï", "version": "1"})
    for fmt in ("json", "yaml"):
        s = load_spec(_file(tmp_path, doc, f"u.{fmt}", fmt))
        assert _ops(s)["GET /città/{id}"].op["summary"] == "Ünïcödé 日本語 🚀"
        assert _ops(s)["GET /città/{id}"].path_params == {"id": "1"}


def test_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_spec(str(tmp_path / "nope.json"))


@pytest.mark.parametrize("text", ["", "null", "[1, 2]", "just text", "{\"info\": {}}", "openapi: [unclosed",
                                  json.dumps({"openapi": "3.0.0", "paths": []}),
                                  json.dumps({"swagger": "2.0", "paths": "nope"}), "openapi: 3.0.0\npaths:\n",
                                  "<html><body>Swagger UI</body></html>", "\t- bad\n:yaml"])
def test_not_a_spec_file(tmp_path, text):
    p = tmp_path / "x.json"
    p.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match="Not a Swagger 2.0 / OpenAPI 3.x document"):
        load_spec(str(p))


@pytest.mark.parametrize("doc", [{"openapi": "3.0.0"}, {"swagger": "2.0"}, {"openapi": "3.0.0", "paths": {}},
                                 {"openapi": "3.1.0", "webhooks": {"x": {}}}])
def test_spec_without_paths(tmp_path, doc):
    assert load_spec(_file(tmp_path, doc)).operations == []


# ---------- versions and base URLs ----------

@pytest.mark.parametrize("doc,source,base", [
    (oas(servers=[{"url": "https://api.test/v1/"}]), "file", "https://api.test/v1"),
    (oas(servers=[{"url": "http://api.test"}, {"url": "https://second.test"}]), "file", "http://api.test"),
    (oas(servers=[{"url": "/api"}]), "file", ""),
    (oas(servers=[{"url": "/api"}]), "http://h.test/docs/openapi.json", "http://h.test/api"),
    (oas(servers=[{"url": "v2"}]), "http://h.test/docs/openapi.json", "http://h.test/docs/v2"),
    (oas(servers=[{"url": "/"}]), "http://h.test/openapi.json", "http://h.test"),
    (oas(servers=[{}]), "https://h.test:8443/openapi.json", "https://h.test:8443"),
    (oas(servers=[]), "http://h.test:8080/x/openapi.json", "http://h.test:8080"),
    (oas(), "file", ""),
    (sw2(host="api.test", basePath="/v1/", schemes=["http", "https"]), "file", "http://api.test/v1"),
    (sw2(host="api.test:8080"), "file", "https://api.test:8080"),
    (sw2(host="api.test", schemes=[]), "file", "https://api.test"),
    (sw2(basePath="/v1"), "http://h.test/swagger.json", "http://h.test"),
    (sw2(), "file", ""),
])
def test_base_url(tmp_path, web, doc, source, base):
    if source == "file":
        source = _file(tmp_path, doc)
    else:
        web[source] = httpx.Response(200, json=doc)
    s = load_spec(source)
    assert s.base_url == base and s.version == ("openapi3" if "openapi" in doc else "swagger2")


def test_server_variables_use_defaults(tmp_path):
    doc = oas(servers=[{"url": "https://{env}.api.test/{ver}",
                        "variables": {"env": {"default": "prod"}, "ver": {"default": "v2"}}}])
    assert load_spec(_file(tmp_path, doc)).base_url == "https://prod.api.test/v2"


@pytest.mark.parametrize("version", ["3.0.0", "3.0.3", "3.1.0", "3.1.1"])
def test_openapi3_versions(tmp_path, version):
    assert load_spec(_file(tmp_path, {**oas(), "openapi": version})).version == "openapi3"


# ---------- operations ----------

def test_all_methods_and_non_operation_keys(tmp_path):
    item = {m: OK for m in METHODS}
    item.update({"summary": "s", "description": "d", "servers": [], "x-internal": {"get": 1}, "trace": OK,
                 "parameters": [], "$comment": "c"})
    s = load_spec(_file(tmp_path, oas({"/r": item, "/bad": {"get": "not an object", "post": None}})))
    assert sorted(o.method for o in s.operations) == sorted(METHODS)
    assert all(o.path == "/r" for o in s.operations)


def test_operation_order_follows_document(tmp_path):
    s = load_spec(_file(tmp_path, oas({"/b": {"post": OK, "get": OK}, "/a": {"delete": OK}})))
    assert [o.label for o in s.operations] == ["POST /b", "GET /b", "DELETE /a"]


def test_operation_fields(tmp_path):
    op = {"operationId": "getThing", "deprecated": True, "tags": ["t"], **OK}
    [o] = load_spec(_file(tmp_path, oas({"/things/{id}": {"get": op}}))).operations
    assert isinstance(o, Operation) and o.label == "GET /things/{id}" and o.method == "get"
    assert o.op == op and o.op["deprecated"] is True  # deprecated operations are still tested
    assert o.query_params == {} and not o.has_body and not o.secured and o.params == []


@pytest.mark.parametrize("schema,placeholder", [
    ({"type": "integer"}, "1"), ({"type": "number", "format": "double"}, "1"), ({"type": "boolean"}, "true"),
    ({"type": "string"}, "1"), ({"type": "string", "format": "uuid"}, "00000000-0000-0000-0000-000000000001"),
    ({"type": "string", "enum": ["red", "green"]}, "red"), ({"type": "integer", "enum": [7, 8]}, "7"),
    ({"type": "string", "enum": []}, "1"), ({}, "1"), ({"type": "array", "items": {"type": "string"}}, "1"),
])
def test_path_param_placeholders_openapi3(tmp_path, schema, placeholder):
    doc = oas({"/x/{p}": {"get": {"parameters": [{"name": "p", "in": "path", "required": True, "schema": schema}],
                                  **OK}}})
    [o] = load_spec(_file(tmp_path, doc)).operations
    assert o.path_params == {"p": placeholder}


@pytest.mark.parametrize("param,placeholder", [
    ({"type": "integer", "format": "int64"}, "1"), ({"type": "string", "format": "uuid"},
                                                     "00000000-0000-0000-0000-000000000001"),
    ({"type": "boolean"}, "true"), ({"type": "string", "enum": ["a"]}, "a"),
])
def test_path_param_placeholders_swagger2(tmp_path, param, placeholder):
    doc = sw2({"/x/{p}": {"get": {"parameters": [{"name": "p", "in": "path", "required": True, **param}], **OK}}})
    [o] = load_spec(_file(tmp_path, doc)).operations
    assert o.path_params == {"p": placeholder}


def test_undeclared_path_params_get_a_default(tmp_path):
    doc = oas({"/orgs/{orgId}/users/{user_id}/x{n}": {"get": OK}})
    [o] = load_spec(_file(tmp_path, doc)).operations
    assert o.path_params == {"orgId": "1", "user_id": "1", "n": "1"}


def test_shared_and_operation_params_merge(tmp_path):
    doc = oas({"/o/{id}": {
        "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}},
                       {"name": "tenant", "in": "query", "required": True, "schema": {"type": "string",
                                                                                      "enum": ["acme"]}}],
        "get": {"parameters": [{"name": "id", "in": "path", "required": True,
                                "schema": {"type": "string", "format": "uuid"}},  # operation level overrides
                               {"name": "page", "in": "query", "schema": {"type": "integer"}},
                               {"name": "limit", "in": "query", "required": True, "schema": {"type": "integer"}},
                               {"name": "X-Trace", "in": "header", "required": True, "schema": {"type": "string"}}],
                **OK}}})
    [o] = load_spec(_file(tmp_path, doc)).operations
    assert o.path_params == {"id": "00000000-0000-0000-0000-000000000001"}
    assert o.query_params == {"tenant": "acme", "limit": "1"}  # required only
    assert [p["name"] for p in o.params] == ["id", "tenant", "id", "page", "limit", "X-Trace"]


@pytest.mark.parametrize("op,shared,has_body", [
    ({"requestBody": {"content": {}}}, [], True),
    ({"parameters": [{"name": "b", "in": "body", "schema": {}}]}, [], True),
    ({}, [{"name": "b", "in": "body", "schema": {}}], True),
    ({"parameters": [{"name": "f", "in": "formData", "type": "string"}]}, [], False),
    ({}, [], False),
])
def test_has_body(tmp_path, op, shared, has_body):
    doc = sw2({"/x": {"parameters": shared, "post": {**op, **OK}}})
    assert load_spec(_file(tmp_path, doc)).operations[0].has_body is has_body


@pytest.mark.parametrize("global_sec,op_sec,secured", [
    (None, None, False),
    ([{"bearer": []}], None, True),
    ([{"bearer": []}], [], False),
    ([{"bearer": []}], [{}], False),
    (None, [{"bearer": []}], True),
    (None, [{"bearer": []}, {"apiKey": []}], True),
    (None, [{"bearer": []}, {}], False),
    ([], [{"oauth": ["read"]}], True),
    ([{}], None, False),
])
def test_security(tmp_path, global_sec, op_sec, secured):
    op = dict(OK) if op_sec is None else {"security": op_sec, **OK}
    doc = oas({"/x": {"get": op}})
    if global_sec is not None:
        doc["security"] = global_sec
    assert load_spec(_file(tmp_path, doc)).operations[0].secured is secured


# ---------- $ref ----------

def test_refs_for_params_and_path_items(tmp_path):
    doc = oas({"/a/{id}": {"$ref": "#/components/pathItems/A"},
               "/b/{id}": {"parameters": [{"$ref": "#/components/parameters/Alias"}], "get": OK}},
              components={"pathItems": {"A": {"get": {"parameters": [{"$ref": "#/components/parameters/Id"}], **OK},
                                              "post": {"requestBody": {"$ref": "#/components/requestBodies/B"},
                                                       **OK}}},
                          "parameters": {"Id": {"name": "id", "in": "path", "required": True,
                                                "schema": {"type": "string", "format": "uuid"}},
                                         "Alias": {"$ref": "#/components/parameters/Id"}},
                          "requestBodies": {"B": {"content": {}}}})
    ops = _ops(load_spec(_file(tmp_path, doc)))
    assert set(ops) == {"GET /a/{id}", "POST /a/{id}", "GET /b/{id}"}
    uuid = {"id": "00000000-0000-0000-0000-000000000001"}
    assert ops["GET /a/{id}"].path_params == uuid and ops["GET /b/{id}"].path_params == uuid  # ref -> ref
    assert ops["POST /a/{id}"].has_body


def test_swagger2_parameter_refs(tmp_path):
    doc = sw2({"/x/{id}": {"get": {"parameters": [{"$ref": "#/parameters/Id"}, {"$ref": "#/parameters/Q"}], **OK}}},
              parameters={"Id": {"name": "id", "in": "path", "required": True, "type": "boolean"},
                          "Q": {"name": "q", "in": "query", "required": True, "type": "integer"}})
    [o] = load_spec(_file(tmp_path, doc)).operations
    assert o.path_params == {"id": "true"} and o.query_params == {"q": "1"}


def test_json_pointer_escapes():
    raw = {"defs": {"a/b": {"x~y": {"v": 1}}}}
    assert resolve(raw, {"$ref": "#/defs/a~1b/x~0y"}) == {"v": 1}


@pytest.mark.parametrize("node", [{"$ref": "other.yaml#/components/parameters/Id"},
                                  {"$ref": "https://example.test/common.json#/Id"}, {"$ref": "#"}])
def test_external_or_root_refs_are_left_alone(node):
    assert resolve({"x": 1}, node) is node


def test_external_ref_left_unresolved_does_not_crash(tmp_path):
    doc = oas({"/x/{id}": {"get": {"parameters": [{"$ref": "common.yaml#/Id"}], **OK}}})
    [o] = load_spec(_file(tmp_path, doc)).operations
    assert o.path_params == {"id": "1"} and o.params == [{"$ref": "common.yaml#/Id"}]


def test_ref_cycles_and_dangling_refs_terminate():
    raw = {"a": {"$ref": "#/b"}, "b": {"$ref": "#/a"}}
    assert "$ref" in resolve(raw, {"$ref": "#/a"})
    assert resolve(raw, {"$ref": "#/missing/deep"}) == {}
    assert resolve(raw, "plain") == "plain" and resolve(raw, None) is None and resolve(raw, [1]) == [1]


def test_dangling_param_refs_are_ignored(tmp_path):
    doc = oas({"/x": {"get": {"parameters": [{"$ref": "#/components/parameters/Nope"}], **OK}}})
    [o] = load_spec(_file(tmp_path, doc)).operations
    assert o.params == [{}] and o.path_params == {} and o.query_params == {}


def test_cyclic_param_ref_does_not_hang(tmp_path):
    doc = oas({"/x": {"get": {"parameters": [{"$ref": "#/components/parameters/A"}], **OK}}},
              components={"parameters": {"A": {"$ref": "#/components/parameters/B"},
                                         "B": {"$ref": "#/components/parameters/A"}}})
    assert load_spec(_file(tmp_path, doc)).operations[0].path_params == {}


def test_ref_into_array():
    raw = {"paths": {"/a": {"get": {"parameters": [{"name": "id", "in": "path"}]}}}}
    assert resolve(raw, {"$ref": "#/paths/~1a/get/parameters/0"}) == {"name": "id", "in": "path"}


# ---------- URLs ----------

def test_from_url_json_and_yaml(web):
    web["http://api.test/openapi.json"] = httpx.Response(200, json=oas({"/a": {"get": OK}}))
    web["http://api.test/openapi.yaml"] = httpx.Response(200, text=yaml.safe_dump(sw2({"/b": {"get": OK}})),
                                                         headers={"content-type": "application/yaml"})
    a = load_spec("http://api.test/openapi.json")
    b = load_spec("http://api.test/openapi.yaml")
    assert a.source == "http://api.test/openapi.json" and a.base_url == "http://api.test" and not a.from_page
    assert [o.label for o in a.operations] == ["GET /a"] and [o.label for o in b.operations] == ["GET /b"]
    assert b.version == "swagger2"


def test_from_url_sends_headers_and_timeout(web, monkeypatch):
    got = {}

    def spec(r):
        got.update(r.headers)
        return httpx.Response(200, json=oas())
    web["/openapi.json"] = spec
    real = httpx.Client
    kws = []

    def recording(*a, **kw):
        kws.append(kw)
        return real(*a, **kw)
    monkeypatch.setattr(httpx, "Client", recording)
    load_spec("https://api.test/openapi.json", headers={"Authorization": "Bearer t"}, timeout=3.5)
    assert got["authorization"] == "Bearer t"
    assert kws[0]["timeout"] == 3.5 and kws[0]["follow_redirects"] is True and kws[0]["verify"] is CTX


@pytest.mark.parametrize("status", [401, 403, 404, 500])
def test_from_url_http_errors_raise(web, status):
    web["/openapi.json"] = httpx.Response(status, json={"message": "no"})
    with pytest.raises(httpx.HTTPStatusError):
        load_spec("http://api.test/openapi.json")


def test_from_url_connection_error(web):
    def boom(r):
        raise httpx.ConnectError("refused")
    web["/openapi.json"] = boom
    with pytest.raises(httpx.ConnectError):
        load_spec("http://api.test/openapi.json")


def test_redirect_followed(web):
    web["http://api.test/spec"] = httpx.Response(301, headers={"Location": "http://api.test/v3/api-docs"})
    web["http://api.test/v3/api-docs"] = httpx.Response(200, json=oas({"/a": {"get": OK}}))
    s = load_spec("http://api.test/spec")
    assert [o.label for o in s.operations] == ["GET /a"] and s.source == "http://api.test/spec"


def test_relative_server_resolved_against_final_url(web):
    web["http://api.test/openapi.json"] = httpx.Response(301, headers={"Location": "https://api.test/openapi.json"})
    web["https://api.test/openapi.json"] = httpx.Response(200, json=oas(servers=[{"url": "/api"}]))
    assert load_spec("http://api.test/openapi.json").base_url == "https://api.test/api"


def test_swagger_ui_page_with_spec_url(web):
    page = '<html><script>SwaggerUIBundle({url: "/v3/api-docs", dom_id: "#swagger-ui"})</script></html>'
    web["http://api.test/swagger-ui/index.html"] = httpx.Response(200, html=page)
    web["http://api.test/v3/api-docs"] = httpx.Response(200, json=oas({"/a": {"get": OK}}, servers=[{"url": "/x"}]))
    s = load_spec("http://api.test/swagger-ui/index.html")
    assert s.from_page and [o.label for o in s.operations] == ["GET /a"]
    assert s.base_url == "http://api.test/x" and s.source == "http://api.test/swagger-ui/index.html"
    assert json.loads(s.text)["openapi"] == "3.0.3"


def test_swagger_ui_page_tries_urls_in_order(web):
    page = ('<html><script>window.ui = SwaggerUIBundle({urls: [{"url": "/v1/missing.json", "name": "a"}, '
            '{"url": "/v1/broken.json", "name": "b"}, {"url": "/v1/good.json", "name": "c"}]})</script></html>')
    web["/docs"] = httpx.Response(200, html=page)
    web["/v1/broken.json"] = httpx.Response(200, text="not a spec")
    web["/v1/good.json"] = httpx.Response(200, json=sw2({"/g": {"get": OK}}))
    s = load_spec("http://api.test/docs")
    assert s.from_page and [o.label for o in s.operations] == ["GET /g"]
    assert web["_seen"][-3:] == ["http://api.test/v1/missing.json", "http://api.test/v1/broken.json",
                                 "http://api.test/v1/good.json"]


def test_swagger_ui_express_embedded_spec(web):
    doc = oas({"/e": {"get": OK}}, servers=[{"url": "https://real.test"}])
    js = 'window.onload = function() { var options = {"swaggerDoc": ' + json.dumps(doc) + ', "customOptions": {}};'
    web["/api-docs/"] = httpx.Response(200, html='<html><script src="./swagger-ui-init.js"></script></html>')
    web["/api-docs/swagger-ui-init.js"] = httpx.Response(200, text=js)
    s = load_spec("http://api.test/api-docs/")
    assert s.from_page and s.raw == doc and s.text == json.dumps(doc) and s.base_url == "https://real.test"
    assert [o.label for o in s.operations] == ["GET /e"]


def test_html_page_without_spec_is_a_clear_error(web):
    web["/"] = httpx.Response(200, html="<html><body><h1>Welcome</h1></body></html>")
    with pytest.raises(ValueError, match="Use 'Discover' with the application's root URL"):
        load_spec("http://api.test/")


def test_ui_page_whose_spec_urls_all_fail(web):
    web["/docs"] = httpx.Response(200, html='<script>SwaggerUIBundle({url: "/openapi.json"})</script>')
    web["/openapi.json"] = httpx.Response(500)
    with pytest.raises(ValueError, match="Not a Swagger"):
        load_spec("http://api.test/docs")


# ---------- scale ----------

def test_huge_spec(tmp_path):
    paths = {f"/r{i}/{{id}}": {m: OK for m in ("get", "put", "delete", "patch", "post")} for i in range(2000)}
    s = load_spec(_file(tmp_path, oas(paths, security=[{"b": []}])))
    assert len(s.operations) == 10_000 and all(o.secured and o.path_params == {"id": "1"} for o in s.operations)
    f = filter_operations(s, ["GET /r1999/{id}", "post /r0/{id}"])
    assert [o.label for o in f.operations] == ["POST /r0/{id}", "GET /r1999/{id}"]


# ---------- filter_operations ----------

def _two(tmp_path):
    return load_spec(_file(tmp_path, oas({"/a": {"parameters": [], "get": OK, "post": OK}, "/b": {"get": OK}},
                                         components={"schemas": {"S": {"type": "string"}}})))


def test_filter_keeps_selected_and_components(tmp_path):
    s = _two(tmp_path)
    f = filter_operations(s, ["get /a", " GET /b "])
    assert f.filtered and f.full_text == s.text and f.version == s.version and f.base_url == s.base_url
    assert [o.label for o in f.operations] == ["GET /a", "GET /b"]
    assert set(f.raw["paths"]["/a"]) == {"parameters", "get"} and f.raw["components"] == s.raw["components"]
    assert json.loads(f.text) == f.raw
    assert "post" in s.raw["paths"]["/a"]  # the original is not modified


def test_filter_drops_paths_with_no_operations_left(tmp_path):
    f = filter_operations(_two(tmp_path), ["POST /a"])
    assert list(f.raw["paths"]) == ["/a"] and set(f.raw["paths"]["/a"]) == {"parameters", "post"}


def test_filter_unknown_operations(tmp_path):
    with pytest.raises(ValueError, match=r"Operation\(s\) not in the spec: DELETE /a, GET /zzz"):
        filter_operations(_two(tmp_path), ["GET /zzz", "DELETE /a", "GET /a"])


def test_filter_ignores_malformed_labels_and_chains(tmp_path):
    s = _two(tmp_path)
    f = filter_operations(s, ["GET", "", "GET /a", "POST /a"])
    assert [o.label for o in f.operations] == ["GET /a", "POST /a"]
    g = filter_operations(f, ["POST /a"])
    assert g.full_text == s.text and [o.label for o in g.operations] == ["POST /a"]
    assert filter_operations(s, []).operations == [] and filter_operations(s, []).raw["paths"] == {}


def test_filter_keeps_from_page(web):
    web["/docs"] = httpx.Response(200, html='<script>SwaggerUIBundle({url: "/openapi.json"})</script>')
    web["/openapi.json"] = httpx.Response(200, json=oas({"/a": {"get": OK}}))
    assert filter_operations(load_spec("http://api.test/docs"), ["GET /a"]).from_page
