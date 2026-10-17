import httpx

from sprat.config import Config
from sprat.spec import Operation, Spec
from sprat.stages import types as T

RAW = {
    "openapi": "3.0.1",
    "components": {"schemas": {
        "Base": {"type": "object", "required": ["id"], "properties": {"id": {"type": "integer", "minimum": 5}}},
        "Item": {"allOf": [{"$ref": "#/components/schemas/Base"}, {
            "type": "object", "required": ["active"],
            "properties": {
                "active": {"type": "boolean"},
                "note": {"type": "string", "nullable": True, "maxLength": 2},
                "tags": {"type": "array", "items": {"type": "object", "properties": {"label": {"type": "string"}}}},
                "kind": {"oneOf": [{"type": "string"}, {"type": "integer"}]},
                "created": {"type": "string", "format": "date-time", "readOnly": True},
            }}]},
    }},
}
ITEM = {"$ref": "#/components/schemas/Item"}


def test_json_type_ok():
    assert T._json_type_ok(1, {"integer"}) and T._json_type_ok(1, {"number"})
    assert not T._json_type_ok(True, {"integer"})  # bool is not an integer in JSON Schema
    assert not T._json_type_ok("1", {"integer"})
    assert T._json_type_ok(None, {"string", "null"}) and not T._json_type_ok(None, {"string"})
    assert T._json_type_ok(2.0, {"integer"}) and not T._json_type_ok(1.5, {"integer"})


def test_sample_respects_allof_bounds_formats_readonly():
    s = T.sample(RAW, ITEM)
    assert s["id"] == 5 and s["active"] is True
    assert len(s["note"]) <= 2
    assert "created" not in s  # readOnly is never sent
    assert s["tags"] == [{"label": "test"}]


def test_fields_walks_nested_and_skips_unions():
    s = T.sample(RAW, ITEM)
    got = {T.path_str(p): (types, req) for p, types, req in T.fields(RAW, ITEM, s)}
    assert got["id"] == ({"integer"}, True)
    assert got["active"] == ({"boolean"}, True)
    assert got["note"] == ({"string", "null"}, False)
    assert "tags[0].label" in got
    assert "kind" not in got  # oneOf: many "wrong" types are valid


def _strict_server(request: httpx.Request) -> httpx.Response:
    import json
    body = json.loads(request.content)
    tags = body.get("tags", [])
    ok = (type(body.get("id")) is int and type(body.get("active")) is bool
          and ("note" not in body or body["note"] is None or type(body["note"]) is str)
          and type(tags) is list
          and all(type(t) is dict and type(t.get("label", "")) is str for t in tags))
    return httpx.Response(201 if ok else 400)


def _lenient_server(request: httpx.Request) -> httpx.Response:
    return httpx.Response(201)


def _run_with(handler, monkeypatch, tmp_path):
    real_client = httpx.Client
    monkeypatch.setattr(T.httpx, "Client", lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw))
    op = Operation("post", "/items", True, True, op={"requestBody": {"content": {"application/json": {"schema": ITEM}}}})
    spec = Spec(RAW, "x", "openapi3", "http://api.test", [op])
    return T.run(spec, Config(base_url="http://api.test"), tmp_path)


def test_strict_server_has_no_findings(monkeypatch, tmp_path):
    res = _run_with(_strict_server, monkeypatch, tmp_path)
    assert res.findings == [], [f.title for f in res.findings]


def test_lenient_server_is_flagged_per_field(monkeypatch, tmp_path):
    res = _run_with(_lenient_server, monkeypatch, tmp_path)
    titles = " | ".join(f.title for f in res.findings)
    assert 'Field `active` (boolean) accepted wrong types: string "true"' in titles
    assert 'Field `id` (integer) accepted wrong types: numeric string "1"' in titles
    assert "Field `active` (boolean, required) accepted null" in titles
    assert "Field `note` (null/string) accepted wrong types: integer" in titles
    # note is nullable, so null must not be reported for it
    assert not any("note" in f.title and "accepted null" in f.title for f in res.findings)
