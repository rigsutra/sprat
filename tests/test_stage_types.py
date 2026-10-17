"""Wrong-type probing stage (sprat/stages/types.py): schema helpers, value generation and the
stage itself against in-process fake APIs (httpx.MockTransport, no network)."""
import json
import threading

import httpx
import pytest

from sprat.config import Config
from sprat.proc import Cancelled
from sprat.spec import Operation, Spec, resolve
from sprat.stages import types as T
from sprat.testlog import TestLog, iter_entries

BASE = "http://api.test"
OAS = {"openapi": "3.0.1"}


# ---------- an independent (JSON Schema semantics) validator: the strict fake API ----------

def _is(v, t):
    num = isinstance(v, (int, float)) and not isinstance(v, bool)
    return {"null": v is None, "boolean": isinstance(v, bool), "string": isinstance(v, str),
            "array": isinstance(v, list), "object": isinstance(v, dict), "number": num,
            "integer": num and float(v).is_integer()}[t]


def conforms(raw, s, v) -> bool:
    s = resolve(raw, s) or {}
    if not all(conforms(raw, p, v) for p in s.get("allOf", [])):
        return False
    if "oneOf" in s and sum(conforms(raw, p, v) for p in s["oneOf"]) != 1:
        return False
    if "anyOf" in s and not any(conforms(raw, p, v) for p in s["anyOf"]):
        return False
    t = s.get("type")
    ts = set(t) if isinstance(t, list) else ({t} if t else set())
    if s.get("nullable"):
        ts.add("null") if ts else None
    if v is None:
        return "null" in ts or (not ts and (not s.get("enum") or None in s["enum"]))
    if ts and not any(_is(v, x) for x in ts):
        return False
    if "enum" in s and not any(type(e) is type(v) and e == v for e in s["enum"]):
        return False
    if _is(v, "number"):
        lo, hi, exlo, exhi = (s.get(k) for k in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"))
        if lo is not None and (v < lo or (exlo is True and v == lo)):
            return False
        if hi is not None and (v > hi or (exhi is True and v == hi)):
            return False
        if type(exlo) in (int, float) and v <= exlo or type(exhi) in (int, float) and v >= exhi:
            return False
    if isinstance(v, str) and not s.get("minLength", 0) <= len(v) <= s.get("maxLength", 10**9):
        return False
    if isinstance(v, list):
        if not s.get("minItems", 0) <= len(v) <= s.get("maxItems", 10**9):
            return False
        if not all(conforms(raw, s.get("items", {}), x) for x in v):
            return False
    if isinstance(v, dict):
        props = s.get("properties", {})
        if not set(s.get("required", [])) <= set(v):
            return False
        if s.get("additionalProperties") is False and not set(v) <= set(props):
            return False
        if not all(conforms(raw, props[k], x) for k, x in v.items() if k in props):
            return False
    return True


# ---------- harness ----------

def body_op(schema, method="post", path="/items", example=None, ctype="application/json", **kw):
    media = {"schema": schema}
    if example is not None:
        media["example"] = example
    return Operation(method, path, True, True, op={"requestBody": {"content": {ctype: media}}}, **kw)


def run_stage(monkeypatch, tmp_path, handler, ops, raw=None, cfg=None, spec_base=BASE):
    calls = []

    def h(request):
        calls.append(request)
        return handler(request)

    monkeypatch.setattr(T, "client_for",
                        lambda base, **kw: httpx.Client(transport=httpx.MockTransport(h), **kw))
    cfg = cfg or Config(base_url=BASE)
    res = T.run(Spec(raw or OAS, "x", "openapi3", spec_base, ops), cfg, tmp_path)
    return res, calls


def strict(raw, schema):
    return lambda r: httpx.Response(201 if conforms(raw, schema, json.loads(r.content)) else 400)


def lenient(r):
    return httpx.Response(201)


def bodies(calls):
    return [json.loads(c.content) for c in calls]


def titles(res):
    return [f.title for f in res.findings]


def obj(props, required=()):
    return {"type": "object", "required": list(required), "properties": props}


# ---------- _norm / _types / _json_type_ok / _num_bounds ----------

RAW = {"openapi": "3.0.1", "components": {"schemas": {
    "Base": obj({"id": {"type": "integer"}}, ["id"]) | {"description": "base"},
    "Named": {"allOf": [{"$ref": "#/components/schemas/Base"},
                        obj({"name": {"type": "string"}}, ["name"])]},
    "Ro": {"type": "string", "readOnly": True},
    "Node": obj({"v": {"type": "integer"}, "next": {"$ref": "#/components/schemas/Node"}}),
    "Loop": {"$ref": "#/components/schemas/Loop"},
}}}


def test_norm_resolves_ref_and_flattens_nested_allof():
    s = T._norm(RAW, {"allOf": [{"$ref": "#/components/schemas/Named"},
                                obj({"age": {"type": "integer"}}, ["age"])], "description": "top"})
    assert set(s["properties"]) == {"id", "name", "age"}
    assert sorted(s["required"]) == ["age", "id", "name"]
    assert s["type"] == "object" and s["description"] == "top"  # own keys win over parts
    assert "allOf" not in s


def test_norm_allof_without_properties_keeps_part_type():
    s = T._norm({}, {"allOf": [{"type": "string", "maxLength": 3}]})
    assert s["type"] == "string" and s["maxLength"] == 3 and s["properties"] == {}


@pytest.mark.parametrize("schema", [None, "string", 3, {"$ref": "#/components/schemas/Missing"}])
def test_norm_unusable_schema_is_empty(schema):
    assert T._norm(RAW, schema) == {}


@pytest.mark.parametrize("schema, types", [
    ({"type": "string"}, {"string"}),
    ({"type": ["integer", "null"]}, {"integer", "null"}),
    ({"type": "string", "nullable": True}, {"string", "null"}),
    ({"type": "string", "enum": ["a", None]}, {"string", "null"}),
    ({"enum": ["a", None]}, {"null"}),
    ({"enum": ["a"]}, set()),
    ({"properties": {"a": {}}}, {"object"}),
    ({"items": {"type": "string"}}, {"array"}),
    ({}, set()),
    ({"description": "anything"}, set()),
])
def test_types(schema, types):
    assert T._types(schema) == types


@pytest.mark.parametrize("value, types, ok", [
    (None, {"null"}, True), (None, {"string"}, False),
    (True, {"boolean"}, True), (True, {"integer"}, False), (False, {"number"}, False),
    (0, {"integer"}, True), (0, {"number"}, True), (0, {"boolean"}, False), (1, {"string"}, False),
    (2.0, {"integer"}, True), (1.5, {"integer"}, False), (1.5, {"number"}, True), (1.5, {"string"}, False),
    ("1", {"integer"}, False), ("true", {"boolean"}, False), ("x", {"string"}, True),
    ([], {"array"}, True), ([], {"object"}, False), ({}, {"object"}, True), ({}, {"array"}, False),
    ("x", set(), False), ({1, 2}, {"array", "object", "string"}, False),  # not a JSON value at all
    (1.5, {"integer", "number"}, True), ("1", {"integer", "string"}, True),
])
def test_json_type_ok(value, types, ok):
    assert T._json_type_ok(value, types) is ok


@pytest.mark.parametrize("schema, default, want", [
    ({}, 1, 1), ({"minimum": 5}, 1, 5), ({"minimum": -3}, 1, -3),
    ({"minimum": 5, "exclusiveMinimum": True}, 1, 6), ({"minimum": 5, "exclusiveMinimum": False}, 1, 5),
    ({"exclusiveMinimum": True}, 1, 1),  # boolean form without a minimum: nothing to exclude
    ({"exclusiveMinimum": 2}, 1, 3), ({"exclusiveMinimum": 1.5}, 1.5, 2.5),
    ({"maximum": 0}, 1, 0), ({"maximum": 10}, 1.5, 1.5), ({"minimum": 3, "maximum": 3}, 1, 3),
    ({"exclusiveMinimum": 0, "maximum": 0.5}, 1.5, 0.5),
])
def test_num_bounds(schema, default, want):
    assert T._num_bounds(schema, default) == want


@pytest.mark.parametrize("schema", [{"type": "integer", "maximum": 1, "exclusiveMaximum": True},
                                    {"type": "number", "exclusiveMaximum": 1}])
def test_sample_respects_exclusive_maximum(schema):
    assert conforms({}, schema, T.sample({}, schema))


def test_sample_integer_with_fractional_minimum():
    assert T.sample({}, {"type": "integer", "minimum": 1.5}) == 2


# ---------- sample ----------

@pytest.mark.parametrize("schema, want", [
    ({"type": "integer", "example": 7, "default": 3}, 7),
    ({"type": "integer", "default": 3}, 3),
    ({"type": "integer", "examples": [9, 8]}, 9),
    ({"type": "integer", "examples": []}, 1),
    ({"type": "string", "enum": [None, "b", "c"]}, "b"),
    ({"enum": [None]}, None),
    ({"oneOf": [{"$ref": "#/components/schemas/Ro"}, {"type": "integer"}]}, "test"),
    ({"anyOf": [{"type": "boolean"}, {"type": "string"}]}, True),
    ({"type": "integer"}, 1), ({"type": "number"}, 1.5), ({"type": "boolean"}, True),
    ({"type": "string"}, "test"), ({"type": "string", "minLength": 7}, "testxxx"),
    ({"type": "string", "maxLength": 2}, "te"), ({"type": "string", "maxLength": 0}, ""),
    ({"type": "string", "minLength": 2, "maxLength": 3}, "tes"),
    ({"type": "string", "format": "made-up"}, "test"),
    ({"type": ["null", "integer"]}, 1), ({"type": ["integer", "string"]}, 1),
    ({"type": "integer", "minimum": 10, "maximum": 20}, 10), ({"type": "number", "maximum": -2}, -2.0),
    ({}, {}), ({"properties": {"a": {"type": "boolean"}}}, {"a": True}),
    ({"type": "array", "items": {"type": "integer"}}, [1]),
    ({"type": "array", "items": {"type": "integer"}, "minItems": 0}, [1]),
    ({"type": "array", "items": {"type": "boolean"}, "minItems": 3}, [True, True, True]),
    ({"type": "array"}, ["test"]),
    ({"$ref": "#/components/schemas/Named"}, {"id": 1, "name": "test"}),
])
def test_sample(schema, want):
    got = T.sample(RAW, schema)
    assert got == want and type(got) is type(want)


@pytest.mark.parametrize("fmt", sorted(T.STRING_FORMATS))
def test_sample_string_formats(fmt):
    assert T.sample({}, {"type": "string", "format": fmt}) == T.STRING_FORMATS[fmt]


def test_sample_untyped_nested_field_is_a_string():
    assert T.sample({}, obj({"x": {"description": "no type"}})) == {"x": "test"}


def test_sample_skips_read_only_fields_also_through_ref():
    s = obj({"id": {"type": "integer", "readOnly": True}, "ro": {"$ref": "#/components/schemas/Ro"},
             "name": {"type": "string"}})
    assert T.sample(RAW, s) == {"name": "test"}


def test_sample_terminates_on_recursive_and_cyclic_refs():
    s = T.sample(RAW, {"$ref": "#/components/schemas/Node"})
    depth, cur = 0, s
    while "next" in cur:
        cur, depth = cur["next"], depth + 1
    assert depth == T.MAX_DEPTH and cur == {}
    assert T.sample(RAW, {"$ref": "#/components/schemas/Loop"}) == {}


def test_sample_depth_limits():
    assert T.sample({}, obj({"a": {"type": "integer"}}), depth=T.MAX_DEPTH) == {}
    assert T.sample({}, {"type": "array", "items": {"type": "integer"}}, depth=T.MAX_DEPTH) == []


def test_sample_returns_copies_of_examples():
    schema = {"type": "object", "example": {"a": [1]}}
    T.sample({}, schema)["a"].append(2)
    assert schema["example"] == {"a": [1]}


# ---------- body_schema ----------

SCHEMA = obj({"a": {"type": "integer"}})


@pytest.mark.parametrize("ctype", ["application/json", "application/json; charset=utf-8",
                                   "application/vnd.api+json", "application/problem+json", "text/json",
                                   "application/merge-patch+json"])
def test_body_schema_json_media_types(ctype):
    assert T.body_schema(OAS, body_op(SCHEMA, ctype=ctype)) == (SCHEMA, None)


@pytest.mark.parametrize("ctype", ["application/x-www-form-urlencoded", "multipart/form-data", "text/plain",
                                   "application/xml", "application/x-ndjson", "application/jsonl",
                                   "application/octet-stream"])
def test_body_schema_non_json_media_types(ctype):
    assert T.body_schema(OAS, body_op(SCHEMA, ctype=ctype)) == (None, None)


def test_body_schema_prefers_exact_application_json():
    other = {"type": "string"}
    op = Operation("post", "/x", True, True, op={"requestBody": {"content": {
        "application/vnd.api+json": {"schema": other}, "application/json": {"schema": SCHEMA}}}})
    assert T.body_schema(OAS, op)[0] is SCHEMA


def test_body_schema_examples_and_refs():
    raw = {"openapi": "3.0.1", "components": {
        "requestBodies": {"Rb": {"content": {"application/json": {
            "schema": SCHEMA, "examples": {"first": {"$ref": "#/components/examples/E"}, "second": {"value": 2}}}}}},
        "examples": {"E": {"value": {"a": 5}}}}}
    op = Operation("post", "/x", True, True, op={"requestBody": {"$ref": "#/components/requestBodies/Rb"}})
    assert T.body_schema(raw, op) == (SCHEMA, {"a": 5})
    assert T.body_schema(OAS, body_op(SCHEMA, example={"a": 9})) == (SCHEMA, {"a": 9})
    empty = Operation("post", "/x", True, True,
                      op={"requestBody": {"content": {"application/json": {"schema": SCHEMA, "examples": {}}}}})
    assert T.body_schema(OAS, empty) == (SCHEMA, None)


def test_body_schema_swagger2_body_param_and_no_body():
    sw = Operation("post", "/x", True, True, params=[{"in": "query", "name": "q"},
                                                    {"in": "body", "name": "b", "schema": SCHEMA}])
    assert T.body_schema({}, sw) == (SCHEMA, None)
    assert T.body_schema({}, Operation("post", "/x", True, False, params=[{"in": "formData", "name": "f"}])) \
        == (None, None)
    assert T.body_schema({}, Operation("post", "/x", True, False)) == (None, None)


# ---------- fields / set_at / path_str ----------

def _fields(raw, schema, value):
    return {T.path_str(p): (types, req) for p, types, req in T.fields(raw, schema, value)}


def test_fields_paths_types_and_required():
    schema = obj({
        "id": {"type": "integer"},
        "addr": obj({"zip": {"type": "string"}, "geo": obj({"lat": {"type": "number"}}, ["lat"])}, ["zip"]),
        "tags": {"type": "array", "items": obj({"label": {"type": "string", "nullable": True}})},
        "flag": {"type": ["boolean", "null"]},
    }, ["id", "tags"])
    got = _fields({}, schema, T.sample({}, schema))
    assert got == {
        "id": ({"integer"}, True), "addr": ({"object"}, False), "addr.zip": ({"string"}, True),
        "addr.geo": ({"object"}, False), "addr.geo.lat": ({"number"}, True), "tags": ({"array"}, True),
        "tags[0].label": ({"string", "null"}, False), "flag": ({"boolean", "null"}, False)}


def test_fields_only_present_declared_fields():
    schema = obj({"a": {"type": "integer"}, "b": {"type": "integer"}})
    assert set(_fields({}, schema, {"a": 1, "extra": "x"})) == {"a"}  # absent b, undeclared extra
    assert _fields({}, schema, "not an object") == {}


def test_fields_skip_unions_but_not_allof():
    schema = obj({"u": {"oneOf": [{"type": "string"}, {"type": "integer"}]},
                  "v": {"anyOf": [{"type": "string"}]},
                  "w": {"allOf": [{"$ref": "#/components/schemas/Base"}]}})
    got = _fields(RAW, schema, {"u": "x", "v": "y", "w": {"id": 1}})
    assert got == {"w": ({"object"}, False), "w.id": ({"integer"}, True)}
    assert _fields(RAW, {"oneOf": [SCHEMA]}, {"a": 1}) == {}


def test_fields_untyped_properties():
    schema = obj({"free": {"description": "any"}, "meta": {"properties": {"n": {"type": "integer"}}}})
    got = _fields({}, schema, {"free": "x", "meta": {"n": 1}})
    assert got == {"meta": ({"object"}, False), "meta.n": ({"integer"}, False)}  # properties imply object


def test_fields_top_level_array_and_empty_list():
    schema = {"type": "array", "items": {"$ref": "#/components/schemas/Base"}}
    assert _fields(RAW, schema, [{"id": 1}, {"id": 2}]) == {"[0].id": ({"integer"}, True)}
    assert _fields(RAW, schema, []) == {}
    nested = obj({"m": {"type": "array", "items": {"type": "array", "items": obj({"x": {"type": "string"}})}}})
    assert _fields({}, nested, {"m": [[{"x": "a"}]]}) == {"m": ({"array"}, False), "m[0][0].x": ({"string"}, False)}


def test_fields_depth_limit():
    schema = {"type": "integer"}
    for name in "fedcba":
        schema = obj({name: schema})
    value = {"a": {"b": {"c": {"d": {"e": {"f": 1}}}}}}
    got = _fields({}, schema, value)
    assert "a.b.c.d.e" in got and "a.b.c.d.e.f" not in got


def test_set_at_copies_and_handles_lists():
    doc = {"a": [{"b": 1}], "c": 2}
    out = T.set_at(doc, ("a", 0, "b"), None)
    assert out == {"a": [{"b": None}], "c": 2} and doc == {"a": [{"b": 1}], "c": 2}
    assert T.set_at([{"x": 1}], (0, "x"), "y") == [{"x": "y"}]


@pytest.mark.parametrize("path, want", [((), ""), (("a",), "a"), (("a", "b"), "a.b"), (("a", 0, "b"), "a[0].b"),
                                        ((0, "id"), "[0].id"), (("a", 0, 0), "a[0][0]"), ((3,), "[3]")])
def test_path_str(path, want):
    assert T.path_str(path) == want


# ---------- MUTATIONS ----------

@pytest.mark.parametrize("declared, label, value",
                         [(t, label, v) for t, ms in T.MUTATIONS.items() for label, v in ms])
def test_every_mutation_is_the_wrong_type(declared, label, value):
    assert not T._json_type_ok(value, {declared})
    assert not conforms({}, {"type": declared}, value)
    json.dumps(value)  # always sendable as JSON


def test_mutations_include_null_and_lenient_look_alikes():
    vals = {t: [v for _, v in ms] for t, ms in T.MUTATIONS.items()}
    assert all(None in v for v in vals.values())
    assert "1" in vals["integer"] and 1.5 in vals["integer"]
    assert "1.5" in vals["number"]
    assert {"true", "yes"} <= set(x for x in vals["boolean"] if isinstance(x, str))
    assert [x for x in vals["boolean"] if type(x) is int] == [1, 0]


# ---------- stage: setup and selection ----------

def test_no_base_url_is_an_error(tmp_path):
    res = T.run(Spec(OAS, "x", "openapi3", "", [body_op(SCHEMA)]), Config(), tmp_path)
    assert res.status == "error" and "base URL" in res.note


def test_spec_base_url_used_when_config_has_none(monkeypatch, tmp_path):
    res, calls = run_stage(monkeypatch, tmp_path, strict({}, SCHEMA), [body_op(SCHEMA)],
                           cfg=Config(), spec_base="http://spec.test/v1/")
    assert calls and all(str(c.url) == "http://spec.test/v1/items" for c in calls)


def test_nothing_to_probe(monkeypatch, tmp_path):
    events = []
    ops = [Operation("get", "/a", True, False), body_op(SCHEMA, method="delete"),
           body_op(SCHEMA, ctype="application/x-www-form-urlencoded"), body_op(SCHEMA, path="/admin/x"),
           Operation("post", "/nobody", True, False)]
    cfg = Config(base_url=BASE, exclude_paths=["^/admin"], on_progress=events.append)
    res, calls = run_stage(monkeypatch, tmp_path, lenient, ops, cfg=cfg)
    assert calls == [] and res.findings == [] and res.status == "ok"
    assert res.note.startswith("No POST/PUT/PATCH operations")
    assert events == [{"stage": "types", "msg": res.note, "op": "", "done": None, "total": None, "level": "info"}]
    assert not (tmp_path / "types.log").exists()


def test_exclude_paths_is_a_regex_search(monkeypatch, tmp_path):
    ops = [body_op(SCHEMA, path="/v1/admin/users"), body_op(SCHEMA, path="/v1/items")]
    res, calls = run_stage(monkeypatch, tmp_path, lenient, ops, cfg=Config(base_url=BASE, exclude_paths=["admin"]))
    assert {c.url.path for c in calls} == {"/v1/items"}


@pytest.mark.parametrize("method", ["post", "put", "patch"])
def test_write_methods_are_probed_with_their_method(monkeypatch, tmp_path, method):
    res, calls = run_stage(monkeypatch, tmp_path, lenient, [body_op(SCHEMA, method=method)])
    assert {c.method for c in calls} == {method.upper()}
    assert titles(res)[0].startswith("Field `a` (integer) accepted wrong types")


def test_swagger2_body_parameter_is_probed(monkeypatch, tmp_path):
    op = Operation("post", "/pets", True, True, params=[{"in": "body", "name": "b", "schema": SCHEMA}])
    res, calls = run_stage(monkeypatch, tmp_path, strict({}, SCHEMA), [op])
    assert res.findings == [] and len(calls) == 1 + len(T.MUTATIONS["integer"])


# ---------- stage: strict vs lenient servers ----------

BIG_RAW = {"openapi": "3.0.1", "components": {"schemas": {
    "Address": obj({"street": {"type": "string", "minLength": 1}, "zip": {"type": "string", "maxLength": 5},
                    "geo": obj({"lat": {"type": "number", "minimum": -90, "maximum": 90},
                                "lng": {"type": "number"}}, ["lat", "lng"])}, ["street"]),
    "Tag": obj({"label": {"type": "string"}, "weight": {"type": "integer", "minimum": 1}}, ["label"]),
    "Order": {"allOf": [
        obj({"id": {"type": "integer", "readOnly": True}, "created": {"type": "string", "format": "date-time"}}),
        {"type": "object", "required": ["qty", "active"], "additionalProperties": True, "properties": {
            "qty": {"type": "integer", "minimum": 1, "maximum": 99},
            "price": {"type": "number", "exclusiveMinimum": 0},
            "active": {"type": "boolean"},
            "note": {"type": "string", "nullable": True},
            "status": {"type": "string", "enum": ["new", "paid"]},
            "level": {"type": "integer", "enum": [1, 2, 3]},
            "email": {"type": "string", "format": "email"},
            "ref": {"type": "string", "format": "uuid"},
            "address": {"$ref": "#/components/schemas/Address"},
            "tags": {"type": "array", "minItems": 1, "items": {"$ref": "#/components/schemas/Tag"}},
            "codes": {"type": "array", "items": {"type": "integer"}},
            "meta": {"type": "object", "additionalProperties": {"type": "string"}},
            "kind": {"oneOf": [{"type": "string"}, {"type": "integer"}]},
            "maybe": {"type": ["integer", "null"]},
            "either": {"type": ["integer", "string"]},
        }}]},
}}}
ORDER = {"$ref": "#/components/schemas/Order"}
ORDER_FIELDS = {"created", "qty", "price", "active", "note", "status", "level", "email", "ref", "address",
                "address.street", "address.zip", "address.geo", "address.geo.lat", "address.geo.lng", "tags",
                "tags[0].label", "tags[0].weight", "codes", "meta", "maybe", "either"}


def test_baseline_of_complex_schema_is_valid():
    body = T.sample(BIG_RAW, ORDER)
    assert conforms(BIG_RAW, ORDER, body) and "id" not in body
    assert set(_fields(BIG_RAW, ORDER, body)) == ORDER_FIELDS


def test_strict_server_no_false_positives(monkeypatch, tmp_path):
    res, calls = run_stage(monkeypatch, tmp_path, strict(BIG_RAW, ORDER), [body_op(ORDER)], raw=BIG_RAW)
    assert res.findings == [], titles(res)
    assert res.note == f"1 operation(s) probed, 0 skipped (baseline rejected), {len(calls)} requests"
    # every probe really was wrong, and only the baseline was right
    assert [conforms(BIG_RAW, ORDER, b) for b in bodies(calls)] == [True] + [False] * (len(calls) - 1)


def test_lenient_server_every_field_flagged(monkeypatch, tmp_path):
    res, calls = run_stage(monkeypatch, tmp_path, lenient, [body_op(ORDER)], raw=BIG_RAW)
    wrong = {f.title.split("`")[1] for f in res.findings if "accepted wrong types" in f.title}
    nulls = {f.title.split("`")[1]: f.severity for f in res.findings if f.title.endswith("accepted null")}
    assert wrong == ORDER_FIELDS
    assert nulls == {"created": "low", "qty": "medium", "price": "low", "active": "medium", "status": "low",
                     "level": "low", "email": "low", "ref": "low", "address": "low", "address.street": "medium",
                     "address.zip": "low", "address.geo": "low", "address.geo.lat": "medium",
                     "address.geo.lng": "medium", "tags": "low", "tags[0].label": "medium",
                     "tags[0].weight": "low", "codes": "low", "meta": "low", "either": "low"}
    assert {f.severity for f in res.findings if "wrong types" in f.title} == {"medium"}
    assert all(f.stage == "types" and f.endpoint == "POST /items" for f in res.findings)
    assert 'Field `qty` (integer) accepted wrong types: numeric string "1", string "abc", decimal 1.5, ' \
           'boolean, array, object' in titles(res)
    assert "Field `active` (boolean, required) accepted null" in titles(res)
    assert "Field `note` (null/string) accepted wrong types: integer, number, boolean, array, object" in titles(res)
    assert "Field `either` (integer/string) accepted wrong types: decimal 1.5, boolean, array, object" in titles(res)


def test_nullable_and_union_fields_never_get_null_or_allowed_values(monkeypatch, tmp_path):
    res, calls = run_stage(monkeypatch, tmp_path, lenient, [body_op(ORDER)], raw=BIG_RAW)
    sent = bodies(calls)[1:]
    base = bodies(calls)[0]
    changed = lambda k: [b[k] for b in sent if b.get(k) != base.get(k)]
    assert None not in changed("note") and None not in changed("maybe")
    assert "1" not in changed("either") and "abc" not in changed("either")
    assert changed("kind") == []  # oneOf fields are not probed at all


@pytest.mark.parametrize("declared", sorted(T.MUTATIONS))
def test_each_declared_type_reports_every_non_null_mutation(monkeypatch, tmp_path, declared):
    schema = obj({"f": {"type": declared}}, ["f"])
    res, calls = run_stage(monkeypatch, tmp_path, lenient, [body_op(schema)])
    labels = [label for label, v in T.MUTATIONS[declared] if v is not None]
    assert titles(res) == [f"Field `f` ({declared}) accepted wrong types: {', '.join(labels)}",
                           f"Field `f` ({declared}, required) accepted null"]
    assert [b["f"] for b in bodies(calls)[1:]] == [v for _, v in T.MUTATIONS[declared]]


def _lookalike_server(request):
    """A lenient parser: coerces "1" -> 1, "true"/1/0 -> bool, "1.5" -> 1.5; rejects everything else wrong."""
    b = json.loads(request.content)
    n, flag, price = b.get("n"), b.get("flag"), b.get("price")
    ok = ((type(n) is int or n == "1") and (type(flag) is bool or flag in ("true", 1, 0))
          and (type(price) in (int, float) and type(price) is not bool or price == "1.5"))
    return httpx.Response(200 if ok else 422)


def test_lookalike_values_are_caught(monkeypatch, tmp_path):
    schema = obj({"n": {"type": "integer"}, "flag": {"type": "boolean"}, "price": {"type": "number"}},
                 ["n", "flag", "price"])
    res, _ = run_stage(monkeypatch, tmp_path, _lookalike_server, [body_op(schema)])
    assert sorted(titles(res)) == ['Field `flag` (boolean) accepted wrong types: string "true", integer 1, integer 0',
                                   'Field `n` (integer) accepted wrong types: numeric string "1"',
                                   'Field `price` (number) accepted wrong types: numeric string "1.5"']


def test_null_only_accepted(monkeypatch, tmp_path):
    schema = obj({"a": {"type": "integer"}, "b": {"type": "string"}}, ["a"])
    handler = lambda r: httpx.Response(
        200 if all(v is None or type(v) is t for v, t in zip(json.loads(r.content).values(), (int, str))) else 400)
    res, _ = run_stage(monkeypatch, tmp_path, handler, [body_op(schema)])
    assert [(f.severity, f.title) for f in res.findings] == [
        ("medium", "Field `a` (integer, required) accepted null"),
        ("low", "Field `b` (string, optional) accepted null")]


def test_server_crash_is_high(monkeypatch, tmp_path):
    def handler(r):
        a = json.loads(r.content)["a"]
        return httpx.Response(201 if type(a) is int else 500 if a is None or isinstance(a, str) else 400)
    events = []
    res, _ = run_stage(monkeypatch, tmp_path, handler, [body_op(SCHEMA)],
                       cfg=Config(base_url=BASE, on_progress=events.append))
    [f] = res.findings
    assert (f.severity, f.title) == ("high", "Field `a` (integer) crashed the server on wrong type")
    assert f.detail.splitlines() == ['numeric string "1" -> HTTP 500', 'string "abc" -> HTTP 500', "null -> HTTP 500"]
    bad = [e for e in events if e["level"] == "bad"]
    assert len(bad) == 1 and bad[0]["msg"].startswith("`a` crashed on: numeric string")


def test_accepted_and_crashed_on_same_field(monkeypatch, tmp_path):
    def handler(r):
        a = json.loads(r.content)["a"]
        return httpx.Response(201 if type(a) is int or a == "1" else 503 if isinstance(a, list) else 400)
    res, _ = run_stage(monkeypatch, tmp_path, handler, [body_op(SCHEMA)])
    assert [(f.severity, f.title) for f in res.findings] == [
        ("medium", 'Field `a` (integer) accepted wrong types: numeric string "1"'),
        ("high", "Field `a` (integer) crashed the server on wrong type")]
    assert res.findings[1].detail == "array -> HTTP 503"


# ---------- stage: baseline handling ----------

def test_example_is_the_baseline(monkeypatch, tmp_path):
    res, calls = run_stage(monkeypatch, tmp_path, lenient, [body_op(SCHEMA, example={"a": 42, "zz": "kept"})])
    assert bodies(calls)[0] == {"a": 42, "zz": "kept"}
    assert all(b["zz"] == "kept" for b in bodies(calls))


def test_top_level_array_body(monkeypatch, tmp_path):
    schema = {"type": "array", "items": obj({"id": {"type": "integer"}}, ["id"])}
    res, calls = run_stage(monkeypatch, tmp_path, lenient, [body_op(schema)])
    assert bodies(calls)[0] == [{"id": 1}]
    assert 'Field `[0].id` (integer) accepted wrong types: numeric string "1", string "abc", decimal 1.5, ' \
           'boolean, array, object' in titles(res)


def test_scalar_baseline_is_not_probed(monkeypatch, tmp_path):
    res, calls = run_stage(monkeypatch, tmp_path, lenient, [body_op({"type": "string"})])
    assert calls == [] and res.findings == []
    assert res.note == "0 operation(s) probed, 0 skipped (baseline rejected), 0 requests"


@pytest.mark.parametrize("status", [400, 404, 422, 302, 500])
def test_rejected_baseline_skips_the_operation(monkeypatch, tmp_path, status):
    events = []
    res, calls = run_stage(monkeypatch, tmp_path, lambda r: httpx.Response(status, text="nope"),
                           [body_op(SCHEMA)], cfg=Config(base_url=BASE, on_progress=events.append))
    assert len(calls) == 1
    [f] = res.findings
    assert (f.severity, f.title) == ("info", f"Type probing skipped: valid baseline body got HTTP {status}")
    assert '"a": 1' in f.detail and f.detail.endswith("Response:\nnope")
    assert res.note == "0 operation(s) probed, 1 skipped (baseline rejected), 1 requests"
    assert [e["level"] for e in events if "Skipped" in e["msg"]] == ["warn"]


@pytest.mark.parametrize("exc", [httpx.ConnectError("refused"), httpx.ReadTimeout("timed out")])
def test_baseline_transport_error_continues_with_next_op(monkeypatch, tmp_path, exc):
    def handler(r):
        if r.url.path == "/down":
            raise exc
        return httpx.Response(400)
    log = TestLog(tmp_path / "log.ndjson")
    ops = [body_op(SCHEMA, path="/down"), body_op(SCHEMA, path="/up")]
    res, calls = run_stage(monkeypatch, tmp_path, handler, ops, cfg=Config(base_url=BASE, testlog=log))
    assert [(f.title, f.endpoint) for f in res.findings] == [
        ("Request failed", "POST /down"), ("Type probing skipped: valid baseline body got HTTP 400", "POST /up")]
    assert str(exc) in res.findings[0].detail
    first = next(iter_entries(log.path))
    assert (first["verdict"], first["scenario"], first["operation"]) == ("error", "Valid baseline body", "POST /down")
    assert first["details"]["error"] == str(exc)


def test_probe_transport_errors_are_logged_not_reported(monkeypatch, tmp_path):
    def handler(r):
        if type(json.loads(r.content)["a"]) is int:
            return httpx.Response(201)
        raise httpx.ReadTimeout("slow")
    log = TestLog(tmp_path / "log.ndjson")
    res, calls = run_stage(monkeypatch, tmp_path, handler, [body_op(SCHEMA)], cfg=Config(base_url=BASE, testlog=log))
    assert res.findings == []
    entries = list(iter_entries(log.path))
    assert [e["verdict"] for e in entries] == ["pass"] + ["error"] * len(T.MUTATIONS["integer"])
    assert entries[1]["scenario"] == 'Field `a` should be integer; sent "1" (numeric string "1") instead'
    assert res.note.endswith(f"{len(calls)} requests") and len(calls) == 8
    assert (tmp_path / "types.log").read_text(encoding="utf-8") == ""


# ---------- stage: requests sent ----------

def test_path_query_and_headers_are_sent_unchanged(monkeypatch, tmp_path):
    class Provider:
        def headers(self):
            return {"Authorization": "Bearer fresh"}
    op = body_op(SCHEMA, path="/users/{uid}/items", path_params={"uid": "7"}, query_params={"dry": "true"})
    cfg = Config(base_url=BASE + "/", headers={"X-Tenant": "t1"})
    cfg.auth_a = Provider()
    res, calls = run_stage(monkeypatch, tmp_path, lenient, [op], cfg=cfg)
    assert len(calls) == 8
    for c in calls:
        assert c.url.path == "/users/7/items" and dict(c.url.params) == {"dry": "true"}
        assert c.headers["x-tenant"] == "t1" and c.headers["authorization"] == "Bearer fresh"
        assert c.headers["content-type"] == "application/json"


def test_only_one_field_changes_per_probe(monkeypatch, tmp_path):
    res, calls = run_stage(monkeypatch, tmp_path, lenient, [body_op(ORDER)], raw=BIG_RAW)
    base, *probes = bodies(calls)
    for b in probes:
        diff = [k for k in set(base) | set(b) if json.dumps(base.get(k)) != json.dumps(b.get(k))]
        assert len(diff) == 1


def test_types_max_fields_caps_probing(monkeypatch, tmp_path):
    schema = obj({"a": {"type": "integer"}, "b": {"type": "string"}, "c": {"type": "boolean"}})
    res, calls = run_stage(monkeypatch, tmp_path, lenient, [body_op(schema)],
                           cfg=Config(base_url=BASE, types_max_fields=1))
    assert {f.title.split("`")[1] for f in res.findings} == {"a"}
    assert len(calls) == 1 + len(T.MUTATIONS["integer"])


def test_types_log_lines(monkeypatch, tmp_path):
    res, calls = run_stage(monkeypatch, tmp_path, lambda r: httpx.Response(
        201 if json.loads(r.content)["a"] == 1 else 422), [body_op(SCHEMA)])
    lines = (tmp_path / "types.log").read_text(encoding="utf-8").splitlines()
    assert lines[0] == 'POST /items a="1" -> 422' and lines[-1] == "POST /items a=null -> 422"
    assert len(lines) == len(T.MUTATIONS["integer"])


# ---------- stage: progress, test log, cancellation ----------

def test_progress_events(monkeypatch, tmp_path):
    events = []
    ops = [body_op(SCHEMA, path="/one"), body_op(SCHEMA, path="/two")]
    handler = lambda r: httpx.Response(400 if r.url.path == "/two" else 201)
    run_stage(monkeypatch, tmp_path, handler, ops, cfg=Config(base_url=BASE, on_progress=events.append))
    assert {e["stage"] for e in events} == {"types"} and {e["total"] for e in events} == {2}
    msgs = [(e["op"], e["msg"], e["done"], e["level"]) for e in events]
    assert msgs == [
        ("POST /one", "Sending a valid baseline body", 0, "info"),
        ("POST /one", "Field 1/1 `a` (integer): sending wrong types", 0, "info"),
        ("POST /one", '`a` accepted: numeric string "1", string "abc", decimal 1.5, boolean, array, object', 0, "bad"),
        ("POST /one", "Done: 1 field(s) probed", 1, "ok"),
        ("POST /two", "Sending a valid baseline body", 1, "info"),
        ("POST /two", "Skipped: valid baseline body got HTTP 400", 2, "warn"),
    ]


def test_testlog_entries(monkeypatch, tmp_path):
    def handler(r):
        a = json.loads(r.content)["a"]
        return httpx.Response(201 if a in (1, "1") else 500 if a is None else 422)
    log = TestLog(tmp_path / "log.ndjson")
    run_stage(monkeypatch, tmp_path, handler, [body_op(SCHEMA)], cfg=Config(base_url=BASE, testlog=log))
    base, *probes = list(iter_entries(log.path))
    assert base["scenario"] == "Valid request first (every field the correct type)"
    assert (base["verdict"], base["expected"], base["stage"]) == ("pass", "2xx: a valid body is accepted", "types")
    assert base["explanation"].startswith("Accepted with HTTP 201")
    by_value = {json.dumps(p["details"]["sent_value"]): p for p in probes}
    assert len(by_value) == len(T.MUTATIONS["integer"])
    ok, acc, crash = by_value['"abc"'], by_value['"1"'], by_value["null"]
    assert (ok["verdict"], ok["details"]["problem"]) == ("pass", "")
    assert ok["explanation"] == "Refused with HTTP 422, as it should."
    assert (acc["verdict"], acc["details"]["problem"]) == ("fail", "wrong type accepted")
    assert "although the Swagger says it must be integer" in acc["explanation"]
    assert (crash["verdict"], crash["details"]["problem"]) == ("fail", "server crashed (5xx)")
    assert crash["explanation"] == "The server crashed (HTTP 500) when `a` was null."
    assert acc["details"] | {"sent_value": None} == {"field": "a", "declared_type": ["integer"], "sent_value": None,
                                                     "required": False, "problem": "wrong type accepted",
                                                     "error_200": ""}
    assert all(p["expected"] == "4xx: the wrong type must be rejected" and p["operation"] == "POST /items"
               and p["response"]["status"] in (201, 422, 500) for p in probes)
    assert json.loads(acc["request"]["body"]) == {"a": "1"}


@pytest.mark.parametrize("status, body, hint", [
    (401, "", "set a valid token or API key for user A"), (403, '{"message": "missing scope"}', "missing scope"),
    (400, '{"detail": "qty is required"}', "Save a working request for this API (APIs tab → ✎ Example)")])
def test_testlog_rejected_baseline_explanation(monkeypatch, tmp_path, status, body, hint):
    log = TestLog(tmp_path / "log.ndjson")
    run_stage(monkeypatch, tmp_path, lambda r: httpx.Response(status, text=body), [body_op(SCHEMA)],
              cfg=Config(base_url=BASE, testlog=log))
    [e] = list(iter_entries(log.path))
    assert e["verdict"] == "error" and f"HTTP {status}" in e["explanation"] and hint in e["explanation"]


def test_cancel_before_start_sends_nothing(monkeypatch, tmp_path):
    ev = threading.Event()
    ev.set()
    with pytest.raises(Cancelled):
        run_stage(monkeypatch, tmp_path, lenient, [body_op(SCHEMA)], cfg=Config(base_url=BASE, cancel=ev))


def test_cancel_mid_run_stops_sending(monkeypatch, tmp_path):
    ev = threading.Event()
    sent = []

    def handler(r):
        sent.append(r)
        if len(sent) == 3:
            ev.set()
        return httpx.Response(201)
    with pytest.raises(Cancelled):
        run_stage(monkeypatch, tmp_path, handler, [body_op(ORDER), body_op(SCHEMA, path="/b")], raw=BIG_RAW,
                  cfg=Config(base_url=BASE, cancel=ev))
    assert len(sent) == 3
