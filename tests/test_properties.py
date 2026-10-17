"""Property-based tests (hypothesis) for the pure helpers across sprat."""
import base64
import datetime as dt
import json
import os
import re
import string
from unittest import mock

import httpx
import pytest
from cryptography.fernet import Fernet, InvalidToken
from hypothesis import HealthCheck, assume, given, settings, strategies as st

from sprat import auth, coverage, discover, secretstore, spec as S, testlog
from sprat.config import ENV_REF, Config, expand_env, parse_header
from sprat.spec import Operation, Spec, resolve
from sprat.stages import types as T

# database=None: nothing is written into the repo (no .hypothesis/ directory).
# Cheap properties run 200 examples; heavier ones fewer, to keep the file well under ~30 s.
PROPS = settings(max_examples=200, deadline=None, database=None,
                 suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
MEDIUM = settings(PROPS, max_examples=60)
SLOWER = settings(PROPS, max_examples=30)


def word(first: str, rest: str, max_size: int, min_size: int = 0):
    """Fast stand-in for st.from_regex(f"[{first}][{rest}]{{min,max}}")."""
    return st.builds(lambda a, b: a + b, st.sampled_from(first) if first else st.just(""),
                     st.text(alphabet=rest, min_size=min_size, max_size=max_size))


ALNUM = string.ascii_letters + string.digits

JSON_TYPES = ["null", "boolean", "integer", "number", "string", "array", "object"]
scalars = (st.none() | st.booleans() | st.integers(-10**9, 10**9)
           | st.floats(allow_nan=False, allow_infinity=False) | st.text(max_size=8))
json_values = st.recursive(scalars, lambda c: st.lists(c, max_size=4) | st.dictionaries(st.text(max_size=6), c,
                                                                                        max_size=4), max_leaves=12)


def kinds(v) -> set:
    """JSON Schema types a JSON value belongs to."""
    if v is None:
        return {"null"}
    if isinstance(v, bool):
        return {"boolean"}
    if isinstance(v, int):
        return {"integer", "number"}
    if isinstance(v, float):
        return {"number", "integer"} if v == int(v) else {"number"}
    return {str: {"string"}, list: {"array"}, dict: {"object"}}[type(v)]


def same(a, b) -> bool:
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# ---------- independent validator (JSON Schema + OpenAPI nullable) ----------

def conforms(raw, s, v) -> bool:
    s = resolve(raw, s) or {}
    if not all(conforms(raw, p, v) for p in s.get("allOf", [])):
        return False
    t = s.get("type")
    ts = set(t) if isinstance(t, list) else ({t} if t else set())
    if ts and s.get("nullable"):
        ts.add("null")
    if ts and not ts & kinds(v):
        return False
    if v is None:
        return not ts or "null" in ts
    if "enum" in s and not any(same(e, v) for e in s["enum"]):
        return False
    if "number" in kinds(v):
        lo, hi, ex = s.get("minimum"), s.get("maximum"), s.get("exclusiveMinimum")
        if lo is not None and (v < lo or (ex is True and v == lo)):
            return False
        if hi is not None and v > hi:
            return False
        if type(ex) in (int, float) and v <= ex:
            return False
    if isinstance(v, str) and not s.get("minLength", 0) <= len(v) <= s.get("maxLength", 10**9):
        return False
    if isinstance(v, list) and not (s.get("minItems", 0) <= len(v) <= s.get("maxItems", 10**9)
                                    and all(conforms(raw, s.get("items", {}), x) for x in v)):
        return False
    if isinstance(v, dict):
        props = s.get("properties", {})
        if not set(s.get("required", [])) <= set(v):
            return False
        if s.get("additionalProperties") is False and not set(v) <= set(props):
            return False
        return all(conforms(raw, props[k], x) for k, x in v.items() if k in props)
    return True


# ---------- schema generator: what the types stage supports ----------

NAMES = word(string.ascii_lowercase, ALNUM + "_", 6)


@st.composite
def schemas(draw, max_depth=3):
    """(raw spec, request-body schema): objects, arrays, allOf, $ref, bounds, lengths, enums, formats,
    nullable, readOnly, additionalProperties."""
    comps = {}
    b = lambda: draw(st.booleans())

    def number(t):
        s = {"type": t}
        lo = draw(st.integers(-1000, 1000) if t == "integer" else st.floats(-1000, 1000))
        span = draw(st.integers(1, 50) if t == "integer" else st.floats(0.01, 50))
        style = draw(st.sampled_from(["none", "min", "min_excl", "excl_num", "max"]))
        if style == "min":
            s["minimum"] = lo
        elif style == "min_excl":
            s["minimum"], s["exclusiveMinimum"] = lo, True
        elif style == "excl_num":
            s["exclusiveMinimum"] = lo
        elif style == "max":
            s["maximum"] = lo
        if style in ("min", "min_excl", "excl_num") and b():
            s["maximum"] = lo + span
        return s

    def scalar():
        k = draw(st.sampled_from(["integer", "number", "string", "boolean", "enum", "format"]))
        if k in ("integer", "number"):
            s = number(k)
        elif k == "string":
            s = {"type": "string"}
            if b():
                s["minLength"] = draw(st.integers(0, 8))
            if b():
                s["maxLength"] = s.get("minLength", 0) + draw(st.integers(0, 8))
        elif k == "enum":
            if b():
                s = {"type": "string", "enum": draw(st.lists(st.text(max_size=5), min_size=1, max_size=3, unique=True))}
            else:
                s = {"type": "integer", "enum": draw(st.lists(st.integers(-9, 9), min_size=1, max_size=3, unique=True))}
        elif k == "format":
            s = {"type": "string", "format": draw(st.sampled_from(sorted(T.STRING_FORMATS)))}
        else:
            s = {"type": "boolean"}
        if b() and b():
            s["nullable"] = True
        return s

    def props(depth):
        names = draw(st.lists(NAMES, min_size=1, max_size=3, unique=True))
        p = {n: gen(depth + 1) for n in names}
        return p, [n for n in names if b()]

    def gen(depth):
        kinds_ = ["scalar"] * 3 + (["object", "array", "allof"] if depth < max_depth else [])
        k = draw(st.sampled_from(kinds_))
        if k == "scalar":
            return scalar()
        if k == "array":
            s = {"type": "array", "items": gen(depth + 1), "minItems": draw(st.integers(0, 2))}
            if b():
                s["maxItems"] = max(s["minItems"], 1) + draw(st.integers(0, 2))
            return s
        p, req = props(depth)
        if k == "object":
            s = {"type": "object", "properties": p, "required": req}
            if b():
                s["properties"]["RO"] = {"type": "string", "readOnly": True}
            if b() and b():
                s["additionalProperties"] = False
        else:  # allOf of two parts with disjoint properties
            names = list(p)
            cut = draw(st.integers(0, len(names)))
            part = lambda ns: {"type": "object", "properties": {n: p[n] for n in ns},
                               "required": [n for n in req if n in ns]}
            s = {"allOf": [part(names[:cut]), part(names[cut:])]}
        if b():
            name = f"S{len(comps)}"
            comps[name] = s
            s = {"$ref": f"#/components/schemas/{name}"}
        return s

    p, req = props(0)
    root = {"type": "object", "properties": p, "required": req}
    if b():
        root = {"type": "array", "items": root, "minItems": 1}
    return {"openapi": "3.0.1", "components": {"schemas": comps}}, root


def at(doc, path):
    for p in path:
        doc = doc[p]
    return doc


# ---------- types stage ----------

@MEDIUM
@given(json_values, st.sets(st.sampled_from(JSON_TYPES)))
def test_json_type_ok_matches_json_schema_types(value, types):
    assert T._json_type_ok(value, types) is bool(kinds(value) & types)


@PROPS
@given(st.sampled_from(sorted(T.MUTATIONS)), st.sets(st.sampled_from(JSON_TYPES)))
def test_mutations_sent_are_never_valid_for_the_declared_types(declared, extra):
    types = extra | {declared}
    for _, bad in T.MUTATIONS[declared]:
        if not T._json_type_ok(bad, types):  # what the stage sends
            assert not kinds(bad) & types


@MEDIUM
@given(schemas())
def test_baseline_valid_probes_invalid_one_field_at_a_time(rs):
    raw, schema = rs
    base = T.sample(raw, schema)
    assert conforms(raw, schema, base), base  # the "valid" baseline really is valid
    snapshot = json.dumps(base)
    for path, types, required in T.fields(raw, schema, base):
        cur = at(base, path)
        assert kinds(cur) & types, (path, cur, types)  # the baseline value has the declared type
        assert auth.get_path(base, T.path_str(path)) is cur  # path_str is followable (login token picker syntax)
        parent = T._norm(raw, schema)
        for p in path[:-1]:
            parent = T._norm(raw, parent["items"] if isinstance(p, int) else parent["properties"][p])
        assert required is (path[-1] in parent.get("required", []))
        declared = sorted(types - {"null"})[0]
        for _, bad in T.MUTATIONS[declared]:
            if T._json_type_ok(bad, types):
                continue
            probe = T.set_at(base, path, bad)
            assert not conforms(raw, schema, probe), (path, bad)  # every probe is a wrong-type body
            assert same(T.set_at(probe, path, cur), base)  # ...that differs from the baseline in that field only
    assert json.dumps(base) == snapshot  # set_at never mutates its input
    assert same(base, T.sample(raw, schema))  # deterministic


@SLOWER
@given(rs=schemas())
def test_stage_strict_api_no_findings_lenient_api_every_field(rs, tmp_path):
    raw, schema = rs
    op = Operation("post", "/x", True, True, op={"requestBody": {"content": {"application/json": {"schema": schema}}}})
    spec = Spec(raw, "x", "openapi3", "http://api.test", [op])
    expected = list(T.fields(raw, schema, T.sample(raw, schema)))

    def run(handler):
        mt = httpx.MockTransport(handler)
        with mock.patch.object(T, "client_for", lambda base, **kw: httpx.Client(transport=mt, **kw)):
            return T.run(spec, Config(base_url="http://api.test"), tmp_path)

    strict = run(lambda r: httpx.Response(201 if conforms(raw, schema, json.loads(r.content)) else 400))
    assert strict.findings == [], [f.title for f in strict.findings]
    lenient = run(lambda r: httpx.Response(200))
    wrong = {f.title.split("`")[1] for f in lenient.findings if "wrong types" in f.title}
    nulls = {f.title.split("`")[1]: f.severity for f in lenient.findings if f.title.endswith("accepted null")}
    assert wrong == {T.path_str(p) for p, _, _ in expected}
    assert nulls == {T.path_str(p): "medium" if req else "low" for p, types, req in expected if "null" not in types}


# ---------- auth ----------

KEYS = word("", ALNUM + "_-", 8, min_size=1) | st.text(max_size=8)  # any key, e.g. "a.b" or ""
docs = st.recursive(scalars, lambda c: st.lists(c, max_size=4) | st.dictionaries(KEYS, c, max_size=4),
                    max_leaves=15) | st.lists(scalars, min_size=18, max_size=23).map(lambda xs: {"items": xs})


def count_leaves(o):
    if isinstance(o, dict):
        return sum(count_leaves(v) for v in o.values())
    if isinstance(o, list):
        return sum(count_leaves(v) for v in o[:20])
    return 1


@MEDIUM
@given(docs)
def test_leaf_paths_resolve_back_through_get_path(doc):
    leaves = auth.leaf_paths(doc)
    assert len(leaves) == count_leaves(doc)
    for path, value in leaves:
        assert auth.get_path(doc, path) is value
        indices = re.findall(r"\[(\d+)\]", re.sub(r'\["(?:[^"\\]|\\.)*"\]', "", path))  # not in ["quoted keys"]
        assert all(int(i) < 20 for i in indices)


def test_leaf_paths_dotted_key_round_trip():
    doc = {"auth.token": "abc"}
    [(path, value)] = auth.leaf_paths(doc)
    assert auth.get_path(doc, path) == value


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


@PROPS
@given(st.text() | st.lists(st.text(alphabet=string.ascii_letters + string.digits + "-_=+/", max_size=12),
                            min_size=3, max_size=3).map(".".join)
       | st.binary(max_size=40).map(lambda b: f"h.{_b64(b)}.s"))
def test_jwt_claims_never_raises(token):
    out = auth.jwt_claims(token)
    assert out is None or json.dumps(out)


@MEDIUM
@given(st.dictionaries(st.text(max_size=8), scalars | st.lists(scalars, max_size=3), max_size=5))
def test_jwt_claims_round_trip(claims):
    token = f"{_b64(b'{}')}.{_b64(json.dumps(claims).encode())}.sig"
    assert same(auth.jwt_claims(token), claims)


def test_expiry_with_non_object_jwt_payload():
    p = auth.TokenProvider(auth.LoginConfig(url="http://login.test"))
    assert p._expiry({}, "a.MQ.b", 1000.0)[0] == 1000.0 + auth.DEFAULT_LIFETIME  # payload "MQ" is JSON `1`


@PROPS
@given(st.integers(-10**15, 10**15) | st.floats(-1e15, 1e15), st.floats(0, 2e9))
def test_to_epoch_numbers(value, now):
    got = auth._to_epoch(value, now)
    want = value / 1000.0 if value > 1e12 else float(value) if value > 1e9 else now + value
    assert got == want
    if isinstance(value, int) and value >= 0:
        assert auth._to_epoch(f" {value} ", now) == got  # digit strings are numbers


@PROPS
@given(st.datetimes(min_value=dt.datetime(1, 1, 2), max_value=dt.datetime(9999, 12, 30),
                    timezones=st.just(dt.timezone.utc)))
def test_to_epoch_iso_dates(when):
    assert auth._to_epoch(when.isoformat().replace("+00:00", "Z"), 0.0) == when.timestamp()


@PROPS
@given(st.text(alphabet=string.printable))
def test_to_epoch_never_raises_on_ascii_text(s):
    out = auth._to_epoch(s, 0.0)
    assert out is None or isinstance(out, float)


def test_to_epoch_unicode_digit():
    assert auth._to_epoch("²", 0.0) is None


def test_to_epoch_far_future_naive_date():
    assert isinstance(auth._to_epoch("9999-12-31", 0.0), float)


# ---------- config ----------

VAR_NAMES = word("", string.ascii_uppercase + string.digits + "_", 8, min_size=1).map("SPRAT_HYP_".__add__)


@MEDIUM
@given(st.text(), st.dictionaries(VAR_NAMES, st.text(), max_size=3))
def test_expand_env_identity_without_references(s, variables):
    assume(not ENV_REF.search(s))
    assert expand_env(s, variables) == s


@MEDIUM
@given(st.lists(st.text(alphabet=st.characters(blacklist_characters="$"), max_size=6) | VAR_NAMES.map(lambda n: ("ref", n)),
                max_size=6),
       st.lists(st.text(max_size=6) | st.just("${SPRAT_HYP_OTHER}"), min_size=1, max_size=3))
def test_expand_env_substitutes_each_reference_once(parts, vals):
    names = sorted({p[1] for p in parts if isinstance(p, tuple)})
    variables = {n: vals[i % len(vals)] for i, n in enumerate(names)}
    template = "".join("${" + p[1] + "}" if isinstance(p, tuple) else p for p in parts)
    want = "".join(variables[p[1]] if isinstance(p, tuple) else p for p in parts)
    assert expand_env(template, variables) == want  # values are not expanded again


@MEDIUM
@given(VAR_NAMES, st.text(max_size=8), st.text(max_size=8))
def test_expand_env_missing_raises_and_project_secrets_win(name, before, after):
    assume(name not in os.environ)
    before, after = before.replace("$", ""), after.replace("$", "")
    template = before + "${" + name + "}" + after
    with pytest.raises(ValueError, match=name):
        expand_env(template)
    with mock.patch.dict(os.environ, {name: "from-env"}):
        assert expand_env(template) == before + "from-env" + after
        assert expand_env(template, {name: "from-project"}) == before + "from-project" + after


TOKEN = word("", ALNUM + "!#$%&'*+.^_`|~-", 12, min_size=1)
HVALUE = st.text(alphabet=st.characters(blacklist_categories=("Cc", "Cs", "Zl", "Zp")), min_size=1,
                 max_size=20).map(str.strip).filter(bool)


@PROPS
@given(TOKEN, HVALUE, st.text(" \t", max_size=2), st.text(" \t", max_size=2))
def test_parse_header_round_trip(name, value, ws1, ws2):
    assert parse_header(f"{ws1}{name}{ws1}:{ws2}{value}{ws2}") == (name, value)


@PROPS
@given(st.text(max_size=30))
def test_parse_header_raises_only_the_documented_error(h):
    name, _, value = (s.strip() for s in h.partition(":"))
    try:
        assert parse_header(h) == (name, value)
    except ValueError as e:
        assert "Name: value" in str(e)
        assert not name or not value


def test_parse_header_empty_name():
    with pytest.raises(ValueError):
        parse_header(": abc")


# ---------- secretstore ----------

@PROPS
@given(st.text(max_size=12) | word(string.ascii_letters + "_", ALNUM + "_", 10))
def test_check_name_accepts_only_names_usable_as_references(name):
    try:
        secretstore.check_name(name)
    except ValueError:
        assert not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name)
        return
    assert ENV_REF.fullmatch("${" + name + "}")
    assert expand_env("${" + name + "}", {name: "v"}) == "v"


def test_check_name_rejects_trailing_newline():
    with pytest.raises(ValueError):
        secretstore.check_name("PASSWORD\n")


@PROPS
@given(st.text(min_size=1, max_size=30), st.text(min_size=1, max_size=30), st.binary(max_size=40))
def test_passphrase_keys_round_trip_and_differ(p1, p2, data):
    token = secretstore._fernet_from(p1).encrypt(data)
    assert secretstore._fernet_from(p1).decrypt(token) == data
    if p1 != p2:
        with pytest.raises(InvalidToken):
            secretstore._fernet_from(p2).decrypt(token)


def test_real_fernet_key_is_used_as_is():
    key = Fernet.generate_key()
    assert secretstore._fernet_from(key.decode()).decrypt(Fernet(key).encrypt(b"x")) == b"x"


# ---------- testlog ----------

SECRET = st.text(alphabet=st.characters(blacklist_characters="*", blacklist_categories=("Cs",)), min_size=6,
                 max_size=12)
JWTS = st.lists(word("", ALNUM + "_-", 10, min_size=5), min_size=3, max_size=3).map(lambda p: "eyJ" + ".".join(p))


@MEDIUM
@given(secrets=st.lists(SECRET, min_size=1, max_size=3), chunks=st.lists(st.text(max_size=8), max_size=5),
       data=st.data())
def test_mask_text_never_leaks_a_configured_secret(secrets, chunks, data, tmp_path):
    tl = testlog.TestLog(tmp_path / "t.ndjson", secrets=secrets)
    text = "".join(c + data.draw(st.sampled_from(secrets)) for c in chunks + [""])
    out = tl._mask_text(text)
    assert not any(s in out for s in secrets)
    assert not any(s in tl._body(text) for s in secrets)


@MEDIUM
@given(parts=st.lists(st.text(max_size=6) | JWTS, max_size=6))
def test_mask_text_removes_every_jwt(parts, tmp_path):
    tl = testlog.TestLog(tmp_path / "t.ndjson")
    text = " ".join(parts)
    out = tl._mask_text(text)
    assert not testlog.JWT.search(out)
    if "eyJ" not in text:
        assert out == text


@PROPS
@given(name=st.sampled_from(sorted(testlog.SENSITIVE)), upper=st.booleans(), value=st.text(max_size=20))
def test_sensitive_headers_never_keep_their_credential(name, upper, value, tmp_path):
    tl = testlog.TestLog(tmp_path / "t.ndjson")
    out = tl._headers({name.upper() if upper else name: value})
    [(k, v)] = out.items()
    scheme = value.partition(" ")[0]
    assert v == "***" or (v == f"{scheme} ***" and scheme.lower() in ("bearer", "basic", "token"))


@PROPS
@given(body=st.text(max_size=120) | st.binary(max_size=120))
def test_body_is_truncated_and_binary_is_summarised(body, tmp_path):
    tl = testlog.TestLog(tmp_path / "t.ndjson")
    with mock.patch.object(testlog, "BODY_LIMIT", 40):
        out = tl._body(body)
    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8")
        except UnicodeDecodeError:
            assert out == f"<{len(body)} bytes of binary data>"
            return
    masked = tl._mask_text(body)
    assert out == masked if len(masked) <= 40 else out.startswith(masked[:40]) and f"{len(masked)} chars" in out


@PROPS
@given(st.text())
def test_b64_or_text_round_trip(s):
    assert testlog.b64_or_text({"$base64": base64.b64encode(s.encode()).decode()}) == s
    assert testlog.b64_or_text(s) == s


SEG = word("", string.ascii_lowercase + string.digits + "-", 6, min_size=1)
VAL = word("", ALNUM + "_~-", 8, min_size=1)


@MEDIUM
@given(st.lists(st.tuples(st.booleans(), SEG), min_size=1, max_size=5), st.data(),
       st.sampled_from(["", "/api", "/api/v1/"]), st.booleans())
def test_op_matcher_maps_concrete_urls_to_their_template(segs, data, base_path, slash):
    template = "".join(f"/{{{n}}}" if is_param else f"/{n}" for is_param, n in segs)
    concrete = "".join(f"/{data.draw(VAL)}" if is_param else f"/{n}" for is_param, n in segs)
    m = testlog.OpMatcher([Operation("put", template, False, False)], "http://h.test" + base_path)
    url = "http://h.test" + base_path.rstrip("/") + concrete + ("/" if slash else "") + "?q=1"
    assert m("PUT", url) == f"PUT {template}"
    assert m("GET", url) == ""


# ---------- spec / discover / coverage ----------

@MEDIUM
@given(st.dictionaries(st.text(min_size=1, max_size=8), st.integers(), min_size=1, max_size=4))
def test_resolve_follows_escaped_json_pointers(defs):
    raw = {"components": {"schemas": {k: {"x": v} for k, v in defs.items()}}}
    for k, v in defs.items():
        ref = "#/components/schemas/" + k.replace("~", "~0").replace("/", "~1")
        assert resolve(raw, {"$ref": ref}) == {"x": v}


@MEDIUM
@given(st.builds(lambda s, h, port, segs, slash: f"{s}://{h}{port}{segs}{slash}", st.sampled_from(["http", "https"]),
                 word(string.ascii_lowercase, string.ascii_lowercase + ".", 10), st.sampled_from(["", ":8080"]),
                 st.lists(SEG, max_size=3).map(lambda xs: "".join("/" + x for x in xs)), st.sampled_from(["", "/", "//"])),
       st.sampled_from(["openapi", "swagger"]))
def test_derive_base_url_absolute_and_without_trailing_slash(url, kind):
    if kind == "openapi":
        got = S._derive_base_url({"openapi": "3.0.0", "servers": [{"url": url}]}, "spec.json")
        assert got == url.rstrip("/")
    else:
        host = url.split("://")[1].split("/")[0]
        got = S._derive_base_url({"swagger": "2.0", "host": host, "basePath": "/v1/"}, "spec.json")
        assert got == f"https://{host}/v1"
    assert not got.endswith("/")


@MEDIUM
@given(st.text(max_size=60) | json_values.map(json.dumps)
       | st.dictionaries(st.sampled_from(["openapi", "swagger", "paths", "info"]), json_values).map(json.dumps))
def test_parse_spec_returns_a_spec_or_none(text):
    doc = discover.parse_spec(text)
    assert doc is None or (isinstance(doc, dict) and ("openapi" in doc or "swagger" in doc)
                           and isinstance(doc.get("paths", {}), dict))


def test_parse_spec_impossible_yaml_date():
    assert discover.parse_spec("openapi: 3.0.0\npaths: {}\ninfo: {released: 2024-02-30}") is None


@MEDIUM
@given(st.lists(st.text(max_size=8) | st.lists(st.sampled_from(["read:a", "write:b", 3]), max_size=3), max_size=3),
       st.sampled_from(["required", "requiredScopes", "required_scopes"]))
def test_missing_permissions_from_scope_lists(scopes, key):
    entries = [{"response": {"status": 403, "body": json.dumps({key: s})}} for s in scopes]
    got = coverage._missing_permissions({"GET /x": entries})
    want = {str(p) for s in scopes if isinstance(s, list) for p in s}
    assert set(got) == want and all(v == {"GET /x"} for v in got.values())
