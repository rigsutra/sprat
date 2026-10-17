"""Wrong-type probing of JSON request bodies.

For each operation with a JSON body:
  1. Build a valid baseline body (spec example, else generated from the schema) and send it.
     If the server doesn't accept it (non-2xx), probing is skipped for that operation, because
     a rejection could then come from anything, not the type.
  2. For every field, replace its value with values of other types and resend. A 4xx is
     correct. A 2xx means the server accepted the wrong type; a 5xx means it crashed on it.

Unlike plain fuzzing, this includes look-alike values that lenient parsers accept silently:
"1" for an integer, "true" / 1 / 0 for a boolean, "1.5" for a number.
"""
from __future__ import annotations

import copy
import json
import math
import re
from pathlib import Path

import httpx

from ..discover import client_for
from ..models import Finding, StageResult
from ..proc import check, progress
from ..auth import current_headers
from ..explain import ACCESS_TEXT, failure_body, server_said
from ..testlog import log_of
from ..spec import resolve
from .authz import _url

# (label, value) pairs sent in place of a field of the given declared type
MUTATIONS: dict[str, list[tuple[str, object]]] = {
    "string": [("integer", 123), ("number", 1.5), ("boolean", True), ("array", ["x"]),
               ("object", {"a": "x"}), ("null", None)],
    "integer": [('numeric string "1"', "1"), ('string "abc"', "abc"), ("decimal 1.5", 1.5),
                ("boolean", True), ("array", [1]), ("object", {"a": 1}), ("null", None)],
    "number": [('numeric string "1.5"', "1.5"), ('string "abc"', "abc"), ("boolean", True),
               ("array", [1]), ("object", {"a": 1}), ("null", None)],
    "boolean": [('string "true"', "true"), ("integer 1", 1), ("integer 0", 0), ('string "yes"', "yes"),
                ("array", [True]), ("object", {"a": True}), ("null", None)],
    "array": [("string", "x"), ("object", {"a": 1}), ("integer", 1), ("null", None)],
    "object": [("string", "x"), ("array", []), ("integer", 1), ("null", None)],
}
MAX_DEPTH = 4
WRITE_METHODS = {"post", "put", "patch"}


# ---------- schema helpers ----------

def _norm(raw: dict, schema) -> dict:
    """Resolve $ref and flatten allOf. Returns {} for unusable schemas."""
    schema = resolve(raw, schema) or {}
    if not isinstance(schema, dict):
        return {}
    if "allOf" in schema:
        merged = {k: v for k, v in schema.items() if k != "allOf"}
        props, req = dict(merged.get("properties", {})), list(merged.get("required", []))
        for part in schema["allOf"]:
            part = _norm(raw, part)
            props.update(part.get("properties", {}))
            req += part.get("required", [])
            for k, v in part.items():
                if k not in ("properties", "required"):
                    merged.setdefault(k, v)
        merged["properties"], merged["required"] = props, req
        if props:
            merged.setdefault("type", "object")
        return merged
    return schema


def _types(schema: dict) -> set[str]:
    t = schema.get("type")
    if isinstance(t, list):
        types = set(t)
    elif t:
        types = {t}
    elif "properties" in schema:
        types = {"object"}
    elif "items" in schema:
        types = {"array"}
    else:
        types = set()
    if schema.get("nullable") or (schema.get("enum") and None in schema["enum"]):
        types.add("null")
    return types


def _json_type_ok(value, types: set[str]) -> bool:
    """Would `value` be valid for a field declared with `types` (type check only)?"""
    if value is None:
        return "null" in types
    if isinstance(value, bool):
        return "boolean" in types
    if isinstance(value, int):
        return bool({"integer", "number"} & types)
    if isinstance(value, float):
        return "number" in types or ("integer" in types and value.is_integer())
    if isinstance(value, str):
        return "string" in types
    if isinstance(value, list):
        return "array" in types
    if isinstance(value, dict):
        return "object" in types
    return False


def _bound(schema: dict, key: str, integer: bool):
    """Tightest usable minimum/maximum, or None. Exclusive bounds (3.0 boolean form, 3.1 numeric form) step
    1 inward; for integers a fractional bound rounds inward (ceil for a minimum, floor for a maximum)."""
    lower = key == "minimum"
    ex = schema.get("exclusiveM" + key[1:])
    out = []
    for b, excl in ((schema.get(key), ex is True), (ex, True)):
        if not isinstance(b, (int, float)) or isinstance(b, bool):
            continue
        if integer and lower:
            b = math.floor(b) + 1 if excl else math.ceil(b)
        elif integer:
            b = math.ceil(b) - 1 if excl else math.floor(b)
        elif excl:
            b = b + 1 if lower else b - 1
        out.append(b)
    return (max if lower else min)(out, default=None)


def _num_bounds(schema: dict, default: float, integer: bool = False) -> float:
    lo, hi = _bound(schema, "minimum", integer), _bound(schema, "maximum", integer)
    v = lo if lo is not None else default
    if hi is not None and v > hi:
        v = hi
    return v


STRING_FORMATS = {
    "uuid": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "date-time": "2024-01-01T00:00:00Z",
    "date": "2024-01-01",
    "time": "12:00:00",
    "email": "test@example.com",
    "uri": "https://example.com",
    "url": "https://example.com",
    "hostname": "example.com",
    "ipv4": "192.0.2.1",
    "ipv6": "2001:db8::1",
    "byte": "dGVzdA==",
}


def sample(raw: dict, schema, depth: int = 0):
    """Generate one valid value for a schema (best effort)."""
    s = _norm(raw, schema)
    for key in ("example", "default"):
        if key in s:
            return copy.deepcopy(s[key])
    if isinstance(s.get("examples"), list) and s["examples"]:
        return copy.deepcopy(s["examples"][0])
    if s.get("enum"):
        return next((v for v in s["enum"] if v is not None), s["enum"][0])
    for union in ("oneOf", "anyOf"):
        if s.get(union):
            return sample(raw, s[union][0], depth)
    types = _types(s) - {"null"}
    t = next(iter(sorted(types)), "string") if types else ("object" if depth == 0 else "string")
    if t == "object":
        if depth >= MAX_DEPTH:
            return {}
        return {name: sample(raw, sub, depth + 1)
                for name, sub in s.get("properties", {}).items()
                if not _norm(raw, sub).get("readOnly")}
    if t == "array":
        if depth >= MAX_DEPTH:
            return []
        n = max(s.get("minItems", 1), 1)
        return [sample(raw, s.get("items", {}), depth + 1) for _ in range(n)]
    if t == "integer":
        return int(_num_bounds(s, 1, integer=True))
    if t == "number":
        return float(_num_bounds(s, 1.5))
    if t == "boolean":
        return True
    if s.get("format") in STRING_FORMATS:
        return STRING_FORMATS[s["format"]]
    lo, hi = s.get("minLength", 0), s.get("maxLength")
    n = max(lo, 4) if hi is None else min(max(lo, 4), hi)
    return ("test" + "x" * n)[:n]


def body_schema(raw: dict, op) -> tuple[dict | None, object | None]:
    """Return (schema, example) for the JSON request body, or (None, None)."""
    if "requestBody" in op.op:
        rb = resolve(raw, op.op["requestBody"]) or {}
        content = rb.get("content", {})
        mt = next((k for k in content if k == "application/json"), None) or \
            next((k for k in content if re.search(r"[/+]json\b", k)), None)
        if not mt:
            return None, None
        media = content[mt]
        example = media.get("example")
        if example is None and isinstance(media.get("examples"), dict) and media["examples"]:
            example = (resolve(raw, next(iter(media["examples"].values()))) or {}).get("value")
        return media.get("schema"), example
    for p in op.params:
        if p.get("in") == "body":
            return p.get("schema"), None
    return None, None


def fields(raw: dict, schema, value, path: tuple = (), depth: int = 0):
    """Yield (path, declared types) for every field present in `value`."""
    s = _norm(raw, schema)
    if depth > MAX_DEPTH or s.get("oneOf") or s.get("anyOf"):
        return
    if isinstance(value, dict):
        props = s.get("properties", {})
        required = set(s.get("required", []))
        for name, sub in props.items():
            if name not in value:
                continue
            sub_n = _norm(raw, sub)
            if sub_n.get("oneOf") or sub_n.get("anyOf"):
                continue  # union field: many "wrong" types are actually valid
            types = _types(sub_n)
            if types:
                yield path + (name,), types, name in required
            yield from fields(raw, sub_n, value[name], path + (name,), depth + 1)
    elif isinstance(value, list) and value:
        yield from fields(raw, s.get("items", {}), value[0], path + (0,), depth + 1)


def set_at(obj, path: tuple, value):
    obj = copy.deepcopy(obj)
    cur = obj
    for p in path[:-1]:
        cur = cur[p]
    cur[path[-1]] = value
    return obj


def path_str(path: tuple) -> str:
    out = ""
    for p in path:
        out += f"[{p}]" if isinstance(p, int) else (f".{p}" if out else p)
    return out


# ---------- stage ----------

def run(spec, cfg, out: Path) -> StageResult:
    res = StageResult("types")
    base = cfg.base_url or spec.base_url
    if not base:
        res.status, res.note = "error", "No base URL (pass --base-url)"
        return res
    raw = spec.raw
    probed = skipped = sent = 0
    log = []
    candidates = []
    for op in spec.operations:
        if op.method not in WRITE_METHODS or any(re.search(p, op.path) for p in cfg.exclude_paths):
            continue
        schema, example = body_schema(raw, op)
        if schema is not None:
            candidates.append((op, schema, example))
    if not candidates:
        res.note = "No POST/PUT/PATCH operations with a JSON body to probe"
        progress(cfg, "types", res.note)
        return res
    with client_for(base, timeout=cfg.timeout, follow_redirects=False) as c:
        for i, (op, schema, example) in enumerate(candidates, 1):
            baseline = example if example is not None else sample(raw, schema)
            if not isinstance(baseline, (dict, list)):
                continue
            url = _url(base, op.path, op.path_params)
            progress(cfg, "types", "Sending a valid baseline body", op=op.label, done=i - 1, total=len(candidates))

            def send(body):
                nonlocal sent
                check(cfg)
                sent += 1
                return c.request(op.method.upper(), url, headers=current_headers(cfg),
                                 params=op.query_params, json=body)

            tl = log_of(cfg)
            try:
                r = send(baseline)
            except httpx.HTTPError as e:
                res.findings.append(Finding("types", "info", "Request failed", op.label, str(e)))
                if tl:
                    tl.add_error("types", "Valid baseline body", op.method.upper(), url, str(e), op.label)
                continue
            said_200 = failure_body(r.text) if 200 <= r.status_code < 300 else ""
            ok_b = 200 <= r.status_code < 300 and not said_200
            said = said_200 or server_said(r.text)
            if tl:
                own = op.label in (cfg.examples or {})
                tl.add_httpx("types", "Valid request first (every field the correct type)"
                             + (" — your saved example" if own else ""), r, operation=op.label,
                             expected="2xx: a valid body is accepted",
                             verdict="pass" if ok_b else "error",
                             explanation=f"Accepted with HTTP {r.status_code}; wrong-type checks start from this request."
                             if ok_b else
                             f"Even this valid request was refused (HTTP {r.status_code}"
                             + (", but the body says it failed" if said_200 else "")
                             + (f": {said}" if said else "") + "), so the wrong-type "
                             "checks for this API were not run: a refusal wouldn't prove anything. "
                             + ("This is an access problem: set a valid token or API key for user A."
                                if r.status_code in (401, 403) or ACCESS_TEXT.search(said or "") else
                                "Fix the saved example for this API (APIs tab → ✎ Example)." if own else
                                "Save a working request for this API (APIs tab → ✎ Example), or add a working "
                                "`example` to this request body in the Swagger."),
                             details={"example_source": "project" if own else "swagger", "error_200": said_200})
            if not ok_b:
                skipped += 1
                progress(cfg, "types", f"Skipped: valid baseline body got HTTP {r.status_code}"
                         + (f" ({said})" if said else ""), op=op.label, done=i, total=len(candidates), level="warn")
                res.findings.append(Finding(
                    "types", "info", f"Type probing skipped: valid baseline body got HTTP {r.status_code}"
                    + (" with an error body" if said_200 else ""),
                    op.label,
                    "Add a working `example` to this request body in the spec (real IDs that exist on "
                    f"staging), so probing can start from an accepted request.\n\nBaseline sent:\n"
                    f"{json.dumps(baseline, indent=2)[:1200]}\n\nResponse:\n{r.text[:400]}"))
                continue
            probed += 1
            err_200 = []  # wrong-type requests refused, but with HTTP 200 and an error body
            flist = list(fields(raw, schema, baseline))[: cfg.types_max_fields]
            for fi, (fpath, types, required) in enumerate(flist, 1):
                progress(cfg, "types", f"Field {fi}/{len(flist)} `{path_str(fpath)}` ({'/'.join(sorted(types))}): "
                                       "sending wrong types", op=op.label, done=i - 1, total=len(candidates))
                accepted, crashed, null_ok = [], [], False
                for declared in sorted(types - {"null"}):
                    for label, bad in MUTATIONS.get(declared, []):
                        if _json_type_ok(bad, types):
                            continue  # that value is legitimately allowed
                        scenario = (f"Field `{path_str(fpath)}` should be {'/'.join(sorted(types))}; "
                                    f"sent {json.dumps(bad)} ({label}) instead")
                        try:
                            rr = send(set_at(baseline, fpath, bad))
                        except httpx.HTTPError as e:
                            if tl:
                                tl.add_error("types", scenario, op.method.upper(), url, str(e), op.label)
                            continue
                        log.append(f"{op.label} {path_str(fpath)}={json.dumps(bad)} -> {rr.status_code}")
                        said_200 = failure_body(rr.text) if 200 <= rr.status_code < 300 else ""
                        if said_200:
                            err_200.append(f"`{path_str(fpath)}` = {json.dumps(bad)}: HTTP {rr.status_code}, \"{said_200}\"")
                        if tl:
                            ok = 400 <= rr.status_code < 500 or bool(said_200)
                            fname = path_str(fpath)
                            expl = (f"Refused, but with HTTP {rr.status_code} and an error body (\"{said_200}\") "
                                    "instead of a 4xx." if said_200 else
                                    f"Refused with HTTP {rr.status_code}, as it should." if ok else
                                    f"The server crashed (HTTP {rr.status_code}) when `{fname}` was {json.dumps(bad)}."
                                    if rr.status_code >= 500 else
                                    f"Accepted `{fname}` = {json.dumps(bad)} ({label}) with HTTP {rr.status_code}, "
                                    f"although the Swagger says it must be {'/'.join(sorted(types))}. Bad data can "
                                    "get into the system this way.")
                            tl.add_httpx("types", scenario, rr, operation=op.label,
                                         expected="4xx: the wrong type must be rejected",
                                         verdict="pass" if ok else "fail", explanation=expl,
                                         details={"field": path_str(fpath), "declared_type": sorted(types),
                                                  "sent_value": bad, "required": required, "error_200": said_200,
                                                  "problem": "" if ok else ("server crashed (5xx)" if rr.status_code >= 500
                                                                           else "wrong type accepted")})
                        if 200 <= rr.status_code < 300 and not said_200:
                            if bad is None:
                                null_ok = True
                            else:
                                accepted.append(label)
                        elif rr.status_code >= 500:
                            crashed.append(f"{label} -> HTTP {rr.status_code}")
                    break  # mutate against the first declared type only
                declared_s = "/".join(sorted(types))
                name = path_str(fpath)
                if accepted:
                    res.findings.append(Finding(
                        "types", "medium", f"Field `{name}` ({declared_s}) accepted wrong types: {', '.join(accepted)}",
                        op.label, "The server should reject these with 400/422. Lenient JSON parsing or "
                                  "missing validation lets bad data into the system."))
                if null_ok:
                    res.findings.append(Finding(
                        "types", "medium" if required else "low",
                        f"Field `{name}` ({declared_s}, {'required' if required else 'optional'}) accepted null",
                        op.label, "The spec does not mark this field nullable. Either reject null or mark it "
                                  "`nullable: true` / `type: [..., \"null\"]`."))
                if crashed:
                    res.findings.append(Finding(
                        "types", "high", f"Field `{name}` ({declared_s}) crashed the server on wrong type",
                        op.label, "\n".join(crashed)))
                if accepted or crashed:
                    progress(cfg, "types", f"`{name}` " + ("crashed on: " + ", ".join(crashed) if crashed
                             else "accepted: " + ", ".join(accepted)), op=op.label, done=i - 1,
                             total=len(candidates), level="bad")
            if err_200:
                res.findings.append(Finding(
                    "types", "low", "Reports errors with HTTP 200 instead of 4xx", op.label,
                    f"{len(err_200)} wrong-type request(s) were refused, but with HTTP 200 and an error in the body. "
                    "Clients and monitoring read HTTP 200 as success. For example:\n" + "\n".join(err_200[:5])))
            progress(cfg, "types", f"Done: {len(flist)} field(s) probed", op=op.label, done=i,
                     total=len(candidates), level="ok")
    (out / "types.log").write_text("\n".join(log), encoding="utf-8")
    res.note = f"{probed} operation(s) probed, {skipped} skipped (baseline rejected), {sent} requests"
    return res
