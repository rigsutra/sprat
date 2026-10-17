"""TestLog: writing, masking, truncation, reading back, CSV export."""
import base64
import csv
import io
import json
import threading
from types import SimpleNamespace

import httpx
import pytest

from sprat import testlog
from sprat.spec import Operation
from sprat.testlog import BODY_LIMIT, CSV_FIELDS, OpMatcher, TestLog, b64_or_text, iter_entries, log_of, write_csv

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJxYUB4LnRlc3QifQ.c2lnbmF0dXJlLXBhcnQ"


def _rows(path):
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


@pytest.fixture
def log(tmp_path):
    return TestLog(tmp_path / "sub" / "test-log.ndjson", secrets=["s3cret-value-1", "short", "", None])


def test_init_creates_parent_and_truncates(tmp_path):
    p = tmp_path / "a" / "b" / "log.ndjson"
    p.parent.mkdir(parents=True)
    p.write_text("old line\n", encoding="utf-8")
    TestLog(p)
    assert p.read_text(encoding="utf-8") == ""


def test_short_and_empty_secrets_are_not_masked(log):
    assert log.secrets == ["s3cret-value-1"]  # < 6 chars would mask common words everywhere
    assert log._mask_text("short and s3cret-value-1") == "short and ***"


def test_longer_secret_is_masked_before_its_prefix(tmp_path):
    tl = TestLog(tmp_path / "l.ndjson", secrets=["abcdefgh", "abcdefghijkl"])
    assert tl.secrets[0] == "abcdefghijkl"
    assert tl._mask_text("x abcdefghijkl y abcdefgh") == "x *** y ***"


def test_token_sources_are_masked(tmp_path):
    prov = SimpleNamespace(token="live-token-from-login-123")
    tl = TestLog(tmp_path / "l.ndjson", token_sources=[prov, SimpleNamespace(token=None), SimpleNamespace()])
    tl.add("authz", "s", request={"method": "GET", "url": "http://x/?t=live-token-from-login-123",
                                  "headers": {"X-Debug": "live-token-from-login-123"}})
    row = _rows(tl.path)[0]
    assert "live-token" not in json.dumps(row)
    prov.token = "rotated-token-abcdef"  # a refreshed token is masked too
    tl.add("authz", "s2", response={"status": 200, "body": "your token is rotated-token-abcdef"})
    assert _rows(tl.path)[1]["response"]["body"] == "your token is ***"


def test_any_jwt_is_masked_even_if_unknown(log):
    assert log._mask_text(f"token={JWT}&x=1") == "token=***jwt***&x=1"
    assert log._mask_text("eyJ but not a jwt") == "eyJ but not a jwt"


@pytest.mark.parametrize("name,value,want", [
    ("Authorization", "Bearer abc.def", "Bearer ***"),
    ("authorization", "Basic dXNlcjpwYXNz", "Basic ***"),
    ("AUTHORIZATION", "Token xyz", "Token ***"),
    ("Authorization", "Digest user=x", "***"),
    ("Authorization", "rawtoken", "***"),
    ("Proxy-Authorization", "Bearer x", "Bearer ***"),
    ("Cookie", "session=abc; theme=dark", "***"),
    ("Set-Cookie", "session=abc; HttpOnly", "***"),
    ("X-API-Key", "k-123", "***"),
    ("api-key", "k-123", "***"),
    ("X-Auth-Token", "Bearer t", "Bearer ***"),
    ("X-Other", "contains s3cret-value-1 here", "contains *** here"),
    ("X-Other", "plain", "plain"),
])
def test_header_masking(log, name, value, want):
    assert log._mask_value(name, value) == want


def test_list_header_values_are_joined_and_names_stringified(log):
    assert log._headers({"Accept": ["a", "b"], 5: 6}) == {"Accept": "a, b", "5": "6"}
    assert log._headers(None) == {}


def test_body_variants(log):
    assert log._body(None) is None
    assert log._body("text s3cret-value-1") == "text ***"
    assert log._body("héllo ✓".encode()) == "héllo ✓"
    assert log._body(b"\xff\xfe\x00\x81") == "<4 bytes of binary data>"
    assert log._body({"name": "Zoë", "n": 1}) == '{"name": "Zoë", "n": 1}'  # unicode kept, not \u escaped
    assert log._body([1, 2]) == "[1, 2]"
    assert log._body("") == ""


def test_large_body_is_truncated_after_masking(log):
    big = "s3cret-value-1" + "x" * (BODY_LIMIT * 2)
    out = log._body(big)
    assert out.startswith("***x")
    assert len(out) < BODY_LIMIT + 100
    assert out.endswith(f"[truncated, {len(big) - len('s3cret-value-1') + 3} chars total]")
    assert log._body("y" * BODY_LIMIT) == "y" * BODY_LIMIT  # exactly at the limit: untouched


def test_add_writes_full_entry(log):
    log.add("conformance", "Edge cases: s3cret-value-1", operation="GET /a", expected="4xx", verdict="fail",
            request={"method": "POST", "url": "http://x/a?k=s3cret-value-1", "headers": {"Authorization": "Bearer t"},
                     "body": {"a": 1}},
            response={"status": 500, "headers": {"Set-Cookie": "x=y"}, "body": b"oops", "elapsed_ms": 12.5},
            details={"failures": ["boom"]}, ts=1700000000.0, explanation="crashed with s3cret-value-1")
    log.add("lint", "no request")
    a, b = _rows(log.path)
    assert a == {"seq": 1, "ts": 1700000000.0, "stage": "conformance", "operation": "GET /a",
                 "scenario": "Edge cases: ***", "expected": "4xx", "verdict": "fail",
                 "explanation": "crashed with ***",
                 "request": {"method": "POST", "url": "http://x/a?k=***", "headers": {"Authorization": "Bearer ***"},
                             "body": '{"a": 1}'},
                 "response": {"status": 500, "headers": {"Set-Cookie": "***"}, "body": "oops", "elapsed_ms": 12.5},
                 "details": {"failures": ["boom"]}}
    assert b["seq"] == 2 and b["verdict"] == "info" and b["request"] is None and b["response"] is None
    assert b["details"] == {} and b["ts"] > 1700000000


def test_request_defaults_when_fields_missing(log):
    log.add("authz", "s", request={"url": "http://x"}, response={"body": None})
    row = _rows(log.path)[0]
    assert row["request"] == {"method": "", "url": "http://x", "headers": {}, "body": None}
    assert row["response"] == {"status": None, "headers": {}, "body": None, "elapsed_ms": None}


def test_concurrent_adds_get_unique_sequence_numbers(tmp_path):
    tl = TestLog(tmp_path / "l.ndjson")
    threads = [threading.Thread(target=lambda: [tl.add("types", f"s{i}") for i in range(50)]) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    rows = _rows(tl.path)
    assert sorted(r["seq"] for r in rows) == list(range(1, 401))


def test_add_httpx_logs_exchange(tmp_path):
    tl = TestLog(tmp_path / "l.ndjson", secrets=["api-key-value-9"])

    def handler(req):
        return httpx.Response(201, json={"echo": req.headers.get("x-api-key")}, headers={"Set-Cookie": "sid=1"})
    with httpx.Client(transport=httpx.MockTransport(handler)) as c:
        r = c.post("http://api.test/items?x=1", json={"name": "ü"}, headers={"X-API-Key": "api-key-value-9"})
    tl.add_httpx("types", "Valid request", r, operation="POST /items", expected="2xx", verdict="pass",
                 details={"field": "name"}, explanation="ok")
    row = _rows(tl.path)[0]
    assert row["request"]["method"] == "POST" and row["request"]["url"] == "http://api.test/items?x=1"
    assert row["request"]["headers"]["x-api-key"] == "***"
    assert json.loads(row["request"]["body"]) == {"name": "ü"}
    assert row["response"]["status"] == 201 and row["response"]["headers"]["set-cookie"] == "***"
    assert json.loads(row["response"]["body"]) == {"echo": "***"}
    assert row["response"]["elapsed_ms"] is None or isinstance(row["response"]["elapsed_ms"], float)
    assert row["details"] == {"field": "name"} and row["operation"] == "POST /items"


def test_add_httpx_without_elapsed_or_readable_request_body(tmp_path):
    tl = TestLog(tmp_path / "l.ndjson")

    def gen():
        yield b"chunk"
    req = httpx.Request("PUT", "http://api.test/x", content=gen())  # streaming body: .content not readable
    tl.add_httpx("authz", "s", httpx.Response(204, request=req))  # never sent: .elapsed raises
    row = _rows(tl.path)[0]
    assert row["request"]["body"] is None and row["response"]["elapsed_ms"] is None
    assert row["response"]["status"] == 204 and row["response"]["body"] == ""


def test_add_httpx_never_raises_on_garbage(tmp_path):
    tl = TestLog(tmp_path / "l.ndjson")
    tl.add_httpx("authz", "s", object(), details={"k": 1})  # no .request at all
    row = _rows(tl.path)[0]
    assert row["details"]["k"] == 1 and "AttributeError" in row["details"]["log_error"]


def test_add_error(log):
    log.add_error("authz", "No token", "GET", "http://x/a", "ConnectError: refused", operation="GET /a")
    row = _rows(log.path)[0]
    assert row["verdict"] == "error" and row["details"] == {"error": "ConnectError: refused"}
    assert "couldn't be completed (ConnectError: refused)" in row["explanation"]
    assert row["request"]["method"] == "GET" and row["response"] is None


def test_log_of():
    assert log_of(SimpleNamespace()) is None
    marker = object()
    assert log_of(SimpleNamespace(testlog=marker)) is marker


def test_iter_entries_skips_blank_and_broken_lines(tmp_path):
    p = tmp_path / "l.ndjson"
    assert list(iter_entries(p)) == []  # missing file
    p.write_text('{"seq": 1}\n\n   \nnot json\n{"seq": 2}\n{"seq": \n{"seq": 3}', encoding="utf-8")
    assert [e["seq"] for e in iter_entries(p)] == [1, 2, 3]


def test_csv_round_trip_with_awkward_text(tmp_path):
    tl = TestLog(tmp_path / "l.ndjson")
    nasty = 'Zoë, "quoted", comma,\nnew line; 日本語 ✓ =1+1'
    tl.add("conformance", nasty, operation="POST /a,b", expected=nasty, verdict="fail", explanation=nasty,
           request={"method": "POST", "url": "http://x/a?q=1,2", "body": nasty},
           response={"status": 422, "body": nasty, "elapsed_ms": 3.2}, ts=1700000000)
    tl.add("lint", "no request, no explanation", details={"failures": ["first", "second"]})
    tl.add("zap", "alert", details={"attack": "' OR 1=1"})
    tl.add("authz", "err", details={"error": "timeout"})
    tl.add("authz", "evidence", details={"evidence": "Server: x"})
    tl.add("authz", "message", details={"message": "hi"})
    tl.add("authz", "nothing")
    out = tmp_path / "l.csv"
    assert write_csv(tl.path, out) == 7
    raw = out.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")  # BOM for Excel
    rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
    assert list(rows[0]) == CSV_FIELDS
    r = rows[0]
    assert r["scenario"] == nasty and r["expected"] == nasty and r["explanation"] == nasty
    assert r["request_body"] == nasty and r["response_body"] == nasty
    assert r["operation"] == "POST /a,b" and r["url"] == "http://x/a?q=1,2"
    assert (r["seq"], r["method"], r["status"], r["elapsed_ms"], r["verdict"]) == ("1", "POST", "422", "3.2", "fail")
    assert len(r["time"]) == 19 and r["time"][4] == "-"
    assert [x["explanation"] for x in rows[1:]] == ["first | second", "attack: ' OR 1=1", "error: timeout",
                                                    "evidence: Server: x", "message: hi", ""]
    assert rows[1]["method"] == "" and rows[1]["status"] == "" and rows[1]["request_body"] == ""


def test_csv_cuts_long_bodies_and_details(tmp_path):
    tl = TestLog(tmp_path / "l.ndjson")
    tl.add("x", "s", request={"method": "GET", "url": "u", "body": "a" * 5000}, response={"status": 200, "body": "b" * 5000},
           details={"failures": ["f" * 800]})
    write_csv(tl.path, tmp_path / "o.csv")
    r = next(csv.DictReader(io.StringIO((tmp_path / "o.csv").read_text(encoding="utf-8-sig"))))
    assert len(r["request_body"]) == 2000 and len(r["response_body"]) == 2000 and len(r["explanation"]) == 500


def test_csv_of_missing_log_has_only_header(tmp_path):
    assert write_csv(tmp_path / "none.ndjson", tmp_path / "o.csv") == 0
    assert (tmp_path / "o.csv").read_text(encoding="utf-8-sig").strip() == ",".join(CSV_FIELDS)


@pytest.mark.parametrize("content,want", [
    (None, None),
    ({"$base64": base64.b64encode("héllo".encode()).decode()}, "héllo"),
    ({"$base64": base64.b64encode(b"\xff\xfe").decode()}, "��"),
    ({"$base64": "abc"}, None),  # bad padding
    ("plain", "plain"),
    ({"a": 1}, '{"a": 1}'),
    ([1], "[1]"),
])
def test_b64_or_text(content, want):
    assert b64_or_text(content) == want


def test_op_matcher():
    ops = [Operation("get", "/items", False, False), Operation("get", "/items/{id}", False, False),
           Operation("delete", "/items/{id}", False, False), Operation("post", "/items/{id}/tags/{tag}", False, True)]
    m = OpMatcher(ops, "https://shop.test/api/")
    assert m("GET", "https://shop.test/api/items") == "GET /items"
    assert m("get", "https://shop.test/api/items/42?x=1") == "GET /items/{id}"
    assert m("DELETE", "https://shop.test/api/items/42/") == "DELETE /items/{id}"
    assert m("POST", "https://shop.test/api/items/1/tags/red") == "POST /items/{id}/tags/{tag}"
    assert m("PUT", "https://shop.test/api/items/1") == ""
    assert m("GET", "https://shop.test/api/items/1/2") == ""
    assert m("GET", "/api/items?x=1") == "GET /items"  # relative URL
    assert OpMatcher(ops, "")("GET", "http://h/items") == "GET /items"
    assert OpMatcher([Operation("get", "/", False, False)], "http://h/api")("GET", "http://h/api") == "GET /"
    # a literal path wins over a template listed before it
    m = OpMatcher(ops + [Operation("get", "/items/mine", False, False)], "")
    assert m("GET", "http://h/items/mine") == "GET /items/mine" and m("GET", "http://h/items/7") == "GET /items/{id}"


def test_template_regex_escapes_literal_parts():
    rx = testlog._template_regex("/a.b/{id}+x")
    assert rx.match("/a.b/7+x") and not rx.match("/aXb/7+x") and not rx.match("/a.b/7/8+x")
