"""Automatic login (sprat.auth): request building, token extraction, expiry, refresh, errors."""
import base64
import json
import re
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from urllib.parse import parse_qs

import httpx
import pytest

import sprat.auth as auth
import sprat.discover as discover
from sprat.auth import (DEFAULT_LIFETIME, LoginConfig, LoginError, TokenProvider, _to_epoch, current_headers,
                          get_path, has_user, jwt_claims, leaf_paths, literal_secrets, make_providers)

PW = "s3cret-Pa55"
CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


def _b64(d):
    raw = d if isinstance(d, bytes) else json.dumps(d).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _jwt(exp=None, **claims):
    if exp is not None:
        claims["exp"] = exp
    return f"{_b64({'alg': 'none'})}.{_b64({'sub': 'u1', **claims})}.sig"


class Server:
    """Programmable login endpoint. `respond(request)` returns an httpx.Response."""

    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.respond = lambda r: httpx.Response(200, json={"accessToken": _jwt(int(time.time()) + 600)})
        self.lock = threading.Lock()

    def __call__(self, request):
        with self.lock:
            self.requests.append(request)
        return self.respond(request)

    @property
    def calls(self):
        return len(self.requests)


@pytest.fixture
def srv(monkeypatch):
    """Route the real auth._http -> discover.client_for -> httpx.Client through a MockTransport."""
    s = Server()
    real = httpx.Client
    seen = {}

    def fake_client(*a, **kw):
        seen.update(kw)
        kw["transport"] = httpx.MockTransport(s)
        return real(*a, **kw)
    monkeypatch.setattr(httpx, "Client", fake_client)
    monkeypatch.setattr(discover, "ssl_context", lambda: CTX)
    monkeypatch.setenv("TEST_PW", PW)
    s.client_kw = seen
    return s


def _cfg(**kw):
    return LoginConfig(**{"url": "http://auth.test/login", "body": '{"email": "a@b.c", "password": "${TEST_PW}"}', **kw})


# ---------- request building ----------

def test_json_post_body_and_client_options(srv):
    p = TokenProvider(_cfg(timeout=7.5))
    p.headers()
    [r] = srv.requests
    assert r.method == "POST" and str(r.url) == "http://auth.test/login"
    assert json.loads(r.content) == {"email": "a@b.c", "password": PW}
    assert r.headers["content-type"] == "application/json"
    # redirects are followed by hand (same host only), so the password can't be sent elsewhere
    assert srv.client_kw["follow_redirects"] is False and srv.client_kw["verify"] is CTX
    assert srv.client_kw["timeout"] == 7.5


def test_json_body_keys_nested_lists_and_non_strings_are_expanded(srv, monkeypatch):
    monkeypatch.setenv("KEYNAME", "pass")
    body = json.dumps({"${KEYNAME}": "${TEST_PW}", "list": ["${TEST_PW}", 1, None, True], "n": {"x": "${TEST_PW}"}})
    TokenProvider(_cfg(body=body)).headers()
    assert json.loads(srv.requests[0].content) == {"pass": PW, "list": [PW, 1, None, True], "n": {"x": PW}}


def test_json_body_password_with_json_metacharacters(srv):
    tricky = 'q"uo\\te\n{}'
    TokenProvider(_cfg(), variables={"TEST_PW": tricky}).headers()
    assert json.loads(srv.requests[0].content)["password"] == tricky


def test_form_body_sets_content_type_and_expands(srv):
    TokenProvider(_cfg(body="username=qa&password=${TEST_PW}", body_type="form")).headers()
    r = srv.requests[0]
    assert r.headers["content-type"] == "application/x-www-form-urlencoded"
    assert r.content == f"username=qa&password={PW}".encode()


def test_form_body_user_content_type_wins(srv):
    TokenProvider(_cfg(body="a=b", body_type="form", headers={"Content-Type": "text/x-custom"})).headers()
    assert srv.requests[0].headers["content-type"] == "text/x-custom"


def test_form_body_values_are_url_encoded(srv):
    tricky = "a&b=c+d%20"
    TokenProvider(_cfg(body="username=qa&password=${TEST_PW}", body_type="form"),
                  variables={"TEST_PW": tricky}).headers()
    assert parse_qs(srv.requests[0].content.decode())["password"] == [tricky]


def test_raw_body_sent_verbatim(srv):
    TokenProvider(_cfg(body="<login pw='${TEST_PW}'/>", body_type="raw",
                       headers={"Content-Type": "application/xml"})).headers()
    r = srv.requests[0]
    assert r.content == f"<login pw='{PW}'/>".encode() and r.headers["content-type"] == "application/xml"


def test_get_without_body_with_expanded_url_and_headers(srv, monkeypatch):
    monkeypatch.setenv("TENANT", "acme")
    monkeypatch.setenv("APIKEY", "k-123")
    TokenProvider(_cfg(method="get", body="", url="http://auth.test/${TENANT}/token?key=${APIKEY}",
                       headers={"X-Tenant": "${TENANT}", "X-Both": "${TENANT}:${APIKEY}", "Accept": "application/json"})
                  ).headers()
    r = srv.requests[0]
    assert r.method == "GET" and r.content == b""
    assert str(r.url) == "http://auth.test/acme/token?key=k-123"
    assert r.headers["x-tenant"] == "acme" and r.headers["x-both"] == "acme:k-123"
    assert r.headers["accept"] == "application/json"


@pytest.mark.parametrize("method", ["PUT", "patch", "Post"])
def test_method_is_uppercased(srv, method):
    TokenProvider(_cfg(method=method)).headers()
    assert srv.requests[0].method == method.upper()


def test_project_variables_win_over_environment(srv, monkeypatch):
    monkeypatch.setenv("TEST_PW", "from-env")
    TokenProvider(_cfg(), variables={"TEST_PW": "from-project"}).headers()
    assert json.loads(srv.requests[0].content)["password"] == "from-project"


def test_empty_variable_expands_to_empty_string(srv, monkeypatch):
    monkeypatch.setenv("TEST_PW", "")
    TokenProvider(_cfg()).headers()
    assert json.loads(srv.requests[0].content)["password"] == ""
    TokenProvider(_cfg(), variables={"TEST_PW": ""}).headers()
    assert json.loads(srv.requests[1].content)["password"] == ""


@pytest.mark.parametrize("where", ["url", "header", "json", "form", "raw"])
def test_missing_variable_is_a_login_error_naming_it(srv, monkeypatch, where):
    monkeypatch.delenv("NOPE_VAR_X", raising=False)
    kw = {"url": dict(url="http://auth.test/${NOPE_VAR_X}"),
          "header": dict(headers={"X": "${NOPE_VAR_X}"}),
          "json": dict(body='{"p": "${NOPE_VAR_X}"}'),
          "form": dict(body="p=${NOPE_VAR_X}", body_type="form"),
          "raw": dict(body="${NOPE_VAR_X}", body_type="raw")}[where]
    with pytest.raises(LoginError, match=r"^user B: NOPE_VAR_X has no value"):
        TokenProvider(_cfg(**kw), label="user B").headers()
    assert srv.calls == 0


def test_second_of_several_variables_missing(srv, monkeypatch):
    monkeypatch.delenv("MISSING_TWO", raising=False)
    with pytest.raises(LoginError, match="MISSING_TWO"):
        TokenProvider(_cfg(body='{"p": "${TEST_PW}${MISSING_TWO}"}')).headers()


def test_invalid_json_body(srv):
    with pytest.raises(LoginError, match="isn't valid JSON"):
        TokenProvider(_cfg(body="{not json")).headers()
    assert srv.calls == 0


def test_resolved_fills_secrets(monkeypatch):
    monkeypatch.setenv("TEST_PW", PW)
    d = TokenProvider(_cfg(headers={"X-K": "${TEST_PW}"}, url="http://h/${TEST_PW}")).resolved()
    assert d["url"] == f"http://h/{PW}" and d["headers"] == {"X-K": PW}
    assert json.loads(d["body"]) == {"email": "a@b.c", "password": PW}
    assert TokenProvider(_cfg(body="p=${TEST_PW}", body_type="form")).resolved()["body"] == f"p={PW}"
    assert TokenProvider(_cfg(body="${TEST_PW}", body_type="raw")).resolved()["body"] == PW
    assert TokenProvider(_cfg(body="")).resolved()["body"] == ""
    assert TokenProvider(_cfg()).resolved()["token_path"] == "accessToken"


# ---------- responses ----------

def test_redirect_is_followed(srv):
    def respond(r):
        if r.url.path == "/login":
            return httpx.Response(307, headers={"Location": "/v2/login"})
        return httpx.Response(200, json={"accessToken": "tok-" + "x" * 30, "seen": json.loads(r.content)})
    srv.respond = respond
    p = TokenProvider(_cfg())
    assert p.current_token().startswith("tok-")
    assert [r.url.path for r in srv.requests] == ["/login", "/v2/login"]
    assert srv.requests[1].method == "POST" and json.loads(srv.requests[1].content)["password"] == PW


def test_redirect_loop_is_a_login_error(srv):
    srv.respond = lambda r: httpx.Response(302, headers={"Location": "/login"})
    with pytest.raises(LoginError, match="couldn't reach the login API"):
        TokenProvider(_cfg()).headers()


def test_last_allowed_redirect_going_to_another_host_is_refused(srv):
    from sprat.auth import MAX_REDIRECTS

    def respond(r):
        n = int(r.url.path.rsplit("/", 1)[-1] or 0) if r.url.path != "/login" else 0
        if n < MAX_REDIRECTS:
            return httpx.Response(307, headers={"Location": f"/hop/{n + 1}"})
        return httpx.Response(307, headers={"Location": "http://evil.test/login"})
    srv.respond = respond
    with pytest.raises(LoginError, match="redirected to evil.test"):
        TokenProvider(_cfg()).headers()
    assert len(srv.requests) == MAX_REDIRECTS + 1 and all(r.url.host == "auth.test" for r in srv.requests)


@pytest.mark.parametrize("exc", [httpx.ConnectError("connection refused"), httpx.ReadTimeout("timed out"),
                                 httpx.ConnectTimeout("connect timeout"), httpx.RemoteProtocolError("bad")])
def test_transport_errors_become_login_errors(srv, exc):
    def respond(r):
        raise exc
    srv.respond = respond
    with pytest.raises(LoginError) as ei:
        TokenProvider(_cfg(), label="user A").headers()
    msg = str(ei.value)
    assert msg.startswith("user A: couldn't reach the login API (") and str(exc) in msg
    assert ei.value.__cause__ is None and ei.value.__suppress_context__


@pytest.mark.parametrize("status,body,said", [
    (401, {"message": "Invalid email or password"}, ": Invalid email or password"),
    (403, {"detail": "Account locked"}, ": Account locked"),
    (400, {"error": "invalid_grant"}, ": invalid_grant"),
    (422, {"title": "Validation failed"}, ": Validation failed"),
    (500, {"error": {"code": 1}}, ""),                 # not a string: nothing quoted
    (401, {"message": "x"}, ""),                       # too short to be useful
    (404, None, ""),
])
def test_http_error_statuses(srv, status, body, said):
    srv.respond = lambda r: httpx.Response(status, json=body) if body is not None else httpx.Response(status)
    with pytest.raises(LoginError) as ei:
        TokenProvider(_cfg()).headers()
    assert str(ei.value) == (f"user A: login failed with HTTP {status}{said}. "
                             "Check the login URL, the body and the credential environment variables.")


def test_html_error_page(srv):
    srv.respond = lambda r: httpx.Response(502, html="<html><body><h1>Bad Gateway</h1></body></html>")
    with pytest.raises(LoginError, match=r"HTTP 502\. Check"):
        TokenProvider(_cfg()).headers()


@pytest.mark.parametrize("status", [200, 201, 204, 299])
def test_any_2xx_is_success_but_needs_json(srv, status):
    srv.respond = lambda r: httpx.Response(status, json={"accessToken": "t" * 25})
    if status == 204:  # 204 can't carry a body
        srv.respond = lambda r: httpx.Response(204)
        with pytest.raises(LoginError, match="didn't return JSON"):
            TokenProvider(_cfg()).headers()
    else:
        assert TokenProvider(_cfg()).current_token() == "t" * 25


@pytest.mark.parametrize("resp", [
    httpx.Response(200, html="<html>Welcome! Please log in</html>"),
    httpx.Response(200, text="OK"),
    httpx.Response(200, text=""),
    httpx.Response(200, text="{broken"),
])
def test_non_json_success(srv, resp):
    srv.respond = lambda r: resp
    with pytest.raises(LoginError, match="the login API didn't return JSON"):
        TokenProvider(_cfg()).headers()


@pytest.mark.parametrize("doc,path", [
    ({"data": {"accessToken": "x"}}, "accessToken"),
    ({"data": [{"token": "x"}]}, "data[1].token"),       # index out of range
    ({"data": {"0": "x"}}, "data[0]"),                    # index on a dict
    ({"data": ["x"]}, "data.0"),                          # key on a list
    ({"data": None}, "data.token"),
    ({"data": 5}, "data[0]"),
    ([{"token": "x"}], "token"),                          # top level is an array
    ({"a.b": "x"}, "a.b"),                                # dotted keys can't be addressed
    ({"data": ["x"]}, "data[-1]"),
])
def test_token_path_misses(srv, doc, path):
    srv.respond = lambda r: httpx.Response(200, json=doc)
    with pytest.raises(LoginError, match=re.escape(f"logged in, but there's no `{path}` in the response")) as ei:
        TokenProvider(_cfg(token_path=path)).headers()
    assert "Fields that look like tokens: none." in str(ei.value)


def test_token_path_miss_suggests_long_string_fields(srv):
    srv.respond = lambda r: httpx.Response(200, json={"data": {"jwt": "e" * 40, "short": "abc", "n": 12345678901234567890123,
                                                               "items": [{"refresh": "r" * 21}]}})
    with pytest.raises(LoginError) as ei:
        TokenProvider(_cfg(token_path="data.accessToken")).headers()
    assert str(ei.value).endswith("Fields that look like tokens: data.jwt, data.items[0].refresh.")


@pytest.mark.parametrize("doc,path,token", [
    ({"data": {"items": [{"t": "tok"}]}}, "data.items[0].t", "tok"),
    ([{"token": "first"}, {"token": "second"}], "[1].token", "second"),
    ({"data": {"0": "zero"}}, "data.0", "zero"),
    ({"a": {"b": {"c": {"d": "deep"}}}}, "a.b.c.d", "deep"),
    ({"accessToken": "plain"}, "  accessToken  ", "plain"),
    ({"m": [[0, "nested"]]}, "m[0][1]", "nested"),
])
def test_token_path_hits(srv, doc, path, token):
    srv.respond = lambda r: httpx.Response(200, json=doc)
    assert TokenProvider(_cfg(token_path=path)).current_token() == token


@pytest.mark.parametrize("value", ["", 123, None, True, {"a": 1}, ["x"]])
def test_token_empty_or_not_text(srv, value):
    srv.respond = lambda r: httpx.Response(200, json={"accessToken": value})
    with pytest.raises(LoginError, match="`accessToken` in the login response is empty or not text"):
        TokenProvider(_cfg()).headers()


def test_password_never_in_error_messages(srv):
    cases = [
        lambda r: httpx.Response(401, json={"message": "Invalid credentials"}),
        lambda r: httpx.Response(500, text="<html>Internal error</html>"),
        lambda r: httpx.Response(200, text="not json"),
        lambda r: httpx.Response(200, json={"other": "x" * 30}),
        lambda r: httpx.Response(200, json={"accessToken": None}),
    ]

    def boom(r):
        raise httpx.ConnectError("refused")
    for respond in cases + [boom]:
        srv.respond = respond
        with pytest.raises(LoginError) as ei:
            TokenProvider(_cfg()).headers()
        assert PW not in str(ei.value) and PW not in repr(ei.value)


# ---------- token types ----------

@pytest.mark.parametrize("kw,expected", [
    ({}, {"Authorization": "Bearer TOK"}),
    ({"token_type": "header", "header_name": "X-API-Key"}, {"X-API-Key": "TOK"}),
    ({"token_type": "header", "header_name": ""}, {"Authorization": "TOK"}),
    ({"token_type": "header"}, {"Authorization": "TOK"}),
    ({"token_type": "cookie", "cookie_name": "sid"}, {"Cookie": "sid=TOK"}),
    ({"token_type": "cookie"}, {"Cookie": "token=TOK"}),
])
def test_token_types(srv, kw, expected):
    srv.respond = lambda r: httpx.Response(200, json={"accessToken": "TOK"})
    assert TokenProvider(_cfg(**kw)).headers() == expected


def test_unknown_token_type(srv):
    with pytest.raises(LoginError, match="Unknown token type 'basic'"):
        TokenProvider(_cfg(token_type="basic")).headers()


# ---------- expiry ----------

def _respond_with(srv, doc):
    srv.respond = lambda r: httpx.Response(200, json=doc)


def test_jwt_exp_claim(srv):
    exp = int(time.time()) + 1234
    _respond_with(srv, {"accessToken": _jwt(exp)})
    p = TokenProvider(_cfg())
    p.headers()
    assert p.expires_at == exp and p.expiry_source == "JWT exp claim"


@pytest.mark.parametrize("token", [_jwt(None), _jwt("1700000000"), "opaque-token-value", "a.b", "a.!!!.c",
                                   f"x.{_b64(b'not json')}.y", f"x.{_b64(bytes([0xff, 0xfe]))}.y"])
def test_jwt_without_usable_exp_falls_back_to_default(srv, token):
    _respond_with(srv, {"accessToken": token})
    p = TokenProvider(_cfg())
    before = time.time()
    p.headers()
    assert before + DEFAULT_LIFETIME <= p.expires_at <= time.time() + DEFAULT_LIFETIME
    assert p.expiry_source == "unknown (assumed 10 min)"


@pytest.mark.parametrize("payload", [[1, 2], 12345, "str"])
def test_three_part_token_with_non_object_payload(srv, payload):
    _respond_with(srv, {"accessToken": f"x.{_b64(payload)}.y"})
    p = TokenProvider(_cfg())
    p.headers()
    assert p.expiry_source.startswith("unknown")


def test_field_expiry_seconds_from_now(srv):
    _respond_with(srv, {"accessToken": _jwt(1), "data": {"expiresIn": 900}})
    p = TokenProvider(_cfg(expiry="field", expiry_path="data.expiresIn"))
    p.headers()
    assert 895 < p.expires_at - time.time() <= 900 and p.expiry_source == "response field `data.expiresIn`"


@pytest.mark.parametrize("value", [
    lambda now: int(now) + 5000,                  # epoch seconds
    lambda now: (int(now) + 5000) * 1000,         # epoch milliseconds
    lambda now: str(int(now) + 5000),             # epoch seconds as a string
    lambda now: datetime.fromtimestamp(int(now) + 5000, timezone.utc).isoformat().replace("+00:00", "Z"),
    lambda now: datetime.fromtimestamp(int(now) + 5000, timezone.utc).isoformat(),
    lambda now: datetime.fromtimestamp(int(now) + 5000, timezone(timedelta(hours=5, minutes=30))).isoformat(),
    lambda now: " 5000 ",                         # seconds from now, as text
])
def test_field_expiry_formats(srv, value):
    now = time.time()
    _respond_with(srv, {"accessToken": "t", "exp": value(now)})
    p = TokenProvider(_cfg(expiry="field", expiry_path="exp"))
    p.headers()
    assert abs(p.expires_at - (now + 5000)) < 3


@pytest.mark.parametrize("doc", [{"accessToken": _jwt(2_000_000_000)},
                                 {"accessToken": _jwt(2_000_000_000), "exp": "next tuesday"},
                                 {"accessToken": _jwt(2_000_000_000), "exp": None},
                                 {"accessToken": _jwt(2_000_000_000), "exp": True},
                                 {"accessToken": _jwt(2_000_000_000), "exp": [1]},
                                 {"accessToken": _jwt(2_000_000_000), "exp": "12.5"}])
def test_field_expiry_unusable_falls_back_to_jwt(srv, doc):
    _respond_with(srv, doc)
    p = TokenProvider(_cfg(expiry="field", expiry_path="exp"))
    p.headers()
    assert p.expires_at == 2_000_000_000 and p.expiry_source == "JWT exp claim"


def test_field_expiry_without_path_uses_jwt(srv):
    _respond_with(srv, {"accessToken": _jwt(2_000_000_000)})
    p = TokenProvider(_cfg(expiry="field", expiry_path=""))
    p.headers()
    assert p.expiry_source == "JWT exp claim"


@pytest.mark.parametrize("minutes,secs", [(5, 300), (60, 3600), (0, 60), (-3, 60)])
def test_fixed_expiry(srv, minutes, secs):
    _respond_with(srv, {"accessToken": _jwt(1)})  # the JWT exp is ignored in fixed mode
    p = TokenProvider(_cfg(expiry="fixed", fixed_minutes=minutes))
    before = time.time()
    p.headers()
    assert before + secs <= p.expires_at <= time.time() + secs and p.expiry_source == f"fixed {minutes} min"


def test_to_epoch_direct():
    now = 1_000_000.0
    assert _to_epoch(60, now) == now + 60
    assert _to_epoch(1.5, now) == now + 1.5
    assert _to_epoch(1_700_000_000, now) == 1_700_000_000.0
    assert _to_epoch(1_700_000_000_123, now) == pytest.approx(1_700_000_000.123)
    assert _to_epoch("2030-01-01T00:00:00Z", now) == datetime(2030, 1, 1, tzinfo=timezone.utc).timestamp()
    for bad in (True, False, None, "soon", "", [], {}):
        assert _to_epoch(bad, now) is None


def test_short_lived_token_renewed_halfway_not_on_every_request(srv, monkeypatch):
    now = [1_000_000.0]
    monkeypatch.setattr(auth.time, "time", lambda: now[0])
    _respond_with(srv, {"accessToken": "t", "expiresIn": 10})  # shorter than the 30 s margin
    p = TokenProvider(_cfg(expiry="field", expiry_path="expiresIn"))
    for _ in range(3):
        p.headers()
    assert srv.calls == 1 and p.renew_at == now[0] + 5
    now[0] += 4.9
    p.headers()
    assert srv.calls == 1
    now[0] += 0.1  # halfway through the token's life
    p.headers()
    assert srv.calls == 2 and p.renew_at == now[0] + 5


def test_already_expired_jwt_logs_in_every_time(srv):
    _respond_with(srv, {"accessToken": _jwt(int(time.time()) - 100)})
    p = TokenProvider(_cfg())
    p.headers(); p.headers()
    assert srv.calls == 2


@pytest.mark.parametrize("margin, renew_after", [(0, 100), (10, 90), (30, 70), (80, 50), (200, 50)])
def test_custom_margin_capped_at_half_the_lifetime(srv, monkeypatch, margin, renew_after):
    now = [1_000_000.0]
    monkeypatch.setattr(auth.time, "time", lambda: now[0])
    _respond_with(srv, {"accessToken": "t", "expiresIn": 100})
    p = TokenProvider(_cfg(expiry="field", expiry_path="expiresIn"), margin=margin)
    p.headers()
    now[0] += renew_after - 0.5
    p.headers()
    assert srv.calls == 1
    now[0] += 0.5
    p.headers()
    assert srv.calls == 2


def test_refresh_when_clock_passes_margin(srv, monkeypatch):
    now = [1_000_000.0]
    monkeypatch.setattr(auth.time, "time", lambda: now[0])
    _respond_with(srv, {"accessToken": "t", "expiresIn": 100})
    p = TokenProvider(_cfg(expiry="field", expiry_path="expiresIn"))
    p.headers()
    now[0] += 69
    p.headers()
    assert srv.calls == 1
    now[0] += 1  # exactly 30 s before expiry
    p.headers()
    assert srv.calls == 2 and p.expires_at == now[0] + 100


def test_ensure_valid_for(srv, monkeypatch):
    now = [1_000_000.0]
    monkeypatch.setattr(auth.time, "time", lambda: now[0])
    _respond_with(srv, {"accessToken": "t", "expiresIn": 600})
    p = TokenProvider(_cfg(expiry="field", expiry_path="expiresIn"))
    p.ensure_valid_for(60)  # no token yet
    assert srv.calls == 1
    p.ensure_valid_for(599)
    assert srv.calls == 1
    p.ensure_valid_for(601)
    assert srv.calls == 2


# ---------- state, callbacks, threads ----------

def test_status_and_login_count(srv):
    p = TokenProvider(_cfg(), label="user B")
    assert p.status() == {"label": "user B", "logged_in": False, "expires_at": 0.0, "expiry_source": "", "logins": 0}
    p.headers(); p.headers()
    s = p.status()
    assert s["logged_in"] and s["logins"] == 1 and s["expiry_source"] == "JWT exp claim"


def test_on_login_callback_and_failures_are_swallowed(srv):
    seen = []
    p = TokenProvider(_cfg())
    p.on_login = lambda prov: seen.append(prov.token)
    p.headers()
    assert seen == [p.token]
    p2 = TokenProvider(_cfg())
    p2.on_login = lambda prov: 1 / 0
    assert p2.headers()["Authorization"].startswith("Bearer ")


def test_failed_login_keeps_previous_state(srv, monkeypatch):
    now = [1_000_000.0]
    monkeypatch.setattr(auth.time, "time", lambda: now[0])
    _respond_with(srv, {"accessToken": "first", "expiresIn": 100})
    p = TokenProvider(_cfg(expiry="field", expiry_path="expiresIn"))
    p.headers()
    srv.respond = lambda r: httpx.Response(401, json={"message": "nope nope"})
    now[0] += 80
    with pytest.raises(LoginError):
        p.headers()
    assert p.token == "first" and p.logins == 1
    _respond_with(srv, {"accessToken": "second", "expiresIn": 100})
    assert p.current_token() == "second" and p.logins == 2


def test_concurrent_headers_log_in_exactly_once(srv):
    def slow(r):
        time.sleep(0.05)
        return httpx.Response(200, json={"accessToken": _jwt(int(time.time()) + 600)})
    srv.respond = slow
    p = TokenProvider(_cfg())
    n = 16
    barrier = threading.Barrier(n)
    out, errors = [], []

    def worker():
        try:
            barrier.wait()
            out.append(p.headers())
        except Exception as e:  # pragma: no cover - reported below
            errors.append(e)
    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert not errors and len(out) == n
    assert srv.calls == 1 and p.logins == 1
    assert len({h["Authorization"] for h in out}) == 1


def test_concurrent_refresh_after_expiry_logs_in_once(srv, monkeypatch):
    now = [1_000_000.0]
    monkeypatch.setattr(auth.time, "time", lambda: now[0])
    _respond_with(srv, {"accessToken": "t", "expiresIn": 100})
    p = TokenProvider(_cfg(expiry="field", expiry_path="expiresIn"))
    p.headers()
    now[0] += 75
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        p.headers()
    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert srv.calls == 2


# ---------- users A/B and config helpers ----------

def _app_cfg(**kw):
    base = dict(headers={}, headers_b={}, login_a=None, login_b=None, auth_a=None, auth_b=None, variables={})
    return SimpleNamespace(**{**base, **kw})


def test_make_providers_for_users_a_and_b(srv):
    def respond(r):
        who = json.loads(r.content)["email"]
        return httpx.Response(200, json={"accessToken": f"token-for-{who}"})
    srv.respond = respond
    a = {"url": "http://auth.test/login", "body": '{"email": "alice", "password": "${PW_A}"}', "unknown_key": 1}
    b = {"url": "http://auth.test/login", "body": '{"email": "bob", "password": "${PW_B}"}'}
    cfg = _app_cfg(login_a=a, login_b=b, variables={"PW_A": "pa", "PW_B": "pb"})
    make_providers(cfg)
    assert cfg.auth_a.label == "user A" and cfg.auth_b.label == "user B"
    assert cfg.auth_a.token == "token-for-alice" and cfg.auth_b.token == "token-for-bob"
    assert [json.loads(r.content)["password"] for r in srv.requests] == ["pa", "pb"]
    make_providers(cfg)  # already logged in: no new requests
    assert srv.calls == 2
    assert current_headers(cfg, "a") == {"Authorization": "Bearer token-for-alice"}
    assert current_headers(cfg, "b") == {"Authorization": "Bearer token-for-bob"}


def test_make_providers_keeps_existing_and_skips_missing(srv):
    existing = TokenProvider(_cfg(), label="mine")
    cfg = _app_cfg(login_a={"url": "http://ignored"}, auth_a=existing)
    make_providers(cfg)
    assert cfg.auth_a is existing and existing.token and cfg.auth_b is None
    assert str(srv.requests[0].url) == "http://auth.test/login"
    make_providers(_app_cfg())
    assert srv.calls == 1


def test_make_providers_login_error_propagates(srv):
    srv.respond = lambda r: httpx.Response(401, json={"message": "bad password"})
    cfg = _app_cfg(login_b={"url": "http://auth.test/login"})
    with pytest.raises(LoginError, match=r"^user B: login failed with HTTP 401: bad password"):
        make_providers(cfg)


def test_make_providers_without_variables_attribute(srv):
    cfg = SimpleNamespace(login_a={"url": "http://auth.test/login", "body": '{"p": "${TEST_PW}"}'}, login_b=None,
                          auth_a=None, auth_b=None)
    make_providers(cfg)
    assert cfg.auth_a.variables == {}


def test_current_headers_merges_static_and_token(srv):
    _respond_with(srv, {"accessToken": "TOK"})
    cfg = _app_cfg(headers={"X-Static": "1", "Authorization": "Basic old"}, headers_b={"X-B": "2"})
    cfg.auth_a = TokenProvider(_cfg())
    assert current_headers(cfg) == {"X-Static": "1", "Authorization": "Bearer TOK"}
    assert current_headers(cfg, "b") == {"X-B": "2"}
    assert cfg.headers == {"X-Static": "1", "Authorization": "Basic old"}  # not mutated


@pytest.mark.parametrize("kw,a,b", [
    ({}, False, False),
    ({"headers": {"X": "1"}}, True, False),
    ({"headers_b": {"X": "1"}}, False, True),
    ({"login_a": {"url": "u"}}, True, False),
    ({"login_b": {"url": "u"}}, False, True),
    ({"auth_a": object(), "auth_b": object()}, True, True),
])
def test_has_user(kw, a, b):
    cfg = _app_cfg(**kw)
    assert has_user(cfg) is a and has_user(cfg, "a") is a and has_user(cfg, "b") is b


def test_login_config_dict_round_trip():
    c = LoginConfig.from_dict({"url": "http://x", "token_type": "cookie", "cookie_name": "sid", "nope": 1})
    assert c.token_type == "cookie" and c.method == "POST" and c.timeout == 20.0
    assert LoginConfig.from_dict(c.to_dict()) == c
    c.headers["X"] = "1"
    assert LoginConfig("http://y").headers == {}  # no shared mutable default


# ---------- literal secrets ----------

@pytest.mark.parametrize("key", ["password", "PASSWORD", "Passwd", "pwd", "userPwd", "client_secret", "SECRET",
                                 "token", "refreshToken", "apiKey", "api_key", "API-KEY", "apikey", "credential",
                                 "Credentials", "passphrase"])
def test_literal_secret_keys_in_any_case(key):
    assert literal_secrets(LoginConfig(url="x", body=json.dumps({key: "literal"}))) == [f"body field `{key}`"]


@pytest.mark.parametrize("key", ["email", "username", "user", "grant_type", "scope", "remember"])
def test_non_secret_keys_are_fine(key):
    assert literal_secrets(LoginConfig(url="x", body=json.dumps({key: "literal"}))) == []


@pytest.mark.parametrize("value", ["${PW}", "prefix-${PW}-suffix", "${A}${B}", "", 1234, None, True])
def test_env_refs_empty_and_non_strings_are_fine(value):
    assert literal_secrets(LoginConfig(url="x", body=json.dumps({"password": value}))) == []


def test_literal_secrets_nested_and_arrays():
    body = {"auth": {"creds": [{"password": "x"}, {"password": "${OK}"}, [{"apiKey": "k"}]]},
            "list": ["password", "secret"], "deep": {"a": {"b": {"token": "t"}}}}
    assert literal_secrets(LoginConfig(url="x", body=json.dumps(body))) == [
        "body field `auth.creds[0].password`", "body field `auth.creds[2][0].apiKey`", "body field `deep.a.b.token`"]


@pytest.mark.parametrize("body,expected", [
    ("username=qa&password=hunter2", ["form field `password`"]),
    ("username=qa&password=${PW}", []),
    ("password=", []),
    ("a=1&client_secret=s&user_pwd=p", ["form field `client_secret`", "form field `user_pwd`"]),
    ("PassWord=x", ["form field `PassWord`"]),
    ("username=password", []),  # the value, not the name
])
def test_literal_secrets_form(body, expected):
    assert literal_secrets(LoginConfig(url="x", body=body, body_type="form")) == expected


def test_literal_secrets_form_token_and_api_key():
    found = literal_secrets(LoginConfig(url="x", body="refresh_token=abc&api_key=k", body_type="form"))
    assert found == ["form field `refresh_token`", "form field `api_key`"]


def test_literal_secrets_raw_and_invalid_json_bodies_use_form_rules():
    assert literal_secrets(LoginConfig(url="x", body="password=hunter2", body_type="raw")) == ["form field `password`"]
    assert literal_secrets(LoginConfig(url="x", body='{"password": "x"')) == []  # unparsable: not a form either
    assert literal_secrets(LoginConfig(url="x", body="   ")) == []
    assert literal_secrets(LoginConfig(url="x", body="{}")) == []


def test_literal_secrets_json_body_with_form_type_checks_both():
    cfg = LoginConfig(url="x", body='{"password": "a"}', body_type="form")
    assert literal_secrets(cfg) == ["body field `password`"]


@pytest.mark.parametrize("headers,expected", [
    ({"Authorization": "Basic abc"}, ["header `Authorization`"]),
    ({"authorization": "Bearer ${TOKEN}"}, []),
    ({"AUTHORIZATION": ""}, []),
    ({"X-Api-Key": "k"}, ["header `X-Api-Key`"]),
    ({"X-Auth-Token": "t", "Accept": "application/json"}, ["header `X-Auth-Token`"]),
    ({"X-Client-Secret": "${S}"}, []),
    ({"Accept": "application/json", "X-Tenant": "acme"}, []),
])
def test_literal_secrets_headers(headers, expected):
    assert literal_secrets(LoginConfig(url="x", body="", headers=headers)) == expected


def test_literal_secrets_reports_body_and_headers_together():
    cfg = LoginConfig(url="x", body='{"password": "p"}', headers={"X-Token": "t"})
    assert literal_secrets(cfg) == ["body field `password`", "header `X-Token`"]


# ---------- path helpers ----------

def test_get_path_raises_for_callers():
    with pytest.raises(KeyError):
        get_path({"a": 1}, "b")
    with pytest.raises(IndexError):
        get_path({"a": []}, "a[0]")
    with pytest.raises(TypeError):
        get_path({"a": None}, "a[0]")
    assert get_path({"a": 1}, "") == {"a": 1}


def test_leaf_paths_shapes():
    assert leaf_paths({}) == [] and leaf_paths([]) == []
    assert leaf_paths("x") == [("", "x")]
    assert leaf_paths({"a": [1, {"b": None}], "c": {"d": True}}) == [("a[0]", 1), ("a[1].b", None), ("c.d", True)]
    assert len(leaf_paths({"l": list(range(50))})) == 20  # long arrays are capped


def test_jwt_claims_variants():
    assert jwt_claims(_jwt(5, role="admin")) == {"sub": "u1", "role": "admin", "exp": 5}
    padded = f"h.{base64.urlsafe_b64encode(json.dumps({'exp': 1}).encode()).decode()}.s"
    assert jwt_claims(padded) == {"exp": 1}
    for bad in ("", "a", "a.b", "a.b.c.d", "a.%%%.c", "a..c"):
        assert jwt_claims(bad) is None
