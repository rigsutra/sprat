import base64
import json
import time

import httpx
import pytest

from sprat.auth import LoginConfig, LoginError, TokenProvider, get_path, jwt_claims, leaf_paths, literal_secrets

SAMPLE = {"success": True, "data": {"user": {"id": "u1"}, "accessToken": "", "expiresIn": 900}, "error": None}


def _jwt(exp):
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{b({'alg': 'none'})}.{b({'sub': 'u1', 'exp': exp})}.sig"


class FakeLogin:
    """Mock login server; issues JWTs that live `ttl` seconds."""

    def __init__(self, ttl=60, status=200):
        self.ttl, self.status, self.calls, self.bodies = ttl, status, 0, []

    def __call__(self, request: httpx.Request):
        self.calls += 1
        self.bodies.append(json.loads(request.content or b"{}"))
        if self.status != 200:
            return httpx.Response(self.status, json={"message": "Invalid email or password"})
        doc = json.loads(json.dumps(SAMPLE))
        doc["data"]["accessToken"] = _jwt(int(time.time()) + self.ttl)
        return httpx.Response(200, json=doc)


@pytest.fixture
def server(monkeypatch):
    srv = FakeLogin()
    import sprat.auth as auth_mod

    def fake_http(method, url, timeout, **kw):
        with httpx.Client(transport=httpx.MockTransport(srv)) as c:
            return c.request(method, url, **kw)
    monkeypatch.setattr(auth_mod, "_http", fake_http)
    monkeypatch.setenv("TEST_PW", "s3cret")
    return srv


def _cfg(**kw):
    return LoginConfig(**{"url": "http://auth.test/login", "body": '{"email": "a@b.c", "password": "${TEST_PW}"}',
                          "token_path": "data.accessToken", **kw})


def test_login_uses_env_password_and_jwt_expiry(server):
    p = TokenProvider(_cfg())
    h = p.headers()
    assert h["Authorization"].startswith("Bearer ey")
    assert server.bodies[0]["password"] == "s3cret"
    assert p.expiry_source == "JWT exp claim" and 55 < p.expires_at - time.time() <= 60


def test_refreshes_30s_before_expiry(server, monkeypatch):
    now = [1_000_000.0]
    monkeypatch.setattr(time, "time", lambda: now[0])  # the fake login server reads the same clock
    server.ttl = 600
    p = TokenProvider(_cfg())
    p.headers()
    now[0] += 569.9
    p.headers()
    assert server.calls == 1
    now[0] += 0.1  # 30 s before the JWT's exp
    p.headers(); p.headers(); p.headers()  # one renewal, then the new token is reused
    assert server.calls == 2


def test_short_jwt_renewed_halfway(server, monkeypatch):
    now = [1_000_000.0]
    monkeypatch.setattr(time, "time", lambda: now[0])
    server.ttl = 20  # shorter than the 30 s margin: renewed after 10 s, not on every request
    p = TokenProvider(_cfg())
    p.headers(); p.headers()
    now[0] += 9.9
    p.headers()
    assert server.calls == 1
    now[0] += 0.1
    p.headers()
    assert server.calls == 2


def test_token_types_and_expiry_modes(server):
    assert TokenProvider(_cfg(token_type="header", header_name="X-API-Key")).headers().keys() == {"X-API-Key"}
    assert TokenProvider(_cfg(token_type="cookie", cookie_name="sid")).headers()["Cookie"].startswith("sid=ey")
    p = TokenProvider(_cfg(expiry="field", expiry_path="data.expiresIn"))
    p.headers()
    assert p.expiry_source == "response field `data.expiresIn`" and 890 < p.expires_at - time.time() <= 900
    p = TokenProvider(_cfg(expiry="fixed", fixed_minutes=5))
    p.headers()
    assert p.expiry_source == "fixed 5 min"


def test_clear_errors(server, monkeypatch):
    server.status = 401
    with pytest.raises(LoginError, match="HTTP 401: Invalid email or password"):
        TokenProvider(_cfg()).headers()
    server.status = 200
    with pytest.raises(LoginError, match="no `data.token`"):
        TokenProvider(_cfg(token_path="data.token")).headers()
    monkeypatch.delenv("TEST_PW")
    with pytest.raises(LoginError, match="TEST_PW has no value"):
        TokenProvider(_cfg()).headers()


def test_literal_passwords_are_refused_but_env_refs_are_fine():
    assert literal_secrets(_cfg()) == []
    bad = LoginConfig(url="x", body='{"email": "a", "password": "hunter2", "nested": {"apiKey": "k"}}',
                      headers={"Authorization": "Basic abc"})
    assert set(literal_secrets(bad)) == {"body field `password`", "body field `nested.apiKey`", "header `Authorization`"}


def test_path_helpers():
    doc = {"data": {"items": [{"token": "t"}]}, "ok": True}
    assert get_path(doc, "data.items[0].token") == "t"
    assert ("data.items[0].token", "t") in leaf_paths(doc)
    assert jwt_claims(_jwt(123))["exp"] == 123 and jwt_claims("not-a-jwt") is None
