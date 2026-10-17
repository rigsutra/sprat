import json

import pytest

from sprat.config import expand_env
from sprat.secretstore import SecretStore


def test_values_are_encrypted_on_disk_and_never_listed(tmp_path, monkeypatch):
    monkeypatch.delenv("SPRAT_SECRET_KEY", raising=False)
    s = SecretStore(tmp_path)
    s.set("ntt", "NTT_PASSWORD", 'p@ss"w\\ord')
    raw = (tmp_path / "secrets.json").read_text()
    assert "p@ss" not in raw and (tmp_path / ".secret.key").is_file()
    assert [n["name"] for n in s.names("ntt")] == ["NTT_PASSWORD"] and "value" not in s.names("ntt")[0]
    assert SecretStore(tmp_path).values("ntt") == {"NTT_PASSWORD": 'p@ss"w\\ord'}  # survives a restart
    assert s.values("other") == {}
    s.delete("ntt", "NTT_PASSWORD")
    assert s.values("ntt") == {}


def test_env_key_and_wrong_key(tmp_path, monkeypatch):
    monkeypatch.setenv("SPRAT_SECRET_KEY", "a long passphrase for the server")
    SecretStore(tmp_path).set("p", "K", "v")
    assert not (tmp_path / ".secret.key").exists()
    monkeypatch.setenv("SPRAT_SECRET_KEY", "a different passphrase")
    with pytest.raises(ValueError, match="encryption key changed"):
        SecretStore(tmp_path).values("p")


def test_drop_project_and_names(tmp_path):
    s = SecretStore(tmp_path)
    s.set("a", "X", "1")
    s.set("b", "Y", "2")
    s.drop_project("a")
    assert s.values("a") == {} and s.values("b") == {"Y": "2"}
    for bad in ("", "1X", "has-dash", "a b"):
        with pytest.raises(ValueError):
            s.set("a", bad, "v")


def test_expand_prefers_project_secret_then_environment(monkeypatch):
    monkeypatch.setenv("FROM_ENV", "env-value")
    assert expand_env("${PW}:${FROM_ENV}", {"PW": "secret"}) == "secret:env-value"
    with pytest.raises(ValueError, match="Secrets"):
        expand_env("${MISSING_ONE}", {})


def test_json_body_password_with_quotes_stays_valid(monkeypatch):
    from sprat.auth import LoginConfig, TokenProvider
    p = TokenProvider(LoginConfig(url="http://x/login", body='{"email": "a", "password": "${PW}"}'),
                      variables={"PW": 'he said "hi" \\o/'})
    assert json.loads(p.resolved()["body"])["password"] == 'he said "hi" \\o/'


def test_web_secrets_flow(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from sprat.web import app as web
    import httpx
    spec = {"openapi": "3.0.1", "info": {"title": "t", "version": "1"}, "servers": [{"url": "http://s.test"}],
            "paths": {"/a": {"get": {"responses": {"200": {"description": "ok"}}}}}}
    real = httpx.Client

    def fake_client(*a, **kw):
        kw["transport"] = httpx.MockTransport(lambda r: httpx.Response(200, json=spec))
        return real(*a, **kw)
    monkeypatch.setattr(httpx, "Client", fake_client)
    web.configure(tmp_path)
    c = TestClient(web.app)
    login = {"url": "http://s.test/login", "body": '{"u": "x", "password": "${NTT_PASSWORD}"}', "token_path": "t"}
    pid = c.post("/api/projects", json={"name": "S", "spec": "http://s.test/openapi.json", "login_a": login,
                                         "secrets": {"NTT_PASSWORD": "hunter2"}}).json()["id"]
    p = c.get(f"/api/projects/{pid}").json()
    assert [s["name"] for s in p["secrets"]] == ["NTT_PASSWORD"] and "hunter2" not in json.dumps(p)
    v = c.get("/api/vars", params={"names": "NTT_PASSWORD,NOPE", "project": pid}).json()
    assert v[0]["source"] == "project" and v[1]["source"] is None
    assert c.put(f"/api/projects/{pid}/secrets/OTHER", json={"value": "x"}).json()["ok"]
    assert "hunter2" not in c.get(f"/api/projects/{pid}/yaml").text
    for f in tmp_path.rglob("*"):
        if f.is_file():
            assert b"hunter2" not in f.read_bytes(), f
    c.delete(f"/api/projects/{pid}")
    assert web.store().values(pid) == {}
