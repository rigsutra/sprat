"""config.py: Config defaults, ${VAR} expansion, header parsing, YAML loading."""
import threading

import pytest
import yaml

from sprat.config import ALL_STAGES, Config, expand_env, load_config, parse_header


# ---------- Config ----------

def test_config_defaults():
    c = Config()
    assert c.spec == "" and c.base_url == "" and c.headers == {} and c.headers_b == {}
    assert c.stages == ALL_STAGES and c.max_examples == 50 and c.fail_on == "high"
    assert c.out_dir == "reports" and not c.no_mutating_authz and c.timeout == 15.0
    assert c.login_a is None and c.cancel is None and c.on_progress is None and c.testlog is None


def test_config_mutable_defaults_are_not_shared():
    a, b = Config(), Config()
    a.stages.append("x")
    a.headers["H"] = "v"
    a.operations.append("GET /")
    assert b.stages == ALL_STAGES and b.headers == {} and b.operations == []
    assert "x" not in ALL_STAGES


def test_runtime_fields_ignored_by_eq_and_secrets_not_in_repr():
    a = Config(variables={"PW": "hunter2"}, cancel=threading.Event(), on_progress=print)
    assert a == Config()
    assert "hunter2" not in repr(a) and "variables" not in repr(a)


# ---------- expand_env ----------

@pytest.mark.parametrize("value,expected", [
    ("", ""),
    ("plain", "plain"),
    ("${A}", "a-val"),
    ("Bearer ${A}", "Bearer a-val"),
    ("${A}${B}", "a-valb-val"),
    ("${A}:${A}", "a-val:a-val"),
    ("$A", "$A"),                  # only the braced form is expanded
    ("${}", "${}"),
    ("${A-B}", "${A-B}"),          # not a \w name
    ("${ A }", "${ A }"),
    ("$${A}", "$a-val"),
    ("{A}", "{A}"),
    ("${A", "${A"),
])
def test_expand_env_from_environment(monkeypatch, value, expected):
    monkeypatch.setenv("A", "a-val")
    monkeypatch.setenv("B", "b-val")
    assert expand_env(value) == expected


def test_expand_env_empty_env_value(monkeypatch):
    monkeypatch.setenv("EMPTY_VAR_X", "")
    assert expand_env("[${EMPTY_VAR_X}]") == "[]"


def test_expand_env_variables_win_over_environment(monkeypatch):
    monkeypatch.setenv("SAME", "env")
    assert expand_env("${SAME}", {"SAME": "proj"}) == "proj"
    assert expand_env("${SAME}", {}) == "env"
    assert expand_env("${SAME}", None) == "env"
    assert expand_env("${SAME}", {"OTHER": "x"}) == "env"


def test_expand_env_empty_variable_value_is_used(monkeypatch):
    monkeypatch.setenv("V", "env")
    assert expand_env("[${V}]", {"V": ""}) == "[]"


def test_expand_env_values_are_not_reexpanded_or_regex_processed(monkeypatch):
    monkeypatch.setenv("INNER", "nope")
    assert expand_env("${X}", {"X": "${INNER}"}) == "${INNER}"
    assert expand_env("${X}", {"X": r"a\1\g<0>\\b"}) == r"a\1\g<0>\\b"


def test_expand_env_missing_raises_with_name(monkeypatch):
    monkeypatch.delenv("SPRAT_SURELY_MISSING", raising=False)
    with pytest.raises(ValueError, match="SPRAT_SURELY_MISSING has no value"):
        expand_env("x ${SPRAT_SURELY_MISSING} y")
    with pytest.raises(ValueError, match="environment variable"):
        expand_env("${SPRAT_SURELY_MISSING}", {"OTHER": "1"})


# ---------- parse_header ----------

@pytest.mark.parametrize("raw,expected", [
    ("A: b", ("A", "b")),
    ("A:b", ("A", "b")),
    ("  A  :   b  ", ("A", "b")),
    ("A:\tb\t", ("A", "b")),
    ("Authorization: Bearer a:b:c", ("Authorization", "Bearer a:b:c")),
    ("X-Url: http://h:8080/p?q=1", ("X-Url", "http://h:8080/p?q=1")),
    ("Cookie: a=1; b=2", ("Cookie", "a=1; b=2")),
    ("X-Env: ${TOKEN}", ("X-Env", "${TOKEN}")),  # expansion is the caller's job
    ("A: b c  d", ("A", "b c  d")),
])
def test_parse_header_ok(raw, expected):
    assert parse_header(raw) == expected


@pytest.mark.parametrize("raw", ["", "A", "A b", "A:", ":", "Authorization"])
def test_parse_header_rejects_missing_value(raw):
    with pytest.raises(ValueError, match="Name: value"):
        parse_header(raw)


@pytest.mark.parametrize("raw", [": v", "   : v"])
def test_parse_header_rejects_empty_name(raw):
    with pytest.raises(ValueError):
        parse_header(raw)


def test_parse_header_rejects_whitespace_only_value():
    with pytest.raises(ValueError):
        parse_header("A:   ")


# ---------- load_config ----------

def _yaml(tmp_path, text, name="c.yaml"):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


@pytest.mark.parametrize("path", [None, ""])
def test_load_config_no_path_gives_defaults(path):
    assert load_config(path) == Config()


@pytest.mark.parametrize("text", ["", "# only a comment\n", "---\n", "null\n"])
def test_load_config_empty_file_gives_defaults(tmp_path, text):
    assert load_config(_yaml(tmp_path, text)) == Config()


def test_load_config_sets_every_plain_key(tmp_path, monkeypatch):
    monkeypatch.setenv("TOK_A", "aaa")
    monkeypatch.setenv("TOK_B", "bbb")
    cfg = load_config(_yaml(tmp_path, """
spec: http://x/openapi.json
base_url: http://x/api
headers: {Authorization: "Bearer ${TOK_A}", X-Num: 5}
headers_b: {Authorization: "Bearer ${TOK_B}"}
stages: [lint, authz]
max_examples: 7
fail_on: medium
out_dir: out
no_mutating_authz: true
exclude_paths: ["^/health"]
bola: [{method: GET, path: /a/1}]
timeout: 3.5
types_max_fields: 4
operations: ["GET /a"]
title: Naïve API
login_a: {url: "http://x/login", body: '{"p": "${PW}"}'}
zap_image: zap:latest
"""))
    assert cfg.spec == "http://x/openapi.json" and cfg.base_url == "http://x/api"
    assert cfg.headers == {"Authorization": "Bearer aaa", "X-Num": "5"}
    assert cfg.headers_b == {"Authorization": "Bearer bbb"}
    assert cfg.stages == ["lint", "authz"] and cfg.max_examples == 7 and cfg.fail_on == "medium"
    assert cfg.out_dir == "out" and cfg.no_mutating_authz is True and cfg.exclude_paths == ["^/health"]
    assert cfg.bola == [{"method": "GET", "path": "/a/1"}] and cfg.timeout == 3.5 and cfg.types_max_fields == 4
    assert cfg.operations == ["GET /a"] and cfg.title == "Naïve API" and cfg.zap_image == "zap:latest"
    assert cfg.login_a["body"] == '{"p": "${PW}"}'  # login secrets are resolved at login time, not here


@pytest.mark.parametrize("key", ["headers", "headers_b"])
def test_load_config_null_headers_become_empty(tmp_path, key):
    assert getattr(load_config(_yaml(tmp_path, f"{key}:\n")), key) == {}


def test_load_config_missing_env_in_headers_raises(tmp_path, monkeypatch):
    monkeypatch.delenv("SPRAT_NOPE_XYZ", raising=False)
    with pytest.raises(ValueError, match="SPRAT_NOPE_XYZ"):
        load_config(_yaml(tmp_path, "headers_b: {A: '${SPRAT_NOPE_XYZ}'}\n"))


@pytest.mark.parametrize("key", ["bogus", "Spec", "cancel", "on_progress", "testlog", "auth_a", "auth_b",
                                 "variables"])
def test_load_config_rejects_unknown_and_runtime_keys(tmp_path, key):
    with pytest.raises(ValueError, match=f"Unknown config key: {key}"):
        load_config(_yaml(tmp_path, f"{key}: 1\n"))


def test_load_config_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(str(tmp_path / "nope.yaml"))


def test_load_config_invalid_yaml(tmp_path):
    with pytest.raises(yaml.YAMLError):
        load_config(_yaml(tmp_path, "spec: [unclosed\n"))


@pytest.mark.parametrize("text", ["- a\n- b\n", "just a string\n", "42\n"])
def test_load_config_non_mapping_is_a_value_error(tmp_path, text):
    with pytest.raises(ValueError):
        load_config(_yaml(tmp_path, text))
