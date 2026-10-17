"""Plain-language explanations: every table entry, every branch, and the fallbacks."""
import pytest

from sprat import explain
from sprat.config import ALL_STAGES
from sprat.explain import (CHECKS, FINDING_TITLES, PHASES, STAGES, blocked_by_auth, describe_case, expected_for,
                             explain_check, finding_title, is_auth_probe, is_method_probe, permission_detail,
                             phase_label, server_said)

JARGON = ("_", "schemathesis", "coverage phase")


def test_every_pipeline_stage_has_a_plain_name():
    assert set(STAGES) == set(ALL_STAGES)


@pytest.mark.parametrize("table", [PHASES, STAGES])
def test_tables_are_name_and_description_without_jargon(table):
    for key, (name, desc) in table.items():
        assert name and desc.endswith(".") and len(desc) > 30, key
        assert not any(j in name.lower() for j in JARGON), key


@pytest.mark.parametrize("phase", list(PHASES))
def test_phase_label_known(phase):
    assert phase_label(phase) == PHASES[phase][0]


@pytest.mark.parametrize("phase,want", [("unknown", "Unknown"), ("", "Test"), (None, "Test")])
def test_phase_label_fallback(phase, want):
    assert phase_label(phase) == want


@pytest.mark.parametrize("name", list(CHECKS))
def test_every_check_has_a_sentence(name):
    text = explain_check(name, 418)
    assert text.endswith(".") and len(text) > 20 and "_" not in text and text[0].isupper()
    assert "418" not in text or "HTTP 418" in text


@pytest.mark.parametrize("name", [n for n in CHECKS if "HTTP" in CHECKS[n](999)])
def test_status_is_shown_and_none_becomes_question_mark(name):
    assert "999" in explain_check(name, 999)
    assert "HTTP ?" in explain_check(name, None)


def test_unknown_check_falls_back_to_failure_title_or_readable_name():
    assert explain_check("my_custom_check", 200) == "my custom check."
    assert explain_check("my_custom_check", 200, {"title": "Custom thing broke"}) == "Custom thing broke."
    assert explain_check("my_custom_check", 200, {"title": ""}) == "my custom check."


def test_server_error_hint_is_appended():
    msg = 'Response: {"detail": "NullPointerException in OrderService"}'
    t = explain_check("not_a_server_error", 500, {"message": msg})
    assert t.endswith("Server said: NullPointerException in OrderService")
    assert explain_check("not_a_server_error", 500, {"message": "no json here"}) == CHECKS["not_a_server_error"](500)
    assert explain_check("not_a_server_error", 500, {"message": None}) == CHECKS["not_a_server_error"](500)
    assert "Server said" not in explain_check("status_code_conformance", 500, {"message": msg})


@pytest.mark.parametrize("raw", list(FINDING_TITLES))
def test_finding_titles_are_rewritten(raw):
    assert finding_title(raw) == FINDING_TITLES[raw] != raw
    assert finding_title(f"  {raw}\n") == FINDING_TITLES[raw]


def test_unknown_finding_title_is_kept():
    assert finding_title("Something new") == "Something new"
    assert finding_title("  padded  ") == "  padded  "


@pytest.mark.parametrize("phase,mode,desc,want", [
    ("examples", "positive", "Positive test case", "Swagger examples: valid request"),
    ("fuzzing", "positive", "", "Random data: valid request"),
    ("fuzzing", "negative", "", "Random data: invalid request on purpose"),
    ("stateful", "", "", "Request chains: generated request"),
    ("fuzzing", "negative", "- Missing `id`", "Random data: invalid on purpose (Missing `id`)"),
    ("coverage", "negative", "- Missing `id`", "Edge cases: Missing `id`"),
    ("coverage", "positive", None, "Edge cases: valid request"),
    ("weird", "positive", "x", "Weird: x"),
])
def test_describe_case(phase, mode, desc, want):
    assert describe_case(phase, mode, desc) == want


@pytest.mark.parametrize("raw,want", [
    ("- a\n- b", "a; b"),
    ("  violates `maxLength` at /properties/user.name  ", "`user.name` breaks its `maxLength` rule"),
    ("value (was 1, became \"x\")", "value (changed 1 → \"x\")"),
    ("items[0].qty: Incorrect type", "`items[0].qty` has the wrong type"),
    ("Incorrect type somewhere", "has the wrong type somewhere"),
])
def test_clean_makes_descriptions_readable(raw, want):
    assert explain._clean(raw) == want


def test_probe_classifiers():
    assert is_method_probe("Unspecified HTTP method: TRACE")
    assert not is_method_probe(None) and not is_method_probe("x")
    for d in ("Missing Authorization", "odd X-API-Key", "api-key empty", "bad Cookie"):
        assert is_auth_probe(d), d
    assert not is_auth_probe(None) and not is_auth_probe("Missing `id`")


@pytest.mark.parametrize("mode,desc,start", [
    ("positive", "Unspecified HTTP method: PATCH", "405 Method Not Allowed: this API path doesn't define PATCH"),
    ("negative", "Unspecified HTTP method", "405 Method Not Allowed: this API path doesn't define this method"),
    ("negative", "Missing id", "The API should refuse it with a 4xx"),
    ("positive", "", "The API should accept it"),
    ("", "", "The API should accept it"),
])
def test_expected_for(mode, desc, start):
    assert expected_for(mode, desc).startswith(start)


@pytest.mark.parametrize("body,want", [
    (None, ""),
    ("", ""),
    ('{"required": ["read:a", "write:b"]}', "missing permission `read:a`, `write:b`"),
    ('{"requiredScopes": ["s1"]}', "missing permission `s1`"),
    ('{"required_scopes": ["s2"]}', "missing permission `s2`"),
    ('{"scopes": ["s3"]}', "missing permission `s3`"),
    ('{"required": [], "detail": "Forbidden here"}', "server said: Forbidden here"),
    ('{"required": "read:a", "message": "nope nope"}', "server said: nope nope"),
    ('["read:a"]', 'server said: ["read:a"]'),
    ("Access denied", "server said: Access denied"),
    ("  ", ""),
])
def test_permission_detail(body, want):
    assert permission_detail(body) == want


@pytest.mark.parametrize("status,mode,desc,creds,want", [
    (403, "positive", "Random data", True, "403 Forbidden before anything else, so the API's logic was never reached"),
    (401, "negative", "Missing id", True, "401 (login not accepted), so the invalid input was never checked"),
    (401, "positive", "x", False, ""),
    (200, "positive", "x", True, ""),
    (None, "positive", "x", True, ""),
    (401, "negative", "Missing `Authorization` at header", True, ""),
    (403, "positive", "Unspecified HTTP method: PUT", True, ""),
])
def test_blocked_by_auth(status, mode, desc, creds, want):
    got = blocked_by_auth(status, mode, desc, creds)
    assert (want in got and got.startswith("Not really tested")) if want else got == ""


@pytest.mark.parametrize("body,want", [
    (None, ""),
    ("", ""),
    ('{"detail": "Order not found"}', "Order not found"),
    ('{"message":"bad input"}', "bad input"),
    ('{"error": "x"}', '{"error": "x"}'),  # too short to be a message: raw body instead
    ('{"title": "Unprocessable Entity"}', "Unprocessable Entity"),
    ("  <html>" + "x" * 300, "<html>" + "x" * 154),
])
def test_server_said(body, want):
    assert server_said(body) == want
