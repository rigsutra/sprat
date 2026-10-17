import json

from sprat.spec import load_spec
from sprat.stages.conformance import _split_checks

JUNIT_TEXT = """1. Test Case ID: Dh8wxe

- API accepts requests without authentication

    Expected 401 or 403, got `200 OK` for `GET /admin/stats`

- Undocumented HTTP status code

    Received: 404

2. Test Case ID: xJwM8f

- Undocumented HTTP status code

    Received: 401
"""


def test_split_checks_dedupes_and_ranks():
    fs = {f.title: f for f in _split_checks("GET /admin/stats", JUNIT_TEXT)}
    assert set(fs) == {"API accepts requests without authentication", "Undocumented HTTP status code"}
    assert fs["API accepts requests without authentication"].severity == "high"
    assert fs["Undocumented HTTP status code"].severity == "low"
    assert fs["Undocumented HTTP status code"].detail.startswith("2 failing case(s)")


def test_split_checks_unstructured_text_still_reported():
    [f] = _split_checks("GET /x", "something odd happened")
    assert f.title == "Check failed"


SWAGGER2 = {
    "swagger": "2.0",
    "host": "api.example.com",
    "basePath": "/v1",
    "schemes": ["https"],
    "securityDefinitions": {"Bearer": {"type": "apiKey", "name": "Authorization", "in": "header"}},
    "security": [{"Bearer": []}],
    "paths": {
        "/orders/{id}": {
            "parameters": [{"name": "id", "in": "path", "required": True, "type": "integer"}],
            "get": {"responses": {"200": {"description": "ok"}}},
            "put": {"parameters": [{"name": "body", "in": "body", "schema": {}}],
                    "responses": {"200": {"description": "ok"}}},
        },
        "/health": {"get": {"security": [], "responses": {"200": {"description": "ok"}}}},
    },
}


def test_swagger2_base_url_security_and_params(tmp_path):
    p = tmp_path / "swagger.json"
    p.write_text(json.dumps(SWAGGER2))
    spec = load_spec(str(p))
    assert spec.version == "swagger2"
    assert spec.base_url == "https://api.example.com/v1"
    ops = {o.label: o for o in spec.operations}
    assert ops["GET /orders/{id}"].secured and ops["GET /orders/{id}"].path_params == {"id": "1"}
    assert ops["PUT /orders/{id}"].has_body
    assert not ops["GET /health"].secured  # operation-level `security: []` overrides global


def test_openapi3_relative_server_and_optional_auth(tmp_path):
    doc = {
        "openapi": "3.0.1",
        "servers": [{"url": "/api"}],
        "components": {"parameters": {"Id": {"name": "id", "in": "path", "required": True,
                                             "schema": {"type": "string", "format": "uuid"}}}},
        "paths": {"/things/{id}": {"get": {"parameters": [{"$ref": "#/components/parameters/Id"}],
                                            "security": [{}, {"bearer": []}],
                                            "responses": {"200": {"description": "ok"}}}}},
    }
    p = tmp_path / "openapi.json"
    p.write_text(json.dumps(doc))
    spec = load_spec(str(p))
    [op] = spec.operations
    assert op.path_params == {"id": "00000000-0000-0000-0000-000000000001"}
    assert not op.secured  # `{}` alternative means auth is optional
    assert spec.base_url == ""  # relative server in a local file -> needs --base-url
