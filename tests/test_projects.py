import json
import sys
import threading
import time

import pytest

from sprat.discover import from_ui_text, parse_spec
from sprat.models import Finding, StageResult
from sprat.proc import Cancelled, run_cmd
from sprat.runner import annotate
from sprat.spec import filter_operations, load_spec

DOC = {
    "openapi": "3.0.1", "info": {"title": "Shop", "version": "1"},
    "servers": [{"url": "https://shop.test/api"}],
    "components": {"schemas": {"X": {"type": "object"}}},
    "paths": {
        "/items": {"get": {"responses": {}}, "post": {"responses": {}}},
        "/items/{id}": {"get": {"responses": {}}, "delete": {"responses": {}}},
        "/health": {"get": {"responses": {}}},
    },
}


def _spec(tmp_path):
    f = tmp_path / "s.json"
    f.write_text(json.dumps(DOC))
    return load_spec(str(f))


def test_swagger_ui_express_inline_spec_is_extracted():
    js = 'window.onload = function() { var options = {"customOptions":{},"swaggerDoc": ' + json.dumps(DOC) + ', "x": 1};'
    doc, urls = from_ui_text("http://a/api-docs/", js)
    assert doc["info"]["title"] == "Shop" and urls == []


def test_swashbuckle_index_urls_are_found():
    html = '<script>var configObject = JSON.parse(\'{"urls":[{"url":"/swagger/v1/swagger.json","name":"V1"},{"url":"/swagger/v2/swagger.json","name":"V2"}]}\');</script>'
    doc, urls = from_ui_text("http://a/swagger/index.html", html)
    assert doc is None
    assert urls == ["http://a/swagger/v1/swagger.json", "http://a/swagger/v2/swagger.json"]


def test_swagger_initializer_url_is_found():
    js = 'window.ui = SwaggerUIBundle({ url: "https://petstore.swagger.io/v2/swagger.json", dom_id: "#swagger-ui" });'
    _, urls = from_ui_text("http://a/docs", js)
    assert urls == ["https://petstore.swagger.io/v2/swagger.json"]


def test_parse_spec_rejects_non_specs():
    assert parse_spec("<html></html>") is None
    assert parse_spec('{"hello": 1}') is None
    assert parse_spec(json.dumps(DOC))["info"]["title"] == "Shop"


def test_filter_operations_reduces_document(tmp_path):
    spec = _spec(tmp_path)
    sub = filter_operations(spec, ["GET /items/{id}", "post /items"])
    assert {o.label for o in sub.operations} == {"GET /items/{id}", "POST /items"}
    raw = json.loads(sub.text)
    assert set(raw["paths"]) == {"/items", "/items/{id}"}
    assert set(raw["paths"]["/items"]) == {"post"}
    assert "X" in raw["components"]["schemas"]
    assert sub.filtered and json.loads(sub.full_text)["paths"].keys() == DOC["paths"].keys()
    with pytest.raises(ValueError):
        filter_operations(spec, ["GET /nope"])


def test_annotate_maps_every_finding_style(tmp_path):
    spec = _spec(tmp_path)
    fs = [
        Finding("conformance", "high", "x", "GET /items/{id}"),
        Finding("authz", "critical", "x", "GET /items/{id} {'id': '1'}"),  # BOLA label
        Finding("lint", "low", "x", "paths//items/{id}/delete/responses"),
        Finding("zap", "medium", "x", "DELETE https://shop.test/api/items/42?x=1"),
        Finding("lint", "low", "x", "info"),
    ]
    annotate(spec, "https://shop.test/api", [StageResult("s", findings=fs)])
    assert [f.operation for f in fs] == ["GET /items/{id}", "GET /items/{id}", "DELETE /items/{id}",
                                         "DELETE /items/{id}", ""]


def test_exclude_paths_apply_to_every_stage(tmp_path, monkeypatch):
    from sprat.config import Config
    from sprat import runner
    f = tmp_path / "s.json"
    f.write_text(json.dumps(DOC))
    seen = {}

    def fake_stage(spec, cfg, out):
        seen["labels"] = sorted(o.label for o in spec.operations)
        seen["paths"] = sorted(json.loads(spec.text)["paths"])  # what ZAP/Schemathesis would get
        return StageResult("zap")

    monkeypatch.setitem(runner.STAGE_FUNCS, "zap", fake_stage)
    cfg = Config(spec=str(f), base_url="https://shop.test/api", stages=["zap"], out_dir=str(tmp_path / "o"),
                 exclude_paths=["^/items$"])
    runner.run_pipeline(cfg)
    assert seen["labels"] == ["DELETE /items/{id}", "GET /health", "GET /items/{id}"]
    assert seen["paths"] == ["/health", "/items/{id}"]


def test_run_cmd_cancel_kills_process_quickly():
    ev = threading.Event()
    threading.Timer(0.5, ev.set).start()
    t = time.time()
    with pytest.raises(Cancelled):
        run_cmd([sys.executable, "-c", "import time; time.sleep(30)"], cancel=ev)
    assert time.time() - t < 5


def test_run_cmd_captures_output():
    r = run_cmd([sys.executable, "-c", "print('hi'); import sys; print('err', file=sys.stderr)"])
    assert r.returncode == 0 and r.stdout.strip() == "hi" and "err" in r.stderr
