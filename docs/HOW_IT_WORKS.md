# How sprat Works

sprat reads an API's Swagger/OpenAPI document and runs five test stages against it, from either
the command line or a web UI. Both entry points call the same pipeline, and every stage's findings
end up in one report.

## At a glance

```
 ┌──────────────────────────────┐        ┌──────────────────────────────────┐
 │ CLI · cli.py                 │        │ Web UI · web/app.py + app.js     │
 │ sprat run (flags or YAML)  │        │ Projects, Run and Stop           │
 └──────────────┬───────────────┘        └────────────────┬─────────────────┘
                │ Config from flags/YAML                  │ Config from saved project
                ▼                                         ▼
        ┌──────────────────────────────────────────────────────────┐
        │ run_pipeline() · runner.py                               │
        │ load spec once (spec.py, discover.py), filter operations, │
        │ run stages in order, map each finding to its operation   │
        └─────────────────────────────┬────────────────────────────┘
                                      │ same spec, config, output folder
 ┌────────────────────────────────────▼─────────────────────────────────────┐
 │ Stages · stages/*.py, run in this order                                  │
 │ ┌───────────┐ ┌─────────────┐ ┌────────────┐ ┌─────────────┐ ┌──────────┐ │
 │ │ lint      │ │ conformance │ │ types      │ │ authz       │ │ zap      │ │
 │ │ Spectral  │ │ Schemathesis│ │ built in   │ │ built in    │ │ OWASP ZAP│ │
 │ │ (npx)     │ │ subprocess  │ │ httpx      │ │ httpx       │ │ Docker   │ │
 │ └───────────┘ └──────┬──────┘ └─────┬──────┘ └──────┬──────┘ └────┬─────┘ │
 └───────┬──────────────┼──────────────┼───────────────┼─────────────┼───────┘
         │              └──────────────┴── HTTP ───────┴─────────────┘
         │                              ▼
         │              ┌──────────────────────────────────────────┐
         │              │ Your API (staging)                       │
         │              └──────────────────────────────────────────┘
         │ findings from all stages
         ▼
 ┌──────────────────────────────────────────────────────────────────────────┐
 │ Reports · report.py: report.json, report.html, raw tool output;          │
 │ exit code 1 when any finding is at or above fail_on                      │
 └──────────────────────────────────────────────────────────────────────────┘
```

Only `lint` works on the spec alone. The other four stages send real HTTP requests to the API under test.

## Entry points

There is one command, `sprat`, which `pyproject.toml` maps to `sprat.cli:main`. It has three
subcommands, and two of them end up in the same pipeline function, `run_pipeline()` in `runner.py`.

| Command | What it does | Calls |
| --- | --- | --- |
| `sprat run` | Builds a `Config` from a YAML file and/or flags, runs the stages, and prints progress lines | `load_config()` → `run_pipeline()` → exit code from `failed()` |
| `sprat discover <url>` | Finds the Swagger/OpenAPI documents of a running app and lists every operation | `discover()` → `load_spec()` |
| `sprat ui` | Starts the web UI on `127.0.0.1:8787` | `web/app.py` → `serve()` (FastAPI on uvicorn) |

The web UI is a FastAPI backend (`web/app.py`) plus a plain-JavaScript single-page frontend
(`web/static/app.js`, `index.html`, `style.css`). When you press **Run**, the backend builds a
`Config` from the saved project and starts `run_pipeline()` on a background thread. The page then
polls `GET /api/runs/{id}` every 1.5 seconds to show each stage's status.

## How a run works

`run_pipeline()` loads the spec once, runs the selected stages one after another, then writes one
combined report. Each stage gets the same three inputs (`spec`, `cfg`, `out` directory) and returns
a `StageResult` holding a list of `Finding`s.

1. **Load the spec.** `load_spec()` fetches the URL or file. If the response is a Swagger UI page
   rather than a spec, it pulls out the embedded spec or the spec URL the page references. It
   accepts Swagger 2.0 and OpenAPI 3.x, in JSON or YAML.
2. **Extract operations.** Every `METHOD /path` becomes an `Operation`: whether it is secured,
   whether it has a body, and placeholder values for path and required query parameters (`1`, a
   fixed UUID, or the first enum value).
3. **Work out the base URL.** `--base-url` wins. Otherwise sprat uses `servers[0]` (OpenAPI 3),
   `host` + `basePath` (Swagger 2), or the spec URL's origin.
4. **Filter.** `--op` reduces the spec to the selected operations, and `exclude_paths` regexes
   remove operations. The reduced copy is what the stages test, so ZAP and Schemathesis skip the
   excluded paths too.
5. **Run each stage** in the order `lint`, `conformance`, `types`, `authz`, `zap`. A stage that
   throws becomes `error` and the others still run. A stage that can't run (no Node, no Docker)
   returns `skipped`.
6. **Map findings to operations.** `annotate()` tags each finding with the operation it belongs
   to. It matches `GET /path` labels, concrete URLs from ZAP against path templates, and Spectral's
   JSON paths. That is what lets the UI show a last result per API.
7. **Write reports.** `report.json` and `report.html` go into the output folder, next to each
   tool's raw output.

Stopping a run sets a `threading.Event`. Stages check it between requests, and `proc.run_cmd()`
kills the whole child process tree (`taskkill /T /F` on Windows). The stages still to run are
marked `cancelled`, and a partial report is still written.

## How each stage tests the APIs

Two stages check the spec or fuzz it with outside tools, two are hand-written HTTP checks built
into sprat, and one is a full security scanner. All of them read the same parsed spec.

### lint: is the spec itself good?

This stage sends no requests to the API. It writes the whole spec to disk and runs Spectral's
built-in `spectral:oas` ruleset over it. Findings are missing descriptions, missing schemas, broken
`$ref`s and similar problems. The whole document is always linted, even when only some operations
are selected, so that no false "unused component" warnings appear. Only findings for the selected
operations are kept.

### conformance: does the API behave like its spec?

Schemathesis generates requests from the schemas and runs every check (`--checks all`). Its phases
send the spec's examples, then boundary values and wrong types, then random fuzzing, then stateful
chains such as create → read → delete. It flags 500 errors, responses that don't match the
declared schema, undocumented status codes or content types, invalid input that gets accepted, and
secured endpoints served without authentication. Each failing check becomes one finding per
endpoint. Server errors and authentication failures are rated `high`, schema violations `medium`,
and undocumented statuses `low`.

### types: which field accepts the wrong type?

This is built in (`stages/types.py`) and covers POST, PUT and PATCH operations that have a JSON body.

1. It sends a valid baseline body: the spec's `example`, or one generated from the schema. If that
   baseline doesn't get a 2xx, the operation is skipped, because a rejection would prove nothing.
2. It walks every field, nested ones included, up to 4 levels deep and 60 fields per operation.
3. It replaces one field at a time with values of other types and resends. These include
   look-alikes that lenient parsers accept: `"1"` for an integer, `"true"`, `1` and `0` for a
   boolean, `"1.5"` for a number, and `null` for a field that isn't nullable.
4. A 4xx is the correct answer. A 2xx means the wrong type was accepted (`medium`, or `low` for
   null on an optional field). A 5xx means the server crashed on it (`high`).

Union fields (`oneOf` and `anyOf`) are skipped, because many "wrong" types are valid there.

### authz: is access control enforced?

This is built in (`stages/authz.py`) and uses plain `httpx` requests.

- **Missing or junk credentials.** Every operation the spec marks as secured is called with no
  `Authorization` header, then with `Bearer invalid.token.value`. A 2xx is `critical`.
- **BOLA.** For each `bola:` scenario in the config, user A requests its own resource and must get
  a 2xx. Then user B requests the same URL, and a 2xx is `critical`. If user A fails, the scenario
  is reported as inconclusive.
- **Passive checks** on the responses: stack traces or SQL errors in error bodies (`medium`), a
  missing `X-Content-Type-Options: nosniff` header (`low`), and `Access-Control-Allow-Origin: *`
  together with credentials (`high`).

Public write endpoints are not called. `--no-mutating-authz` limits the stage to GET, HEAD and OPTIONS.

### zap: dynamic security scan

The OWASP ZAP API scan runs in Docker. It imports the spec and sends active attacks: injection,
header problems and misconfigurations. ZAP's risk levels map to severities: 3 is `high`, 2
`medium`, 1 `low`, 0 `info`.

## Integrated tools

The three outside tools are never imported as libraries. Each runs as a subprocess through
`proc.run_cmd()`, writes a machine-readable output file, and sprat parses that file into
`Finding`s. `run_cmd()` sends output to temp files rather than pipes, so a chatty tool can't block,
and it supports cancel and timeout.

| Tool | How it is launched | What sprat reads back | If it is missing |
| --- | --- | --- | --- |
| Spectral | `npx --yes @stoplight/spectral-cli lint spec-full.json --ruleset .spectral.yaml -f json` (5 min timeout) | JSON array of rule hits; severity 0–3 maps to high/medium/low/info | No `npx` → `skipped` |
| Schemathesis | `python -m schemathesis.cli run <spec> --url <base> --checks all --max-examples N` with user A's headers (30 min timeout) | `schemathesis-junit.xml` for findings, plus an NDJSON event stream tailed live for progress | Installed as a Python dependency; zero test cases → `error`, never a silent pass |
| OWASP ZAP | `docker run ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py -t spec.json -f openapi` with the output folder mounted at `/zap/wrk` (60 min timeout) | `zap.json` alerts; the first instance gives the method and URL | No Docker or daemon not running → `skipped` |

A few details make the integration work:

- **Auth headers.** Schemathesis gets them as `-H` flags. ZAP gets them through its replacer rules
  (`-config replacer.full_list(i)...`), which add the header to every request.
- **localhost inside Docker.** A base URL on `localhost` or `127.0.0.1` is rewritten to
  `host.docker.internal` so the ZAP container can reach an API running on your machine.
- **Which spec file.** Schemathesis gets the original URL when possible. When the spec came from a
  Swagger UI page, a local file, or was reduced by `--op`, a copy is written to `spec.json` and
  passed instead.
- **Stopping ZAP.** Killing the Docker client leaves the container running, so a cancel also runs
  `docker rm -f` on the container by name.
- **Windows encoding.** Schemathesis is started with `PYTHONIOENCODING=utf-8`, because it fails on
  Windows' default `utf-8:surrogateescape`.

The Python libraries the project depends on are listed in `pyproject.toml`: `schemathesis`, `httpx`
(all built-in HTTP calls), `pyyaml` (configs and YAML specs), `fastapi` + `uvicorn` (the web UI),
and `jinja2`.

## Data and reports

Everything is stored as plain files under `reports/` (change it with `--data-dir`). There is no database.

| Path | Holds | Written by |
| --- | --- | --- |
| `reports/projects/<id>.json` | One web-UI project: spec URL, base URL, header lines, BOLA scenarios, stages, and the cached operation list | Web UI |
| `reports/runs/<run id>/run.json` | Run status, per-stage status, and headers masked as `***` | Web UI |
| `<out>/report.json`, `report.html` | All findings, grouped by stage and sorted by severity | `report.py` |
| `<out>/schemathesis-junit.xml`, `schemathesis.log`, `types.log`, `zap.json`, `zap.html`, `zap.log` | Each tool's raw output, for digging deeper | Each stage |

A finding has a stage, a severity (`info` < `low` < `medium` < `high` < `critical`), a title, the
endpoint, a detail text, and the spec operation it maps to. `sprat run` exits with 1 when any
finding is at or above `fail_on` (default `high`) or any stage ended in `error`. That makes it
usable as a CI gate; `examples/azure-pipelines.yml` shows one.

**Secrets.** A header line such as `Authorization: Bearer ${ORDERS_TOKEN}` is saved with the
project and read from the server's environment when a run starts. A literal token is kept only in
the server's memory and is gone after a restart.

One gap worth knowing: the stages call `progress()` to report per-operation activity, but the web
backend never sets `Config.on_progress`. Those messages are dropped, and the run page shows
stage-level status only.

## Code map

The package has about 3,000 lines in total. The core is `runner.py` and the five stage files.

| File | Lines | Role |
| --- | --- | --- |
| `sprat/cli.py` | 115 | Command-line parser for `run`, `discover` and `ui` |
| `sprat/config.py` | 66 | `Config` dataclass, YAML loading, `${VAR}` expansion |
| `sprat/spec.py` | 171 | Fetches and parses the spec into `Operation`s; base URL; `--op` filtering |
| `sprat/discover.py` | 185 | Probes 15 spec paths and 8 Swagger UI paths; extracts specs from Swagger UI pages |
| `sprat/runner.py` | 109 | `run_pipeline()`: runs the stages, maps findings to operations, decides pass or fail |
| `sprat/models.py` | 28 | `Finding`, `StageResult`, severity order |
| `sprat/proc.py` | 113 | Cancellable subprocess runner, process-tree kill, live file tail, progress hook |
| `sprat/report.py` | 44 | Writes `report.json` and `report.html` |
| `sprat/stages/lint.py` | 50 | Spectral |
| `sprat/stages/conformance.py` | 128 | Schemathesis, JUnit parsing, severity mapping |
| `sprat/stages/types.py` | 331 | Wrong-type probing |
| `sprat/stages/authz.py` | 131 | Auth enforcement, BOLA, passive response checks |
| `sprat/stages/zap.py` | 68 | OWASP ZAP in Docker |
| `sprat/web/app.py` | 548 | FastAPI backend: projects, discovery, runs, stop, files |
| `sprat/web/static/app.js` | 689 | Single-page frontend |

Other folders: `tests/` holds the pytest suite (spec parsing, projects, types, web). `examples/`
holds the flawed demo API, its config, and an Azure Pipelines file. `docs/` holds guides for
writing specs that test well.
