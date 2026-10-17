# SPRAT — Spec Probing, Robustness & Attack Testing

Point it at a Swagger/OpenAPI URL and it tests the API end to end. The backend
language doesn't matter (.NET, Express, anything) — everything goes through the
spec and HTTP.

## What it checks

| Stage | Tool | What it catches |
|---|---|---|
| `lint` | Spectral (via `npx`) | Spec quality: missing schemas, missing descriptions, bad refs |
| `conformance` | Schemathesis | Type safety + fuzzing: responses that violate the schema, 500s, undocumented status codes, accepting invalid input, auth not enforced |
| `types` | built in | Wrong-type probing: every request-body field (nested too) gets values of other types, including look-alikes lenient parsers accept (`"1"` for an integer, `"true"`/`1`/`0` for a boolean, `"1.5"` for a number, `null` for non-nullable). Reports which field accepted which type |
| `authz` | built in | Secured endpoints served without / with junk credentials, **BOLA** (user B reading user A's data), stack-trace leaks, missing security headers, wildcard CORS with credentials |
| `zap` | OWASP ZAP API scan (Docker) | DAST: injection, header and misconfiguration issues |

Stages that can't run (no Node, no Docker) are reported as `skipped` — never passed silently.

## Setup

```
python -m venv .venv
.venv\Scripts\pip install -e .
```

Optional: Node.js for `lint`, and Docker Desktop running for `zap`.

## Contents

- [Web UI](#web-ui)
- [Run (CLI)](#run-cli)
- [BOLA tests](#bola-tests)
- [Writing specs that test well](#writing-specs-that-test-well)
- [HTTPS certificates](#https-certificates)
- [Safety](#safety)
- [Demo](#demo)

---

## Web UI

```
sprat ui
```

Then open http://localhost:8787.

### Projects

One project = one API application: its Swagger document, base URL, test users, BOLA
scenarios and which tests to run. The home page lists all projects with their last
result, and each card has **Run all APIs** and **Stop** buttons.

### New project → Discover

Enter the running app's URL (the root, the Swagger UI page, or the spec JSON).
sprat finds the Swagger/OpenAPI document(s) and lists every API before you save.
For a root URL it probes the usual locations: `/swagger/v1/swagger.json` (ASP.NET
Core), `/openapi/v1.json` (.NET 9), `/api-docs` (swagger-ui-express, including specs
embedded in the page), `/openapi.json`, `/v3/api-docs` and more.

The same works on the CLI:

```
sprat discover https://orders-staging.example.com
```

### Inside a project

- **APIs** tab — every operation grouped by tag, with its last result (click it to
  see that API's findings). Tick APIs and press **Run selected**, or use **▶ Run** on
  a single row. **Refresh APIs** reloads the Swagger after the app changes.
- **Runs** tab — history.
- **Settings** tab — everything from the new-project form.
- **Export CLI config** — gives the YAML for CI. Selecting APIs works there too:
  `sprat run --config x.yaml --op "GET /orders/{id}"`.

### Live activity

While a run is going, the run page shows **Now**: the current test, the API it's on,
what it's doing ("Sending invalid credentials; expecting 401/403", "Field 3/7
`price`: sending wrong types", "Active scan: attacking the APIs 40%") and an
"N / M APIs done" bar. Below it is a live feed of results, with failures in red.
After the run, the feed is kept as a collapsed **Activity log**.

### HTML report

Run page → **Open HTML report** (also inside the ZIP as `test-report.html`). One
self-contained file you can open offline or send to someone:

- **Read this first** — run-level problems, e.g. no token set (so protected APIs
  only returned 401), test data written to the database, no second user for
  cross-user checks, a test that didn't run.
- **All APIs** — one row per API, one symbol per test: ✓ tested · ◐ partly tested ·
  ✕ not tested · – not applicable · ? not recorded. Hover a symbol for the reason.
- **Per API** — what was tested and what wasn't, and why (e.g. "None of the 193
  requests was accepted (142 refused with 401/403…) because no token was set"; "This
  API takes an ID, but no cross-user scenario is configured for it"). Then the
  problems found, and every test sent to it: what was tested, what was expected, the
  result in plain words, and the full input and output.

The same per-API coverage is in `coverage.csv` / `coverage.json`, and each test-log
entry has a plain-language `explanation`.

### Automatic login

Settings → Test users → *Log in automatically*. Instead of pasting a token that
expires, give sprat the login API and it fetches tokens itself:

1. **Login API URL** and method, and the **request body**, with the password written
   as a name: `{"email": "qa@example.com", "password": "${QA_PASSWORD}"}`. Literal
   passwords are refused. Right below, the **Secrets** box lists every `${…}` name
   used: type the value and press **Save**. It's stored **encrypted with the
   project** (Fernet; `reports/secrets.json`) and never shown again, and it's left
   out of exports, reports and logs. Deleting the project deletes its secrets. The
   same works for API keys or tokens in pasted headers (`X-API-Key: ${INGRESS_KEY}`).
2. **Pick the token** — paste one sample login response and click **Use as token**
   on the right field (e.g. `data.accessToken`). The sample stays in your browser.
3. **Send the token as** — Bearer token, a custom header (e.g. `X-API-Key`), or a
   cookie.
4. **Token expires** — automatically from the JWT's `exp` (the usual case), from a
   response field (e.g. `data.expiresIn`), or after a fixed number of minutes.
5. **Test login** shows when the token expires and when sprat would renew it.

During a run sprat logs in at the start and fetches a new token **30 seconds
before the current one expires**: in its own tests, and inside Schemathesis (through
a generated hooks file). ZAP gets the token through its replacer rules; during the
scan sprat logs in again 90 seconds before expiry and swaps the rule through ZAP's
API (published on 127.0.0.1 only), so long scans don't end in 401s. Wrong credentials stop the run before anything is
tested, with the login API's error message. User A and user B each have their own
login. In a CLI config this is `login_a:` / `login_b:` (see
`examples/demo-login.yaml`); the CLI has no secret store, so there `${NAME}` comes
from environment variables.

**The encryption key.** By default sprat creates `reports/.secret.key` on first
use. Anyone who can read both that file and `secrets.json` can decrypt the secrets,
so **on a shared server set `SPRAT_SECRET_KEY`** (a long passphrase) in the
server's environment instead, and keep it out of the data folder. If the key
changes, saved secrets can't be decrypted and must be entered again. Back up the key
together with `secrets.json`.

**No token, no silent run.** If APIs in the run need login and no token is set for
user A, the UI asks before starting (Open Settings / Run anyway). Tokens typed into
Settings are forgotten when the sprat server restarts; use `${ENV_VAR}` references
to keep them.

### Test log

Every test sprat performs is recorded: one entry per request, with the stage, the
API, the scenario tested ("Boundary values and wrong types: Missing `Authorization`
at header", "Field `price` (declared number) set to numeric string \"1.5\"", "BOLA
step 2: user B requests user A's resource"), what a correct API should do, the
verdict (pass / fail / info / error), the full request and response, and the reason
for any failure. The run page's **Test log** tab lets you filter by stage, API,
verdict and text, and expand any entry.

Downloads:

- **Everything (ZIP)** — test log, findings report, the spec tested, and every
  tool's raw output
- **Test log (CSV)** — one row per test, opens in Excel
- **Test log (NDJSON)** — one JSON object per test, with full requests and responses

Token values and API keys are masked (`Bearer ***`) in every file. The CLI writes
the same `test-log.ndjson` and `test-log.csv` to its output folder.

What each stage logs:

- **conformance** — every request Schemathesis sends, with its phase, the generated
  scenario and every check result
- **types** — the baseline and each wrong-type request
- **authz** — each credentials test, public-endpoint check and both BOLA steps
- **zap** — every alert instance (URL, parameter, attack, evidence); ZAP doesn't
  export the requests that raised no alert, which are only summarised
- **lint** — each rule violation

### Other settings

- **Exclude paths** (Settings → Advanced) apply to every test, ZAP included.
  Excluded APIs are greyed out in the API list, and the **Run all** count only
  includes APIs that will actually be tested.
- **Stop** — a running test can be stopped from the run page, the project page or
  the project card. The current tool is killed (including its child processes, and
  the ZAP container) and partial results from the stages that finished are kept.
- **Tokens** — a header line like `Authorization: Bearer ${ORDERS_TOKEN_A}` is saved
  with the project, and the variable is read from the sprat server's environment
  when a run starts. The CLI supports `${VAR}` too. A literal token is held in
  server memory only, never written to disk, and must be re-entered after the
  server restarts. Run files show header values as `***`.
- Data lives in `reports/projects/` and `reports/runs/<id>/` (change this with
  `--data-dir`).
- The UI binds to `127.0.0.1` by default. It sends requests to any URL you give it,
  so don't expose it on a shared network (`--host 0.0.0.0`) without authentication
  in front.

### Wrong-type probing (`types`)

For each POST/PUT/PATCH with a JSON body, sprat first sends a **valid baseline**
body (the spec's `example`, else one generated from the schema). Only if that
returns 2xx does it swap each field to each wrong type. Otherwise a rejection could
be for any reason, and the operation is reported as "skipped: baseline rejected". To
fix that, add a working `example` to the request body (real IDs that exist on
staging).

Schemathesis (`conformance`) also sends wrong types, but it reports them as one
generic "accepted schema-violating request" per endpoint and doesn't send
look-alike values. `types` names the exact field and type.

## Run (CLI)

Quick, from flags only:

```
sprat run https://staging.example.com/swagger/v1/swagger.json -H "Authorization: Bearer <token>"
```

With a config file (recommended; see `examples/demo.yaml`):

```
sprat run --config myapi.yaml
```

Useful flags: `--base-url` (when the spec has no usable server/host),
`--stages lint,conformance`, `--max-examples 100`, `--fail-on medium`,
`--no-mutating-authz`, `--out reports/myapi`.

Output goes to `reports/` by default: `report.html`, `report.json`, plus each
tool's raw output (`schemathesis-junit.xml`, `schemathesis.log`, `zap.html`, ...).
The exit code is 1 if any finding is at or above `fail_on` (default `high`) or a
stage errored, so it can gate CI.

## BOLA tests

Scanners can't know who owns what, so you list a few resources owned by user A:

```yaml
headers:   {Authorization: Bearer <user A token>}
headers_b: {Authorization: Bearer <user B token>}
bola:
  - method: GET
    path: /api/orders/{id}
    params: {id: 1234}       # an order that belongs to user A
```

The tester checks that A gets 2xx, then replays as B and flags any 2xx.

## Writing specs that test well

- [docs/SWAGGER_GUIDE.md](docs/SWAGGER_GUIDE.md) — the full guide for developers
  (what to put in the spec and why, ASP.NET Core and Express setup, checklist,
  finding → fix table).
- [docs/AI_RULES_OPENAPI.md](docs/AI_RULES_OPENAPI.md) — a short rules block to
  paste into `CLAUDE.md` / Copilot / Cursor instructions in each API repo.
- [docs/STAGES.md](docs/STAGES.md) — what each stage tests, every test case it
  sends, and what counts as pass or fail.

### Getting good results from .NET / Express specs

- **.NET (Swashbuckle/NSwag)** — add `[ProducesResponseType]` for every status the
  action returns, enable nullable reference types, and declare the security scheme
  plus `AddSecurityRequirement`. Otherwise `authz` can't tell which endpoints are
  meant to be protected.
- **Express (swagger-jsdoc etc.)** — make sure `security:` is declared and that
  response schemas exist. A hand-written spec drifts quickly, which is exactly what
  `conformance` will report.
- If the spec uses a relative server URL like `/api`, pass `--base-url`.

## HTTPS certificates

sprat trusts Python's certificate list **plus the Windows certificate store**, so
it works on machines where an antivirus web shield (Norton, Avast...) or a company
proxy re-signs HTTPS, or where servers use an internal CA that Windows trusts.
Discovery, login, every test stage and Schemathesis all use the same list.
Verification is never turned off: an expired or wrong certificate is still
rejected. To trust one more CA (for example on Linux CI), export it as PEM and set
`SPRAT_CA_BUNDLE` to the file.

## Safety

Run against **staging**, never production. Fuzzing and ZAP active scanning send
thousands of requests, including POST/PUT/DELETE with garbage data. Use test
accounts for the tokens.

## Demo

`examples/demo_api.py` is a small API with planted flaws:

```
uvicorn examples.demo_api:app --port 8000
sprat run --config examples/demo.yaml
```

## Tests

```
pytest tests
```
