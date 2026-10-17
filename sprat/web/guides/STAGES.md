# What sprat tests at each stage

sprat runs up to five stages, in this order. Each stage can be switched on or off per run
(`--stages` on the CLI, checkboxes in the web UI).

| # | Stage (name in the report) | Question it answers | Tool | Sends requests? |
|---|---|---|---|---|
| 1 | `lint` (Swagger quality) | Is the Swagger document itself well written? | Spectral | No |
| 2 | `conformance` (Behaviour vs Swagger) | Does the API behave the way the Swagger says? | Schemathesis | Yes, many |
| 3 | `types` (Wrong data types) | Does the API reject a value of the wrong type? | sprat's own code | Yes, POST/PUT/PATCH only |
| 4 | `authz` (Access control) | Can someone get in without a valid login, or read another user's data? | sprat's own code | Yes |
| 5 | `zap` (Security scan) | Does the API have common web vulnerabilities? | OWASP ZAP (Docker) | Yes, attack payloads |

Every request sprat sends is recorded in the test log (`test-log.ndjson` / `.csv`) and in the
HTML report (`test-report.html`). Each row shows the stage and phase it came from, so it can be
matched to the sections below.

---

## 1. `lint`: Swagger quality

sprat reads only the Swagger file, so the API is never called. It uses Spectral's standard
OpenAPI ruleset (`spectral:oas`), including:

- The document is valid OpenAPI, with no broken `$ref`s and no duplicate `operationId`s.
- Every API has an `operationId`, a description, tags and at least one success response.
- Path parameters such as `{id}` are declared, and paths don't end with `/`.
- Examples actually match their schemas.
- Enums have a type and no duplicate values. No components are defined and never used.
- `servers` and `info` (contact, etc.) are present.

**Fails when:** a rule is broken. These findings are usually low severity, but a poor Swagger
makes every later stage weaker. The whole document is always checked, even when only some APIs
are selected. The report lists only the findings for the selected APIs.

## 2. `conformance`: behaviour vs Swagger

Schemathesis sends requests in four phases. Each phase sends up to 50 requests per API, which is
the default (`--max-examples` changes it).

| Phase (name in the report) | What it sends |
|---|---|
| **Swagger examples** | The example values written in the Swagger |
| **Edge cases** | Inputs picked one at a time: min/max values, values just outside the limits, empty strings, a missing required field or header, a wrong type, an unsupported HTTP method |
| **Random data** | Many generated requests, valid and deliberately invalid |
| **Request chains** | Linked calls, e.g. create → read → update → delete, using `links` in the Swagger |

Every response is checked against these test cases:

| Check | Fails when |
|---|---|
| No server errors | The API returns a 5xx |
| Status code | The code isn't one the Swagger documents for that API |
| Response body | The JSON doesn't match the documented schema (types, required fields, enums, formats) |
| Content-Type and headers | Either doesn't match the Swagger |
| Invalid input is rejected | Data that breaks the Swagger's rules gets a 2xx instead of a 4xx |
| Valid input is accepted | Correct data is refused |
| Missing required header | A request without a required header isn't rejected with a 4xx |
| Unsupported method | A method the path doesn't support gets something other than 405 with an `Allow` header |
| Ignored auth | An API the Swagger marks as secured also works with no token or a wrong one |
| Use after delete | A deleted resource can still be fetched |
| Created resource | A resource that was just created can't be found |

If a request is blocked by 401/403 (missing token or permission), sprat marks it
**"Not really tested"** rather than passed. The report names the missing permission when the
server says which one it is.

## 3. `types`: wrong data types

This covers POST/PUT/PATCH APIs with a JSON body:

1. sprat first sends a **valid request**, with every field the correct type. If the server
   refuses it, that API is skipped and the reason is shown, because any later rejection couldn't
   be blamed on the type.
2. It then changes **one field at a time** and resends. Nested fields go 4 levels deep, up to 60
   fields per API:

| Field declared as | Values sent instead |
|---|---|
| string | `123`, `1.5`, `true`, `["x"]`, `{"a":"x"}`, `null` |
| integer | `"1"`, `"abc"`, `1.5`, `true`, `[1]`, `{"a":1}`, `null` |
| number | `"1.5"`, `"abc"`, `true`, `[1]`, `{"a":1}`, `null` |
| boolean | `"true"`, `1`, `0`, `"yes"`, `[true]`, `{"a":true}`, `null` |
| array | `"x"`, `{"a":1}`, `1`, `null` |
| object | `"x"`, `[]`, `1`, `null` |

- **Pass:** 4xx (rejected).
- **Fail:** 2xx (silently accepted). The look-alikes, such as `"1"` for a number or `"true"` for a
  boolean, are what lenient .NET and Express parsers usually let through.
- **Crash:** 5xx.
- `null` is only a finding if the Swagger doesn't mark the field nullable.

## 4. `authz`: access control

**For every API the Swagger marks as secured:**

- Called with **no token**: must not return 2xx.
- Called with a **fake token** (`Bearer invalid.token.value`): must not return 2xx.

**On every response (passive checks):**

- Error responses mustn't leak internals: stack traces, `System.*Exception`, SQL errors,
  Sequelize errors, file and line numbers.
- The `X-Content-Type-Options: nosniff` header is present.
- CORS doesn't allow any origin (`*`) together with credentials.

**BOLA (one user reading another user's data):** this only runs if user B and BOLA scenarios are
set up in the project.

- User A requests their own resource and must get 2xx. Otherwise the scenario is "inconclusive".
- User B makes the exact same request and must get 401, 403 or 404. A 2xx is a **critical** finding.

The "no write methods" option (`--no-mutating-authz`) limits this stage to GET/HEAD/OPTIONS.

## 5. `zap`: security scan

OWASP ZAP's API scan (`zap-api-scan.py` in Docker), using the Swagger and the current token:

- **Passive:** information disclosure, missing security headers, cookie flags, server version
  leaks, error pages.
- **Active:** attack payloads in every parameter. These include SQL injection, cross-site
  scripting (XSS), path traversal, OS command injection, CRLF/header injection, server-side
  include, format string and buffer overflow probes.

The report lists the alerts ZAP raised, mapped back to each API. This stage sends the most
aggressive traffic of the five, so run it against staging only.

---

## Severity, root causes and access issues

Every failed test gets a root cause, a severity and a recommended fix. The HTML report starts with
**Fix these first**: problems grouped by root cause, the 10 APIs with the most failed tests, every
API that crashes with a 5xx, and every API that accepts wrong data types.

| Root cause | Severity |
|---|---|
| Works without a valid login, one user reads another's data (BOLA) | critical |
| Server error (5xx) from any input, CORS `*` with credentials, missing required header not rejected | high |
| Wrong type accepted (e.g. `"1"` for a number), null accepted on a required field, invalid input accepted, response doesn't match the schema, leaked stack traces | medium |
| Undocumented status code or Content-Type, unsupported method not answered with 405, missing security header, null accepted on an optional field | low |
| Swagger rule problems (`lint`) and ZAP alerts | the tool's own rating |

When requests that should reach an API's logic are refused with 401/403, that API is marked
**Not tested: access issue** (every such request refused) or **Partly not tested: access issue**
(some refused), with the reason: no token, a refused token, or the missing permission. Requests
that test the login itself (no token, fake token) don't count.

### APIs that answer errors with HTTP 200

Some APIs refuse a request but still answer HTTP 200, with the error in the body
(`{"status": "Failed", "message": "..."}`, `{"success": false, ...}`). sprat reads the body: such a
response counts as a refusal, so it isn't reported as "accepted the wrong type", "accepted invalid
input" or "works without login", and it isn't counted as a write. Each such API gets one low
finding instead: **Reports errors with HTTP 200 instead of 4xx**.

Access refusals that don't use 401/403 ("400 User is not authorized", "200 API key is required")
also count as access issues, and the reason quotes what the server said.

### Saved working examples

The wrong-type stage starts every API from a valid request. If the Swagger's example doesn't work
on your environment (an ID that doesn't exist, a missing required field), the API is skipped. Save a
request that works under the API's **✎** button on the APIs tab (body, path and query parameters),
or as `examples:` in a CLI config:

```yaml
examples:
  "POST /api/v1/WorkFlowTaskMaintenanceCost":
    body: {taskId: 1018956, purchaseOrder: "PO-1", detail: "test", additionalCost: 1.5}
  "GET /api/v1/site/{id}":
    path: {id: "12"}
```

sprat writes them into its own copy of the Swagger before testing: the wrong-type stage starts
from them and the behaviour tests send them as examples. Swagger-quality checks still judge your
original Swagger.

### When the Swagger isn't reliable: lenient mode

Turn on *The Swagger isn't reliable (lenient mode)* in the project's Settings, or pass
`--lenient-spec` on the CLI (`lenient_spec: true` in a config file). Findings that only show the
API and the Swagger disagree (undocumented status codes, response shape, Content-Type, validation
rules the Swagger declares, fields accepting null that the Swagger doesn't mark nullable) are listed as **Swagger problems** with severity info, so they don't
fail the run. Crashes, wrong types accepted, missing login checks, BOLA and ZAP alerts are still
reported at their normal severity.

## What none of the stages checks

- **Business rules**, e.g. "a discount can't exceed 50%" or "only managers can approve".
- **Whether returned values are correct.** Only their shape and type are checked.
- **Performance under load.**

Results are also only as good as the Swagger. An API with no schema or wrong examples can only be
partly tested, and the per-API report shows "partial" or "not tested" with the reason.
[SWAGGER_GUIDE.md](SWAGGER_GUIDE.md) explains how to write a Swagger that tests well.

## Before running against a real server

- Run against **staging**, not production. Stages 2 to 5 send POST/PUT/DELETE requests with
  invalid data.
- Exclude APIs with side effects outside the database: sending emails, SMS or OTPs, resetting
  passwords, revoking tokens, bulk updates or imports.
- Use test accounts for user A and user B.
