# OpenAPI rules for AI coding assistants

Paste the block below into the project's AI instruction file (`CLAUDE.md`, `AGENTS.md`,
`.github/copilot-instructions.md`, `.cursor/rules`, ...). Full reasoning and code samples:
`docs/SWAGGER_GUIDE.md` in the sprat repo.

---

```markdown
## API spec rules (OpenAPI / Swagger)

This API is tested automatically from its OpenAPI spec (sprat: Spectral + Schemathesis +
auth/BOLA checks + OWASP ZAP). The spec must match the server's real behavior exactly. When you
add or change an endpoint, update the spec in the same change.

Security
- Every operation is explicitly one of: secured (`security: [{bearerAuth: []}]`), public
  (`security: []`), or optional (`security: [{}, {bearerAuth: []}]`). Never leave it implicit.
- Secured operations document `401` and `403`.
- .NET: use a per-endpoint IOperationFilter based on [Authorize]/[AllowAnonymous], not a global
  AddSecurityRequirement.
- Check ownership in every handler that loads a resource by ID (filter by the current user's ID).
  Being authenticated is not enough.

Responses
- Document every status code the handler can return (200/201/204, 400, 401, 403, 404, 409, 422...).
  Never document 500. Never use `default` as a catch-all.
- Every response with a body has a schema. Objects list all always-present fields in `required`,
  mark nullable fields as nullable, and use `additionalProperties: false` when no extra fields are sent.
- Use `format` (uuid, date-time, date, email, uri, int32, int64) and `enum` wherever they apply.
  Enums are serialized as strings.
- All errors use one Problem Details schema (`application/problem+json`). Never return stack traces.
- Return DTOs, never ORM entities.

Requests
- Every constraint in the spec (required, minLength/maxLength, minimum/maximum, pattern, enum,
  format) is enforced by the server, and every rule the server enforces is in the spec.
  .NET: use DataAnnotations on DTOs ([Required], [Range], [StringLength]) so both sides come from one place.
  Node: generate the spec from Zod schemas (zod-to-openapi) and validate with the same schemas,
  or use express-openapi-validator.
- Path and query parameters have a type and format; required ones are `required: true`.
- Invalid path or query values (e.g. `/orders/abc` for a uuid) return 400, never 500.

Structure
- Unique camelCase `operationId`, plus `summary` and `tags`, on every operation.
- Create operations have `links` to the get/update/delete operations of the created resource
  (`orderId: $response.body#/id`).
- Examples must validate against their schema. Add examples for boundary values.
- Old endpoints are marked `deprecated: true`, not removed from the spec while still served.
- A method a path doesn't support returns 405 Method Not Allowed with an `Allow` header, not 404.
  Express: mount a method-not-allowed middleware after all routes and before any catch-all or
  404 handler (see SWAGGER_GUIDE.md §4.2). ASP.NET Core does this itself unless a fallback route
  swallows it.

Before finishing an API change, check: does the spec now describe exactly what the code does,
for success, every error status, auth, and validation?
```
