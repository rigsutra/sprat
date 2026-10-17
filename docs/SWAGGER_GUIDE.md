# Writing Swagger / OpenAPI specs that sprat can test well

sprat knows only what your spec tells it. A precise spec lets it find real bugs. A vague
spec produces two kinds of failure: **noise** (false findings) and **blind spots** (bugs it never
looks for). This guide covers what to put in the spec, why each part matters, and how to do it in
ASP.NET Core and Express.

Use **OpenAPI 3.0 or 3.1**. Swagger 2.0 works, but it can't express nullability, `oneOf`, or links
cleanly.

---

## 1. How sprat uses your spec

| Spec element | Used by | If it's missing or wrong |
|---|---|---|
| `servers` | every stage | sprat can't find the API; you must pass `--base-url` |
| `security` per operation | `authz`, `conformance` | Protected endpoints are never checked for missing auth, **or** public endpoints are reported as "critical: accepts no credentials" |
| Response schemas | `conformance` | Type errors in responses go undetected |
| Every status code an endpoint returns | `conformance` | Every 400/401/404 is reported as "Undocumented HTTP status code" |
| Request constraints (`required`, `minLength`, `enum`, `format`...) | `conformance` | Fuzzing can't tell valid input from invalid, so validation bugs are missed |
| Path parameter types and formats | `authz`, `conformance` | Probes use the wrong ID shape and hit 400/404 instead of the auth check |
| `examples` | `conformance`, `zap` | Edge cases with specific values are rarely reached |
| `links` | `conformance` (stateful) | Create → read → update → delete flows aren't tested |
| `operationId`, `summary`, `tags` | `lint`, report | Lint warnings; findings are harder to read |

**The rule underneath all of these: the spec must describe what the server actually does,
not what you wish it did.** If the server returns 404, document 404. If it accepts a field up to
200 characters, put `maxLength: 200`. A mismatch in either direction is what sprat reports.

---

## 2. Requirements

### 2.1 Servers

```yaml
servers:
  - url: https://orders-staging.example.com/api   # absolute, or relative to where the spec is served
```

- Serve the spec from each environment (`/swagger/v1/swagger.json`) so the server URL matches.
- Don't hard-code `localhost` in a spec that's served from staging.

### 2.2 Security: mark protected and public endpoints explicitly

This is the most important section for security testing. sprat sends **no token** and a
**fake token** to every operation marked as secured, and expects 401/403.

```yaml
components:
  securitySchemes:
    bearerAuth: { type: http, scheme: bearer, bearerFormat: JWT }

security: [ { bearerAuth: [] } ]      # default: everything needs auth

paths:
  /health:
    get:
      security: []                    # explicitly public
  /products:
    get:
      security: [ {}, { bearerAuth: [] } ]   # auth optional (anonymous allowed, more data when logged in)
```

| You write | sprat treats it as |
|---|---|
| `security: [ { bearerAuth: [] } ]` (operation or global) | Secured: must reject no token or a fake token |
| `security: []` on the operation | Public: auth checks skipped |
| `security: [ {}, { bearerAuth: [] } ]` | Optional: auth checks skipped |
| Nothing anywhere | Public (so it is **never** auth-tested) |

Common mistakes:
- **A global `security` while some endpoints allow anonymous access** (`[AllowAnonymous]`, public
  Express routes). Those endpoints get flagged as critical. Mark them with `security: []`.
- **No `security` at all**, even though the API uses JWT. Nothing gets auth-tested.

Also document `401` and `403` responses on every secured operation.

### 2.3 Document every response status the endpoint can return

```yaml
responses:
  "200": { description: OK, content: { application/json: { schema: { $ref: "#/components/schemas/Order" } } } }
  "400": { description: Validation failed, content: { application/problem+json: { schema: { $ref: "#/components/schemas/ValidationProblem" } } } }
  "401": { description: Not authenticated }
  "403": { description: Not allowed }
  "404": { description: Order not found, content: { application/problem+json: { schema: { $ref: "#/components/schemas/Problem" } } } }
```

- Don't document `500`. A 500 is always a bug and sprat reports it as one.
- Avoid `default:` as a catch-all for everything; it hides undocumented statuses.
- Use one shared error schema (RFC 7807 Problem Details) for every error.

### 2.4 Response schemas: precise types

Every 2xx response with a body needs a schema. Be strict:

```yaml
Order:
  type: object
  additionalProperties: false            # extra/leaked fields become findings
  required: [id, status, total, createdAt]   # list every field that is always present
  properties:
    id:        { type: string, format: uuid }
    status:    { type: string, enum: [pending, paid, shipped, cancelled] }
    total:     { type: number, minimum: 0 }
    currency:  { type: string, pattern: "^[A-Z]{3}$" }
    createdAt: { type: string, format: date-time }
    note:      { type: [string, "null"], maxLength: 500 }   # 3.1; in 3.0 use  type: string, nullable: true
```

- **`required`**: list the fields that are always in the response. Without it, a missing field is invisible.
- **Nullability**: if a field can be `null`, say so. Otherwise every null is a finding, and if you
  mark it nullable when it never is, you lose a check.
- **`additionalProperties: false`** on response objects catches leaked internal fields
  (`passwordHash`, `internalNotes`). Only add it if the server really never sends extra fields.
- **`format`**: `uuid`, `date-time`, `date`, `email`, `uri`, `int32`, `int64`. They're checked
  and also used to generate valid IDs.
- **`enum`** for every fixed set of values. Serialize enums as **strings**, not numbers.
- Money: `type: number` or a decimal-as-string. Be consistent across the API.

### 2.5 Request constraints: describe what the server really validates

Schemathesis sends invalid data and checks that the server rejects it with 4xx. It also sends
valid data and checks that the server accepts it. Both checks depend on the constraints.

```yaml
CreateOrder:
  type: object
  additionalProperties: false
  required: [productId, quantity]
  properties:
    productId: { type: string, format: uuid }
    quantity:  { type: integer, minimum: 1, maximum: 100 }
    note:      { type: string, maxLength: 500 }
```

- Every constraint in the spec must be **enforced by the server**. If the spec says
  `minimum: 1` and the server accepts 0, you get "API accepted schema-violating request".
- Every rule the server enforces should be **in the spec**. If the server rejects
  quantities over 100 but the spec doesn't say so, valid-looking inputs get 400 and are reported.
- Mark required query and header parameters `required: true`.

### 2.6 Parameters

```yaml
parameters:
  - name: orderId
    in: path
    required: true
    schema: { type: string, format: uuid }
  - name: page
    in: query
    schema: { type: integer, minimum: 1, default: 1 }
```

Give every path parameter a type and `format`. sprat uses them to build probe URLs: a uuid
parameter gets a uuid, not `1`.

### 2.7 Examples for important values

Fuzzing is random, so specific values (an ID that triggers a special code path, a boundary)
are rarely hit. Add examples:

```yaml
quantity: { type: integer, minimum: 1, maximum: 100, examples: [1, 100] }    # 3.1
```

or at the operation level with `examples:` under the media type. Examples are sent as-is in
Schemathesis's examples phase, so **examples must be valid** against their own schema (`lint`
checks this).

### 2.8 Links: let sprat chain requests

Without links, every request uses random IDs, so most `GET /orders/{id}` calls return 404.
Links tell the tester to take the ID from a create response and use it in later calls:

```yaml
/orders:
  post:
    operationId: createOrder
    responses:
      "201":
        description: Created
        content: { application/json: { schema: { $ref: "#/components/schemas/Order" } } }
        links:
          GetOrder:    { operationId: getOrder,    parameters: { orderId: "$response.body#/id" } }
          CancelOrder: { operationId: cancelOrder, parameters: { orderId: "$response.body#/id" } }
/orders/{orderId}:
  get:    { operationId: getOrder, ... }
  delete: { operationId: cancelOrder, ... }
```

Add links for your main resources at least.

### 2.9 Naming and metadata (keeps `lint` clean)

- A unique `operationId` on every operation, in camelCase: `getOrder`, `createOrder`.
- `summary` and `tags` on every operation; `description` on `info`.
- `info.contact` with the owning team.
- Mark old endpoints with `deprecated: true` instead of leaving them undocumented.

### 2.10 What a spec can't describe

**Ownership.** The spec can say an endpoint needs a token, but not that the order must belong
to that token's user. Configure cross-user (BOLA) checks in the sprat config:

```yaml
bola:
  - { method: GET, path: "/orders/{orderId}", params: { orderId: "<an order owned by user A>" } }
```

Each team should keep two test users and a handful of user-A-owned resource IDs on staging.

---

## 3. ASP.NET Core

Applies to Swashbuckle 6.x. Swashbuckle 7+ and `Microsoft.AspNetCore.OpenApi` (.NET 9+) use the
same ideas with slightly different type names.

### 3.1 Setup

```csharp
builder.Services.AddControllers()
    .AddJsonOptions(o => o.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter())); // enums as strings

builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Orders API", Version = "v1",
        Contact = new OpenApiContact { Name = "Orders team" } });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.Http, Scheme = "bearer", BearerFormat = "JWT"
    });
    c.OperationFilter<AuthorizeOperationFilter>();   // per-endpoint security, see 3.2

    c.SupportNonNullableReferenceTypes();            // string vs string? becomes nullable in the spec
    c.NonNullableReferenceTypesAsRequired();         // non-nullable properties become "required"
    c.EnableAnnotations();                           // [SwaggerOperation], [SwaggerSchema]
});
```

Enable nullable reference types in the `.csproj` (`<Nullable>enable</Nullable>`) and model
optional fields as `string?`, otherwise nullability in the spec will be wrong.

### 3.2 Per-endpoint security (don't use a global `AddSecurityRequirement`)

A global requirement marks `[AllowAnonymous]` endpoints as secured, and sprat will flag them.
Use a filter that reads the real authorization metadata:

```csharp
public class AuthorizeOperationFilter : IOperationFilter
{
    public void Apply(OpenApiOperation operation, OperationFilterContext context)
    {
        var meta = context.ApiDescription.ActionDescriptor.EndpointMetadata;
        bool requiresAuth = meta.OfType<IAuthorizeData>().Any() && !meta.OfType<IAllowAnonymous>().Any();
        if (!requiresAuth)
        {
            operation.Security = new List<OpenApiSecurityRequirement>();   // emits security: []
            return;
        }
        operation.Responses.TryAdd("401", new OpenApiResponse { Description = "Not authenticated" });
        operation.Responses.TryAdd("403", new OpenApiResponse { Description = "Not allowed" });
        operation.Security = new List<OpenApiSecurityRequirement>
        {
            new()
            {
                [new OpenApiSecurityScheme
                {
                    Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer" }
                }] = Array.Empty<string>()
            }
        };
    }
}
```

If you use a global `FallbackPolicy` (all endpoints require auth unless `[AllowAnonymous]`),
`IAuthorizeData` won't be present. Change the condition to `!meta.OfType<IAllowAnonymous>().Any()`.

### 3.3 Controllers

```csharp
[ApiController]
[Route("api/orders")]
[Authorize]
public class OrdersController : ControllerBase
{
    [HttpGet("{orderId:guid}", Name = "getOrder")]
    [ProducesResponseType<OrderDto>(StatusCodes.Status200OK)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<OrderDto>> Get(Guid orderId) { ... }

    [HttpPost(Name = "createOrder")]
    [ProducesResponseType<OrderDto>(StatusCodes.Status201Created)]
    [ProducesResponseType<ValidationProblemDetails>(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<OrderDto>> Create(CreateOrderDto dto) { ... }
}
```

- **One `[ProducesResponseType]` per status** the action can return, including 400 (`[ApiController]`
  returns it automatically on model validation) and 404.
- Use `Name = "..."` or `[SwaggerOperation(OperationId = "...")]` for stable operationIds.
- Use route constraints (`{orderId:guid}`, `{id:int}`); they become the parameter type.
- Return `ProblemDetails` for every error (`builder.Services.AddProblemDetails()`).

### 3.4 DTOs: put validation on the model

```csharp
public sealed class CreateOrderDto
{
    [Required] public Guid ProductId { get; init; }
    [Range(1, 100)] public int Quantity { get; init; }
    [StringLength(500)] public string? Note { get; init; }
}
```

`[Required]`, `[Range]`, `[StringLength]`, `[MinLength]`, `[RegularExpression]`, `[EmailAddress]`
become spec constraints **and** are enforced by `[ApiController]`, so the spec and server match
automatically. Validation done only in service code (FluentValidation, manual `if` checks) is
invisible to the spec. Mirror those rules with attributes, or use a FluentValidation-to-Swagger
package such as `MicroElements.Swashbuckle.FluentValidation`.

Never return EF entities directly. Return DTOs, so internal fields can't leak and the schema is stable.

---

## 4. Express / Node

Hand-written JSDoc specs drift from the code. Prefer one of these, in order:

1. **Generate the spec from validation schemas** (Zod + `@asteasolutions/zod-to-openapi`, or tsoa,
   or NestJS `@nestjs/swagger`). The spec and validation come from one source.
2. **Spec first + `express-openapi-validator`**: write the YAML, and the middleware rejects requests
   that don't match it (and can validate responses in staging).
3. `swagger-jsdoc` comments: acceptable, but every rule in sections 2.2–2.6 must be maintained by hand.

### 4.1 Zod + zod-to-openapi

```ts
import { z } from "zod";
import { extendZodWithOpenApi, OpenAPIRegistry, OpenApiGeneratorV31 } from "@asteasolutions/zod-to-openapi";
extendZodWithOpenApi(z);

const registry = new OpenAPIRegistry();
const bearerAuth = registry.registerComponent("securitySchemes", "bearerAuth",
  { type: "http", scheme: "bearer", bearerFormat: "JWT" });

const Order = registry.register("Order", z.object({
  id: z.string().uuid(),
  status: z.enum(["pending", "paid", "shipped", "cancelled"]),
  total: z.number().min(0),
  note: z.string().max(500).nullable(),
}).strict());

const CreateOrder = z.object({
  productId: z.string().uuid(),
  quantity: z.number().int().min(1).max(100),
}).strict();

registry.registerPath({
  method: "post", path: "/orders", operationId: "createOrder", tags: ["orders"],
  summary: "Create an order",
  security: [{ [bearerAuth.name]: [] }],
  request: { body: { content: { "application/json": { schema: CreateOrder } } } },
  responses: {
    201: { description: "Created", content: { "application/json": { schema: Order } } },
    400: { description: "Validation failed" },
    401: { description: "Not authenticated" },
  },
});

// Use the same schema to validate in the route, so spec and behavior can't diverge:
app.post("/orders", requireAuth, (req, res) => {
  const parsed = CreateOrder.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ title: "Validation failed", errors: parsed.error.issues });
  // ...
});

app.get("/swagger.json", (_req, res) =>
  res.json(new OpenApiGeneratorV31(registry.definitions).generateDocument({
    openapi: "3.1.0", info: { title: "Orders API", version: "1.0.0" }, servers: [{ url: "/" }],
  })));
```

### 4.2 Express-specific rules

- **Public routes need `security: []`** if you set a global `security`.
- Express returns its own HTML 404 and 500 pages by default. Add a JSON error handler, and
  document the JSON error shape.
- Don't leak stack traces: in the error handler, never send `err.stack` outside development.
  sprat reports stack traces in responses.
- Set `helmet()`: it adds `X-Content-Type-Options` and other headers sprat checks for.
- Validate `req.params` and `req.query`, not only the body. Express gives you strings, so
  `/orders/abc` must return 400, not 500.
- **Unsupported methods must return 405, not 404.** If `/orders` only has GET, then `DELETE /orders`
  should get `405 Method Not Allowed` with an `Allow: GET, HEAD, OPTIONS` header. Express doesn't do
  this by itself, and it often answers 404 (or a catch-all/gateway route swallows the request).
  Mount this after every route and before any catch-all or 404 handler:

  ```ts
  // Known path + unsupported method -> 405 with Allow (RFC 9110 §15.5.6). Express 4.
  export function methodNotAllowedHandler(app: Express): RequestHandler {
    return (req, res, next) => {
      const methods = new Set<string>();
      for (const layer of (app as any)._router?.stack ?? []) {
        if (!layer.route || !layer.regexp?.test(req.path)) continue;
        if (layer.route.methods._all) return next();
        for (const [m, on] of Object.entries(layer.route.methods)) if (on) methods.add(m.toUpperCase());
      }
      if (methods.size === 0 || methods.has(req.method)) return next(); // unknown path or allowed
      if (methods.has("GET")) methods.add("HEAD");
      methods.add("OPTIONS");
      const allowed = [...methods].sort();
      res.setHeader("Allow", allowed.join(", "));
      res.status(405).type("application/problem+json").json({
        type: "about:blank", title: "Method Not Allowed", status: 405,
        detail: `${req.method} is not supported for ${req.path}`, allowed,
      });
    };
  }
  // routes.ts: register all routes, then
  app.use(methodNotAllowedHandler(app));
  // ...then catch-alls / notFoundHandler
  ```

  ASP.NET Core's endpoint
  routing already answers 405 when a route matches with another method; check that a
  `MapFallback` or catch-all route isn't turning it into 404.

---

## 5. Checklist

Every item below maps to a check sprat runs.

- [ ] OpenAPI 3.0/3.1, served at a stable URL in each environment, with `servers` set
- [ ] Security scheme defined; every operation is explicitly secured, public (`security: []`) or optional
- [ ] Secured operations document 401 and 403
- [ ] Every status an operation returns is documented (no 500, no catch-all `default`)
- [ ] Every 2xx body has a schema with `required`, correct nullability, `format`, `enum`
- [ ] Response objects use `additionalProperties: false` where the server never adds fields
- [ ] Request bodies list all constraints the server enforces, and the server enforces all constraints listed
- [ ] Path and query parameters have types and formats; required ones are marked
- [ ] One shared error schema (Problem Details) for all 4xx responses
- [ ] An HTTP method a path doesn't support returns 405 with an `Allow` header, not 404
- [ ] Unique camelCase `operationId`, plus `summary` and `tags`, on every operation
- [ ] `links` from create operations to read/update/delete of the same resource
- [ ] Examples for boundary values, and they validate against their schema
- [ ] Two staging test users plus BOLA entries in the sprat config

## 6. What each sprat finding usually means

| Finding | Usual fix |
|---|---|
| `Undocumented HTTP status code` | Add that status to `responses` (`[ProducesResponseType]` in .NET) |
| `Response violates schema` | The code or the schema is wrong. Fix whichever doesn't match reality (often nullability or a number sent as a string) |
| `API accepted schema-violating request` | The server doesn't enforce a constraint the spec declares. Add validation, or remove the constraint |
| `API rejected schema-compliant request` | The server enforces a rule the spec doesn't declare. Add it to the spec |
| `Server error` | A real bug. Usually unvalidated input reaching the database or a null dereference |
| `Secured endpoint accepted no/invalid credentials` | Missing `[Authorize]` or middleware, **or** a public endpoint missing `security: []` |
| `BOLA: user B accessed user A's resource` | Add an ownership check: filter by the current user's ID in the query |
| `Error response leaks stack trace` | Use a production error handler (`UseExceptionHandler` / an Express error middleware) |
| `Missing security header` | `app.UseHsts()` plus header middleware in .NET; `helmet()` in Express |
| `Unsupported methods don't get 405` ("answered … with HTTP 404; the standard answer is 405") | Express: the 405 middleware in section 4.2. .NET: look for a fallback/catch-all route swallowing it |
| Many `lint` warnings | Section 2.9 |
