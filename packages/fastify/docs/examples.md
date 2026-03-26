# Examples

## Plugin Registration

The plugin decorates both `request.auth` (per-request auth context) and `app.auth` (guard factories):

```typescript
import Fastify from "fastify";
import { Auth } from "@urauth/node";
import { urAuthPlugin } from "@urauth/fastify";

const auth = new Auth({
  secretKey: process.env.AUTH_SECRET!,
  algorithm: "HS256",
  issuer: "my-app",
  accessTokenTtl: 900,
  refreshTokenTtl: 604800,
});

const app = Fastify();
await app.register(urAuthPlugin, { auth });
```

## Token Transport

### Bearer Token (Default)

```typescript
await app.register(urAuthPlugin, {
  auth,
  transport: "bearer",
});
```

### Cookie Transport

```typescript
await app.register(urAuthPlugin, {
  auth,
  transport: "cookie",
  cookieName: "access_token",
});
```

### Hybrid Transport

Tries bearer first, falls back to cookie:

```typescript
await app.register(urAuthPlugin, {
  auth,
  transport: "hybrid",
  cookieName: "access_token",
});
```

## Route-Level Auth Config

Fastify supports route-level configuration via `config.auth`:

```typescript
// Make auth optional for a specific route
app.get("/public", {
  config: { auth: { optional: true } },
  handler: (request) => {
    if (request.auth.isAuthenticated()) {
      return { message: `Hello, ${request.auth.user.name}` };
    }
    return { message: "Hello, guest" };
  },
});

// Require a specific permission at the route level
app.get("/admin", {
  config: {
    auth: { require: new Role("admin") },
  },
  handler: () => ({ message: "Admin only" }),
});
```

## Guards via Decorators

The plugin decorates `app.auth` with guard factories. Use them as `preHandler` hooks:

```typescript
// Authentication only
app.get("/me", {
  preHandler: [app.auth.protect()],
  handler: (request) => request.auth.user,
});

// Requirement guard
app.get("/posts", {
  preHandler: [app.auth.guard(new Permission("post", "read"))],
  handler: () => ({ posts: [] }),
});

// Tenant guard
app.get("/org/settings", {
  preHandler: [app.auth.tenant({ level: "organization" })],
  handler: (request) => ({ tenantId: request.auth.tenantId }),
});

// Custom policy
app.post("/posts", {
  preHandler: [app.auth.policy((ctx) => {
    return ctx.isAuthenticated() && ctx.hasPermission("post:write");
  })],
  handler: async (request) => {
    // Create post
  },
});
```

## Composite Requirements

```typescript
import { Permission, Role, allOf, anyOf } from "@urauth/ts";

app.put("/posts/:id", {
  preHandler: [app.auth.guard(
    allOf(new Permission("post", "write"), new Role("editor"))
  )],
  handler: async (request) => {
    // Update post
  },
});

app.get("/reports", {
  preHandler: [app.auth.guard(
    anyOf(new Permission("report", "read"), new Role("admin"))
  )],
  handler: () => ({ reports: [] }),
});
```

## Auth Routes

```typescript
import { urAuthRoutes } from "@urauth/fastify";

await app.register(urAuthRoutes, { auth, prefix: "/auth" });
// POST /auth/login        — { username, password } → { accessToken, refreshToken, tokenType }
// POST /auth/refresh      — { refreshToken } → { accessToken, refreshToken, tokenType }
// POST /auth/logout       — Revokes current token
// POST /auth/logout-all   — Revokes all user tokens
```

## Standalone Guards (Without Plugin)

You can use guard functions directly without the app decorator:

```typescript
import { createGuard, createProtect, createTenantGuard } from "@urauth/fastify";
import { Permission } from "@urauth/ts";

app.get("/posts", {
  preHandler: [createGuard(new Permission("post", "read"))],
  handler: () => ({ posts: [] }),
});
```

## Full Application

```typescript
import Fastify from "fastify";
import { Auth } from "@urauth/node";
import { urAuthPlugin, urAuthRoutes } from "@urauth/fastify";
import { Permission, Role, allOf } from "@urauth/ts";

const auth = new Auth({
  secretKey: process.env.AUTH_SECRET!,
  algorithm: "HS256",
  issuer: "my-app",
  accessTokenTtl: 900,
  refreshTokenTtl: 604800,
});

const app = Fastify({ logger: true });

// Plugins
await app.register(urAuthPlugin, { auth, transport: "hybrid", cookieName: "access_token" });
await app.register(urAuthRoutes, { auth, prefix: "/auth" });

// Public
app.get("/health", () => ({ ok: true }));

// Protected
app.get("/me", {
  preHandler: [app.auth.protect()],
  handler: (request) => request.auth.user,
});

// Permission-based
app.get("/posts", {
  preHandler: [app.auth.guard(new Permission("post", "read"))],
  handler: () => ({ posts: [] }),
});

app.post("/posts", {
  preHandler: [app.auth.guard(new Permission("post", "write"))],
  handler: async (request) => ({ created: true }),
});

// Role-based
app.get("/admin/users", {
  preHandler: [app.auth.guard(new Role("admin"))],
  handler: () => ({ users: [] }),
});

app.listen({ port: 3000 });
```
