# @urauth/hono

Hono middleware for urAuth. Adds JWT verification, permission guards, and auth routes to Hono applications. Works across all Hono runtimes — Cloudflare Workers, Deno, Bun, and Node.js.

## Installation

```bash
pnpm add @urauth/hono
```

## Peer Dependencies

- `hono` >= 4.0.0
- `@urauth/node`
- `@urauth/ts`

## What's Included

| Export | Description |
|--------|-------------|
| [`urAuthMiddleware`](./reference#urauthmiddleware) | Middleware that resolves `c.get("auth")` from the request token |
| [`guard`](./reference#guard) | Guard middleware for requirement checks |
| [`protect`](./reference#protect) | Shorthand for authentication-only guard |
| [`guardPermission`](./reference#guardpermission) | Guard for a specific resource/action |
| [`guardRole`](./reference#guardrole) | Guard for a specific role |
| [`guardTenant`](./reference#guardtenant) | Guard for tenant membership |
| [`guardPolicy`](./reference#guardpolicy) | Guard with custom policy logic |
| [`authRoutes`](./reference#authroutes) | Hono router with login, refresh, logout endpoints |

## Quick Start

```typescript
import { Hono } from "hono";
import { Auth } from "@urauth/node";
import { urAuthMiddleware, guard, protect, authRoutes } from "@urauth/hono";
import { Permission, Role } from "@urauth/ts";

const auth = new Auth({
  secretKey: process.env.AUTH_SECRET!,
  algorithm: "HS256",
  issuer: "my-app",
  accessTokenTtl: 900,
  refreshTokenTtl: 604800,
});

const app = new Hono();

// Resolve auth context on all routes
app.use("*", urAuthMiddleware(auth, { optional: true }));

// Auth endpoints
app.route("/auth", authRoutes(auth));

// Protected routes
app.get("/me", protect(auth), (c) => c.json(c.get("auth").user));

app.get("/posts", guard(auth, new Permission("post", "read")), (c) => {
  return c.json({ posts: [] });
});

app.get("/admin", guard(auth, new Role("admin")), (c) => {
  return c.json({ message: "Admin access" });
});

export default app;
```

## Next Steps

- [Examples](./examples) — Detailed usage patterns.
- [API Reference](./reference) — Full API surface listing.
- [Security Best Practices](./security) — Hardening your Hono auth setup.
