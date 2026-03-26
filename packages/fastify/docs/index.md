# @urauth/fastify

Fastify plugin for urAuth. Registers auth context resolution, permission guards, and auth routes as a native Fastify plugin with full type support.

## Installation

```bash
pnpm add @urauth/fastify
```

## Peer Dependencies

- `fastify` >= 4.0.0
- `fastify-plugin` >= 5.0.0
- `@urauth/node`
- `@urauth/ts`

## What's Included

| Export | Description |
|--------|-------------|
| [`urAuthPlugin`](./reference#urauthplugin) | Fastify plugin — decorates `request.auth` and `app.auth` |
| [`createGuard`](./reference#createguard) | PreHandler hook for requirement checks |
| [`createProtect`](./reference#createprotect) | PreHandler hook for authentication only |
| [`createTenantGuard`](./reference#createtenantguard) | PreHandler hook for tenant checks |
| [`createPolicyGuard`](./reference#createpolicyguard) | PreHandler hook for custom policies |
| [`urAuthRoutes`](./reference#urauthroutes) | Plugin with login, refresh, logout routes |

## Quick Start

```typescript
import Fastify from "fastify";
import { Auth } from "@urauth/node";
import { urAuthPlugin, urAuthRoutes } from "@urauth/fastify";
import { Permission, Role } from "@urauth/ts";

const auth = new Auth({
  secretKey: process.env.AUTH_SECRET!,
  algorithm: "HS256",
  issuer: "my-app",
  accessTokenTtl: 900,
  refreshTokenTtl: 604800,
});

const app = Fastify();

// Register plugin — resolves auth context on every request
await app.register(urAuthPlugin, { auth });

// Register auth routes: POST /auth/login, /auth/refresh, etc.
await app.register(urAuthRoutes, { auth, prefix: "/auth" });

// Protected route with guard
app.get("/me", {
  preHandler: [app.auth.protect()],
  handler: (request) => request.auth.user,
});

// Permission-based route
app.get("/posts", {
  preHandler: [app.auth.guard(new Permission("post", "read"))],
  handler: () => ({ posts: [] }),
});

// Role-based route
app.get("/admin", {
  preHandler: [app.auth.guard(new Role("admin"))],
  handler: () => ({ message: "Admin access" }),
});

app.listen({ port: 3000 });
```

## Next Steps

- [Examples](./examples) — Detailed usage patterns.
- [API Reference](./reference) — Full API surface listing.
- [Security Best Practices](./security) — Hardening your Fastify auth setup.
