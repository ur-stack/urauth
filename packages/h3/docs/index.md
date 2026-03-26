# @urauth/h3

H3/Nitro middleware for urAuth. Adds JWT verification, permission guards, and auth routes to H3 event handlers and Nuxt server routes.

## Installation

```bash
pnpm add @urauth/h3
```

## Peer Dependencies

- `h3` >= 1.0.0
- `@urauth/node`
- `@urauth/ts`

## What's Included

| Export | Description |
|--------|-------------|
| [`defineUrAuth`](./reference#defineurauth) | Factory that creates all H3 utilities from an `Auth` instance |
| [`createUrAuthNitroPlugin`](./reference#createurauthnritroplugin) | Nitro plugin for Nuxt server integration |
| [`createOnRequest`](./reference#createonrequest) | onRequest handler that resolves `event.context.auth` |
| [`requireAuth`](./reference#requireauth) | Guard for authentication only |
| [`requirePermission`](./reference#requirepermission) | Guard for a specific resource/action |
| [`requireRole`](./reference#requirerole) | Guard for a specific role |
| [`requireGuard`](./reference#requireguard) | Guard for a `Requirement` |
| [`requireTenant`](./reference#requiretenant) | Guard for tenant membership |
| [`requirePolicy`](./reference#requirepolicy) | Guard with custom logic |
| [`authRoutes`](./reference#authroutes) | H3 router with login, refresh, logout endpoints |

## Quick Start

### Standalone H3

```typescript
import { createApp, createRouter, defineEventHandler, toNodeListener } from "h3";
import { createServer } from "http";
import { Auth } from "@urauth/node";
import { defineUrAuth } from "@urauth/h3";
import { Permission, Role } from "@urauth/ts";

const auth = new Auth({
  secretKey: process.env.AUTH_SECRET!,
  algorithm: "HS256",
  issuer: "my-app",
  accessTokenTtl: 900,
  refreshTokenTtl: 604800,
});

const { onRequest, requireAuth, requirePermission, authRoutes } = defineUrAuth(auth);

const app = createApp({ onRequest: [onRequest({ optional: true })] });
const router = createRouter();

router.get("/me", defineEventHandler({
  onRequest: [requireAuth()],
  handler: (event) => event.context.auth.user,
}));

router.get("/posts", defineEventHandler({
  onRequest: [requirePermission("post", "read")],
  handler: () => ({ posts: [] }),
}));

app.use(router);
app.use("/auth", authRoutes());

createServer(toNodeListener(app)).listen(3000);
```

### Nuxt Server Routes

```typescript
// ~/server/middleware/auth.ts
import { createOnRequest } from "@urauth/h3";
import { auth } from "~/server/utils/auth";

export default createOnRequest(auth, { optional: true });
```

```typescript
// ~/server/api/posts.get.ts
import { requirePermission } from "@urauth/h3";

export default defineEventHandler({
  onRequest: [requirePermission("post", "read")],
  handler: () => ({ posts: [] }),
});
```

## Next Steps

- [Examples](./examples) — Detailed usage patterns for H3 and Nuxt.
- [API Reference](./reference) — Full API surface listing.
- [Security Best Practices](./security) — Hardening your H3 auth setup.
