# Examples

## Factory Pattern

Use `defineUrAuth()` to create all utilities from a single `Auth` instance:

```typescript
import { Auth } from "@urauth/node";
import { defineUrAuth } from "@urauth/h3";

const auth = new Auth({
  secretKey: process.env.AUTH_SECRET!,
  algorithm: "HS256",
  issuer: "my-app",
  accessTokenTtl: 900,
  refreshTokenTtl: 604800,
});

const {
  onRequest,
  requireAuth,
  requirePermission,
  requireRole,
  requireGuard,
  requireTenant,
  requirePolicy,
  authRoutes,
} = defineUrAuth(auth);
```

## Token Transport

### Bearer Token (Default)

```typescript
const handler = createOnRequest(auth, { transport: "bearer" });
```

### Cookie Transport

```typescript
const handler = createOnRequest(auth, {
  transport: "cookie",
  cookieName: "access_token",
});
```

### Hybrid Transport

```typescript
const handler = createOnRequest(auth, {
  transport: "hybrid",
  cookieName: "access_token",
});
```

## Optional Authentication

```typescript
const handler = createOnRequest(auth, { optional: true });

// event.context.auth is always available — either authenticated or anonymous
export default defineEventHandler((event) => {
  if (event.context.auth.isAuthenticated()) {
    return { message: `Hello, ${event.context.auth.user.name}` };
  }
  return { message: "Hello, guest" };
});
```

## Guards

### Authentication Guard

```typescript
export default defineEventHandler({
  onRequest: [requireAuth()],
  handler: (event) => event.context.auth.user,
});
```

### Permission Guard

```typescript
export default defineEventHandler({
  onRequest: [requirePermission("post", "write")],
  handler: async (event) => {
    const body = await readBody(event);
    // Create post...
  },
});
```

### Role Guard

```typescript
export default defineEventHandler({
  onRequest: [requireRole("admin")],
  handler: () => ({ users: [] }),
});
```

### Composite Requirements

```typescript
import { requireGuard } from "@urauth/h3";
import { Permission, Role, allOf, anyOf } from "@urauth/ts";

// Must have BOTH
export default defineEventHandler({
  onRequest: [requireGuard(
    allOf(new Permission("post", "write"), new Role("editor"))
  )],
  handler: async (event) => { /* ... */ },
});

// Must have EITHER
export default defineEventHandler({
  onRequest: [requireGuard(
    anyOf(new Permission("report", "read"), new Role("admin"))
  )],
  handler: () => ({ reports: [] }),
});
```

### Tenant Guard

```typescript
export default defineEventHandler({
  onRequest: [requireTenant({ level: "organization" })],
  handler: (event) => ({ tenantId: event.context.auth.tenantId }),
});
```

### Custom Policy Guard

```typescript
export default defineEventHandler({
  onRequest: [requirePolicy((ctx) => {
    return ctx.isAuthenticated() && ctx.hasPermission("post:write");
  })],
  handler: async (event) => { /* ... */ },
});
```

## Auth Routes

```typescript
import { authRoutes } from "@urauth/h3";

app.use("/auth", authRoutes(auth));
// POST /auth/login        — { username, password } → { accessToken, refreshToken, tokenType }
// POST /auth/refresh      — { refreshToken } → { accessToken, refreshToken, tokenType }
// POST /auth/logout       — Revokes current token
// POST /auth/logout-all   — Revokes all user tokens
```

## Nuxt Integration

### Server Middleware

```typescript
// ~/server/utils/auth.ts
import { Auth } from "@urauth/node";

export const auth = new Auth({
  secretKey: useRuntimeConfig().authSecret,
  algorithm: "HS256",
  issuer: "my-app",
  accessTokenTtl: 900,
  refreshTokenTtl: 604800,
});
```

```typescript
// ~/server/middleware/auth.ts
import { createOnRequest } from "@urauth/h3";
import { auth } from "~/server/utils/auth";

export default createOnRequest(auth, { optional: true });
```

### Protected API Routes

```typescript
// ~/server/api/posts.get.ts
import { requirePermission } from "@urauth/h3";

export default defineEventHandler({
  onRequest: [requirePermission("post", "read")],
  handler: () => ({ posts: [] }),
});
```

```typescript
// ~/server/api/posts.post.ts
import { requirePermission } from "@urauth/h3";

export default defineEventHandler({
  onRequest: [requirePermission("post", "write")],
  handler: async (event) => {
    const body = await readBody(event);
    // Create post...
    return { created: true };
  },
});
```

```typescript
// ~/server/api/admin/users.get.ts
import { requireRole } from "@urauth/h3";

export default defineEventHandler({
  onRequest: [requireRole("admin")],
  handler: () => ({ users: [] }),
});
```

### Nitro Plugin

For centralized setup including auth routes:

```typescript
// ~/server/plugins/auth.ts
import { createUrAuthNitroPlugin } from "@urauth/h3";
import { auth } from "~/server/utils/auth";

export default createUrAuthNitroPlugin({
  auth,
  routes: { prefix: "/api/auth" },
  transport: "hybrid",
  cookieName: "access_token",
});
```

## Full Standalone Application

```typescript
import { createApp, createRouter, defineEventHandler, toNodeListener } from "h3";
import { createServer } from "http";
import { Auth } from "@urauth/node";
import { defineUrAuth } from "@urauth/h3";
import { Permission, Role, allOf } from "@urauth/ts";

const auth = new Auth({
  secretKey: process.env.AUTH_SECRET!,
  algorithm: "HS256",
  issuer: "my-app",
  accessTokenTtl: 900,
  refreshTokenTtl: 604800,
});

const ua = defineUrAuth(auth);

const app = createApp({ onRequest: [ua.onRequest({ optional: true })] });
const router = createRouter();

// Public
router.get("/health", defineEventHandler(() => ({ ok: true })));

// Protected
router.get("/me", defineEventHandler({
  onRequest: [ua.requireAuth()],
  handler: (event) => event.context.auth.user,
}));

// Permission-based
router.get("/posts", defineEventHandler({
  onRequest: [ua.requirePermission("post", "read")],
  handler: () => ({ posts: [] }),
}));

router.post("/posts", defineEventHandler({
  onRequest: [ua.requirePermission("post", "write")],
  handler: async (event) => ({ created: true }),
}));

// Role-based
router.get("/admin/users", defineEventHandler({
  onRequest: [ua.requireRole("admin")],
  handler: () => ({ users: [] }),
}));

app.use(router);
app.use("/auth", ua.authRoutes());

createServer(toNodeListener(app)).listen(3000);
```
