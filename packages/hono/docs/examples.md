# Examples

## Middleware Setup

The middleware resolves auth context and stores it in `c.get("auth")`:

```typescript
import { Hono } from "hono";
import { Auth } from "@urauth/node";
import { urAuthMiddleware } from "@urauth/hono";

const auth = new Auth({
  secretKey: process.env.AUTH_SECRET!,
  algorithm: "HS256",
  issuer: "my-app",
  accessTokenTtl: 900,
  refreshTokenTtl: 604800,
});

const app = new Hono();
app.use("*", urAuthMiddleware(auth));
```

## Token Transport

### Bearer Token (Default)

```typescript
app.use("*", urAuthMiddleware(auth, { transport: "bearer" }));
```

### Cookie Transport

```typescript
app.use("*", urAuthMiddleware(auth, {
  transport: "cookie",
  cookieName: "access_token",
}));
```

### Hybrid Transport

```typescript
app.use("*", urAuthMiddleware(auth, {
  transport: "hybrid",
  cookieName: "access_token",
}));
```

## Optional Authentication

```typescript
app.use("*", urAuthMiddleware(auth, { optional: true }));

app.get("/posts", (c) => {
  const authCtx = c.get("auth");
  if (authCtx.isAuthenticated()) {
    return c.json({ posts: getPersonalizedPosts(authCtx.user) });
  }
  return c.json({ posts: getPublicPosts() });
});
```

## Guards

### Permission Guard

```typescript
import { guard, guardPermission } from "@urauth/hono";
import { Permission } from "@urauth/ts";

// Using guard() with a Permission requirement
app.get("/posts", guard(auth, new Permission("post", "read")), handler);

// Using guardPermission() shorthand
app.post("/posts", guardPermission(auth, "post", "write"), handler);
```

### Role Guard

```typescript
import { guardRole } from "@urauth/hono";

app.get("/admin", guardRole(auth, "admin"), (c) => {
  return c.json({ message: "Admin only" });
});
```

### Composite Requirements

```typescript
import { guard } from "@urauth/hono";
import { Permission, Role, allOf, anyOf } from "@urauth/ts";

// Must have BOTH
app.put("/posts/:id", guard(auth,
  allOf(new Permission("post", "write"), new Role("editor"))
), handler);

// Must have EITHER
app.get("/reports", guard(auth,
  anyOf(new Permission("report", "read"), new Role("admin"))
), handler);
```

### Tenant Guard

```typescript
import { guardTenant } from "@urauth/hono";

app.get("/org/settings", guardTenant(auth, { level: "organization" }), handler);
```

### Custom Policy Guard

```typescript
import { guardPolicy } from "@urauth/hono";

app.post("/posts", guardPolicy(auth, (ctx) => {
  return ctx.isAuthenticated() && ctx.hasPermission("post:write");
}), handler);
```

## Auth Routes

```typescript
import { authRoutes } from "@urauth/hono";

app.route("/auth", authRoutes(auth));
// POST /auth/login        — { username, password } → { accessToken, refreshToken, tokenType }
// POST /auth/refresh      — { refreshToken } → { accessToken, refreshToken, tokenType }
// POST /auth/logout       — Revokes current token
// POST /auth/logout-all   — Revokes all user tokens
```

The router includes a built-in error handler for `AuthError` subclasses.

## Type Safety with UrAuthEnv

For full type safety, use the `UrAuthEnv` type:

```typescript
import type { UrAuthEnv } from "@urauth/hono";

const app = new Hono<UrAuthEnv>();

app.use("*", urAuthMiddleware(auth));

// c.get("auth") is now fully typed as AuthContext
app.get("/me", (c) => {
  const authCtx = c.get("auth"); // AuthContext
  return c.json(authCtx.user);
});
```

## Cloudflare Workers

```typescript
import { Hono } from "hono";
import { Auth } from "@urauth/node";
import { urAuthMiddleware, guard, authRoutes } from "@urauth/hono";
import { Permission } from "@urauth/ts";

type Env = {
  Bindings: {
    AUTH_SECRET: string;
  };
};

const app = new Hono<Env>();

app.use("*", async (c, next) => {
  const auth = new Auth({
    secretKey: c.env.AUTH_SECRET,
    algorithm: "HS256",
    issuer: "my-app",
    accessTokenTtl: 900,
    refreshTokenTtl: 604800,
  });

  const mw = urAuthMiddleware(auth, { optional: true });
  return mw(c, next);
});

export default app;
```

## Full Application

```typescript
import { Hono } from "hono";
import { Auth } from "@urauth/node";
import {
  urAuthMiddleware,
  guard,
  protect,
  guardPermission,
  guardRole,
  authRoutes,
} from "@urauth/hono";
import { Permission, Role } from "@urauth/ts";

const auth = new Auth({
  secretKey: process.env.AUTH_SECRET!,
  algorithm: "HS256",
  issuer: "my-app",
  accessTokenTtl: 900,
  refreshTokenTtl: 604800,
});

const app = new Hono();

// Global middleware
app.use("*", urAuthMiddleware(auth, { optional: true }));

// Public
app.get("/health", (c) => c.json({ ok: true }));

// Auth
app.route("/auth", authRoutes(auth));

// Protected
app.get("/me", protect(auth), (c) => c.json(c.get("auth").user));

// Permission-based
app.get("/posts", guardPermission(auth, "post", "read"), (c) => c.json({ posts: [] }));
app.post("/posts", guardPermission(auth, "post", "write"), (c) => c.json({ created: true }));

// Role-based
app.get("/admin/users", guardRole(auth, "admin"), (c) => c.json({ users: [] }));

export default app;
```
