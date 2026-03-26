# Examples

## Adapter Pattern

The `expressAuth()` factory is the recommended way to set up auth. It creates all utilities from a single `Auth` instance:

```typescript
import { Auth } from "@urauth/node";
import { expressAuth } from "@urauth/express";

const auth = new Auth({
  secretKey: process.env.AUTH_SECRET!,
  algorithm: "HS256",
  issuer: "my-app",
  accessTokenTtl: 900,
  refreshTokenTtl: 604800,
});

const { middleware, guard, protect, router } = expressAuth(auth);
```

You can also import individual functions:

```typescript
import { createMiddleware, guard, protect, router, errorHandler } from "@urauth/express";
```

## Token Transport

### Bearer Token (Default)

Reads the `Authorization: Bearer <token>` header:

```typescript
app.use(middleware({ transport: "bearer" }));
```

### Cookie Transport

Reads the token from a cookie:

```typescript
app.use(middleware({
  transport: "cookie",
  cookieName: "access_token", // default
}));
```

### Hybrid Transport

Tries bearer header first, falls back to cookie:

```typescript
app.use(middleware({ transport: "hybrid", cookieName: "access_token" }));
```

## Optional Authentication

Allow unauthenticated access — sets an anonymous context instead of throwing:

```typescript
app.use(middleware({ optional: true }));

app.get("/posts", (req, res) => {
  if (req.auth.isAuthenticated()) {
    // Show personalized content
  } else {
    // Show public content
  }
});
```

## Guards

### Permission Guard

```typescript
import { Permission } from "@urauth/ts";

app.get("/posts", guard(new Permission("post", "read")), handler);
app.post("/posts", guard(new Permission("post", "write")), handler);
app.delete("/posts/:id", guard(new Permission("post", "delete")), handler);
```

### Role Guard

```typescript
import { Role } from "@urauth/ts";

app.get("/admin", guard(new Role("admin")), handler);
```

### Composite Requirements

```typescript
import { Permission, Role, allOf, anyOf } from "@urauth/ts";

// Must have BOTH permission AND role
app.put("/posts/:id", guard(
  allOf(new Permission("post", "write"), new Role("editor"))
), handler);

// Must have EITHER permission
app.get("/reports", guard(
  anyOf(new Permission("report", "read"), new Role("admin"))
), handler);
```

### Tenant Guard

```typescript
app.get("/org/settings", guard.tenant({ level: "organization" }), handler);
```

### Custom Policy Guard

```typescript
app.post("/posts", guard.policy((ctx) => {
  // Custom logic — e.g., rate limiting, time-based access
  return ctx.isAuthenticated() && ctx.hasPermission("post:write");
}), handler);
```

## Auth Routes

The `router()` function generates login, refresh, and logout endpoints:

```typescript
app.use("/auth", router());
// POST /auth/login        — { username, password } → { accessToken, refreshToken, tokenType }
// POST /auth/refresh      — { refreshToken } → { accessToken, refreshToken, tokenType }
// POST /auth/logout       — Revokes current token
// POST /auth/logout-all   — Revokes all user tokens
```

Password routes only:

```typescript
app.use("/auth", router.password());
```

## Error Handling

The `errorHandler()` catches `AuthError` subclasses and sends JSON responses:

```typescript
import { errorHandler } from "@urauth/express";

// Must be registered AFTER all routes
app.use(errorHandler());
```

| Error | Status | Response |
|-------|--------|----------|
| `InvalidTokenError` | 401 | `{ error: "..." }` |
| `TokenExpiredError` | 401 | `{ error: "..." }` |
| `UnauthorizedError` | 401 | `{ error: "..." }` |
| `ForbiddenError` | 403 | `{ error: "..." }` |
| `TokenRevokedError` | 401 | `{ error: "..." }` |

## Full Application

```typescript
import express from "express";
import { Auth } from "@urauth/node";
import { expressAuth, errorHandler } from "@urauth/express";
import { Permission, Role } from "@urauth/ts";

const auth = new Auth({
  secretKey: process.env.AUTH_SECRET!,
  algorithm: "HS256",
  issuer: "my-app",
  accessTokenTtl: 900,
  refreshTokenTtl: 604800,
});

const { middleware, guard, protect, router } = expressAuth(auth);
const app = express();

app.use(express.json());
app.use(middleware({ optional: true }));

// Public
app.get("/health", (_req, res) => res.json({ ok: true }));

// Auth
app.use("/auth", router());

// Protected
app.get("/me", protect(), (req, res) => {
  res.json(req.auth.user);
});

// Permission-based
app.get("/posts", guard(new Permission("post", "read")), (req, res) => {
  res.json({ posts: [] });
});

app.post("/posts", guard(new Permission("post", "write")), (req, res) => {
  res.json({ created: true });
});

// Role-based
app.get("/admin/users", guard(new Role("admin")), (req, res) => {
  res.json({ users: [] });
});

// Error handler last
app.use(errorHandler());

app.listen(3000, () => console.log("Listening on :3000"));
```
