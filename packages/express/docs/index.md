# @urauth/express

Express middleware for urAuth. Adds JWT verification, permission guards, auth routes, and error handling to Express applications.

## Installation

```bash
pnpm add @urauth/express
```

## Peer Dependencies

- `express` >= 4.0.0
- `@urauth/node`
- `@urauth/ts`

## What's Included

| Export | Description |
|--------|-------------|
| [`expressAuth`](./examples#adapter-pattern) | Factory that creates all utilities from an `Auth` instance |
| [`createMiddleware`](./reference#createmiddleware) | Middleware that resolves `req.auth` from the request token |
| [`guard`](./reference#guard) | Guard middleware for requirement checks |
| [`protect`](./reference#protect) | Shorthand for authentication-only guard |
| [`router`](./reference#router) | Auto-generated auth routes (login, refresh, logout) |
| [`errorHandler`](./reference#errorhandler) | Error handler for `AuthError` subclasses |

## Quick Start

```typescript
import express from "express";
import { Auth } from "@urauth/node";
import { expressAuth } from "@urauth/express";
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

// Resolve auth context on all routes
app.use(middleware({ optional: true }));

// Auth endpoints: POST /auth/login, /auth/refresh, /auth/logout
app.use("/auth", router());

// Protected routes
app.get("/me", protect(), (req, res) => {
  res.json(req.auth.user);
});

app.get("/admin", guard(new Role("admin")), (req, res) => {
  res.json({ message: "Admin access granted" });
});

app.get("/posts", guard(new Permission("post", "read")), (req, res) => {
  res.json({ posts: [] });
});

// Error handler (must be last)
app.use(errorHandler());

app.listen(3000);
```

## Next Steps

- [Examples](./examples) — Detailed usage patterns.
- [API Reference](./reference) — Full API surface listing.
- [Security Best Practices](./security) — Hardening your Express auth setup.
