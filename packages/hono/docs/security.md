# Security Best Practices

## Secret Key Management

::: danger Never hardcode secrets
Never commit your secret key to source control. Always use environment variables, platform secrets, or a secrets manager.
:::

```typescript
// BAD
const auth = new Auth({ secretKey: "hardcoded-secret" });

// GOOD — environment variable
const auth = new Auth({ secretKey: process.env.AUTH_SECRET! });

// GOOD — Cloudflare Workers binding
const auth = new Auth({ secretKey: c.env.AUTH_SECRET });
```

- Use a cryptographically random secret of at least 256 bits.
- Rotate secrets periodically, supporting both old and new during the transition.
- Use different secrets per environment.

## Token Transport for Browsers

Bearer tokens stored in `localStorage` are vulnerable to XSS. For browser-facing apps, prefer cookie transport:

```typescript
app.use("*", urAuthMiddleware(auth, {
  transport: "cookie",
  cookieName: "access_token",
}));
```

Set secure cookie flags when issuing tokens:

```typescript
import { setCookie } from "hono/cookie";

setCookie(c, "access_token", token, {
  httpOnly: true,
  secure: true,
  sameSite: "Lax",
  maxAge: 900,
  path: "/",
});
```

## CSRF Protection

When using cookie transport, add CSRF protection. Use the `Origin` header check or a CSRF token:

```typescript
import { csrf } from "hono/csrf";

app.use("*", csrf());
```

## Token Lifetime

```typescript
const auth = new Auth({
  secretKey: process.env.AUTH_SECRET!,
  algorithm: "HS256",
  accessTokenTtl: 900,      // 15 minutes
  refreshTokenTtl: 604_800,  // 7 days
});
```

- **Access tokens:** 5-15 minutes to limit exposure from stolen tokens.
- **Refresh tokens:** 1-30 days with automatic rotation and reuse detection.

## Refresh Token Rotation

urAuth's `RefreshService` automatically rotates refresh tokens and detects reuse. If a token is replayed, the entire token family is revoked.

This is automatic when using `authRoutes()`.

## Guard Every Route

The middleware's `optional` flag provides context — it does not protect. Always use explicit guards:

```typescript
// BAD — middleware is optional, no guard
app.get("/admin", (c) => c.json(c.get("auth").user));

// GOOD — explicit guard
app.get("/admin", guard(auth, new Role("admin")), (c) => {
  return c.json(c.get("auth").user);
});
```

## Error Handling

`authRoutes()` includes a built-in error handler that returns safe JSON responses. If you add your own error handler, ensure auth errors are handled:

```typescript
app.onError((err, c) => {
  if (err instanceof AuthError) {
    return c.json({ error: err.detail }, err.statusCode as 401 | 403);
  }
  return c.json({ error: "Internal server error" }, 500);
});
```

Never expose stack traces:

```typescript
// BAD
app.onError((err, c) => c.json({ error: err.message, stack: err.stack }, 500));

// GOOD
app.onError((err, c) => c.json({ error: "Internal server error" }, 500));
```

## Rate Limiting

Protect auth endpoints from brute-force attacks:

```typescript
import { rateLimiter } from "hono-rate-limiter";

const authApp = new Hono();
authApp.use("*", rateLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  keyGenerator: (c) => c.req.header("CF-Connecting-IP") ?? c.req.header("X-Forwarded-For") ?? "unknown",
}));
authApp.route("/", authRoutes(auth));

app.route("/auth", authApp);
```

## Request Body Validation

Validate request bodies before processing:

```typescript
import { zValidator } from "@hono/zod-validator";
import { z } from "zod";

const loginSchema = z.object({
  username: z.string().min(1).max(255),
  password: z.string().min(1).max(255),
});

app.post("/auth/login", zValidator("json", loginSchema), async (c) => {
  const { username, password } = c.req.valid("json");
  const result = await auth.authenticate(username, password);
  return c.json(result);
});
```

## HTTPS

Always serve over HTTPS in production. In Cloudflare Workers, this is automatic. For other runtimes, configure TLS at the reverse proxy or runtime level.

## Security Headers

Use Hono's `secureHeaders` middleware:

```typescript
import { secureHeaders } from "hono/secure-headers";

app.use("*", secureHeaders());
```

## Cloudflare Workers Security

When running on Cloudflare Workers:

- Store secrets using `wrangler secret put AUTH_SECRET`
- Use Workers KV or Durable Objects for token/session stores (not in-memory)
- Rate limiting is available via Cloudflare's built-in rate limiting rules

## Security Checklist

- [ ] Secret key loaded from environment/platform secrets
- [ ] Access token TTL is 15 minutes or less
- [ ] Refresh token rotation enabled (automatic with `authRoutes()`)
- [ ] Cookie transport uses `httpOnly`, `secure`, `sameSite` flags
- [ ] CSRF protection enabled when using cookie transport
- [ ] Rate limiting on login and refresh endpoints
- [ ] HTTPS enforced in production
- [ ] Security headers set (`secureHeaders`)
- [ ] Request bodies validated
- [ ] Every sensitive route has an explicit guard
- [ ] Error responses don't leak internal details
