# Security Best Practices

## Secret Key Management

::: danger Never hardcode secrets
Never commit your secret key to source control. Always use environment variables or a secrets manager.
:::

```typescript
// BAD
const auth = new Auth({ secretKey: "hardcoded-secret" });

// GOOD
const auth = new Auth({ secretKey: process.env.AUTH_SECRET! });
```

- Use a cryptographically random secret of at least 256 bits.
- Rotate secrets periodically, supporting both old and new during the transition.
- Use different secrets per environment.

## Token Transport for Browsers

Bearer tokens in `localStorage` are vulnerable to XSS. For browser-facing apps:

```typescript
await app.register(urAuthPlugin, {
  auth,
  transport: "cookie",
  cookieName: "access_token",
});
```

Set secure cookie flags:

```typescript
reply.setCookie("access_token", token, {
  httpOnly: true,
  secure: true,
  sameSite: "lax",
  maxAge: 900,
  path: "/",
});
```

## CSRF Protection

When using cookie transport, add CSRF protection. Use `@fastify/csrf-protection`:

```typescript
import fastifyCsrf from "@fastify/csrf-protection";

await app.register(fastifyCsrf, {
  cookieOpts: { httpOnly: true, secure: true, sameSite: "strict" },
});
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

urAuth's `RefreshService` automatically rotates refresh tokens and detects reuse. If a refresh token is used twice, the entire token family is revoked — a sign of theft.

This is automatic when using `urAuthRoutes`.

## Guard Every Route

Never rely on the plugin's global context resolution as your only protection:

```typescript
// BAD — no guard, anyone can access
app.get("/admin", {
  handler: (request) => request.auth.user,
});

// GOOD — explicit guard
app.get("/admin", {
  preHandler: [app.auth.guard(new Role("admin"))],
  handler: (request) => request.auth.user,
});
```

## Error Handling

The plugin sets a custom error handler that catches `AuthError` and returns safe JSON responses. It never exposes stack traces or internal state.

If you override the error handler, ensure auth errors are handled:

```typescript
app.setErrorHandler((error, request, reply) => {
  if (error instanceof AuthError) {
    return reply.status(error.statusCode).send({ error: error.detail });
  }
  // Your custom handling...
  reply.status(500).send({ error: "Internal server error" });
});
```

## Rate Limiting

Protect auth endpoints from brute-force attacks:

```typescript
import rateLimit from "@fastify/rate-limit";

await app.register(rateLimit, {
  max: 10,
  timeWindow: "15 minutes",
  keyGenerator: (request) => request.ip,
});
```

For more granular control, apply per-route:

```typescript
app.post("/auth/login", {
  config: {
    rateLimit: { max: 5, timeWindow: "5 minutes" },
  },
  handler: async (request) => { /* ... */ },
});
```

## Request Validation

Validate request bodies with Fastify's built-in schema validation:

```typescript
app.post("/auth/login", {
  schema: {
    body: {
      type: "object",
      required: ["username", "password"],
      properties: {
        username: { type: "string", minLength: 1, maxLength: 255 },
        password: { type: "string", minLength: 1, maxLength: 255 },
      },
      additionalProperties: false,
    },
  },
  handler: async (request) => { /* ... */ },
});
```

## HTTPS

Always serve over HTTPS in production. Configure your reverse proxy (nginx, Caddy) to terminate TLS, or use Fastify's HTTPS support:

```typescript
const app = Fastify({
  https: {
    key: fs.readFileSync("key.pem"),
    cert: fs.readFileSync("cert.pem"),
  },
});
```

## Security Headers

Use `@fastify/helmet` for security headers:

```typescript
import helmet from "@fastify/helmet";
await app.register(helmet);
```

## Logging

Fastify has built-in structured logging via Pino. Enable it for audit trails:

```typescript
const app = Fastify({ logger: true });

// Auth events are logged automatically when using urAuthRoutes
```

## Security Checklist

- [ ] Secret key loaded from environment variable or secrets manager
- [ ] Access token TTL is 15 minutes or less
- [ ] Refresh token rotation enabled (automatic with `urAuthRoutes`)
- [ ] Cookie transport uses `httpOnly`, `secure`, `sameSite` flags
- [ ] CSRF protection enabled when using cookie transport
- [ ] Rate limiting on login and refresh endpoints
- [ ] HTTPS enforced in production
- [ ] Security headers set (`@fastify/helmet`)
- [ ] Request bodies validated with JSON Schema
- [ ] Every sensitive route has an explicit preHandler guard
- [ ] Error handler doesn't leak internal details
- [ ] Logging enabled for auth event audit
