# Security Best Practices

## Secret Key Management

::: danger Never hardcode secrets
Never commit your secret key to source control. Always use environment variables, runtime config, or a secrets manager.
:::

```typescript
// BAD
const auth = new Auth({ secretKey: "hardcoded-secret" });

// GOOD — environment variable
const auth = new Auth({ secretKey: process.env.AUTH_SECRET! });

// GOOD — Nuxt runtime config
const auth = new Auth({ secretKey: useRuntimeConfig().authSecret });
```

- Use a cryptographically random secret of at least 256 bits.
- Rotate secrets periodically, supporting both old and new during the transition.
- Use different secrets per environment.
- In Nuxt, use `runtimeConfig` with environment variables — never `publicRuntimeConfig` for secrets.

## Token Transport for Browsers

Bearer tokens stored in `localStorage` are vulnerable to XSS. For browser-facing apps, prefer cookie transport:

```typescript
export default createOnRequest(auth, {
  transport: "cookie",
  cookieName: "access_token",
});
```

Set secure cookie flags when issuing tokens:

```typescript
import { setCookie } from "h3";

setCookie(event, "access_token", token, {
  httpOnly: true,
  secure: true,
  sameSite: "lax",
  maxAge: 900,
  path: "/",
});
```

## CSRF Protection

When using cookie transport, add CSRF protection. In Nuxt, use a server middleware:

```typescript
// ~/server/middleware/csrf.ts
export default defineEventHandler((event) => {
  if (["POST", "PUT", "DELETE", "PATCH"].includes(event.method)) {
    const origin = getHeader(event, "origin");
    const host = getHeader(event, "host");
    if (origin && !origin.includes(host!)) {
      throw createError({ statusCode: 403, message: "CSRF check failed" });
    }
  }
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

urAuth's `RefreshService` automatically rotates refresh tokens and detects reuse. If a token is replayed, the entire token family is revoked.

This is automatic when using `authRoutes()`.

## Guard Every Route

The middleware's `optional` flag provides context — it does not protect. Always apply explicit guards to sensitive routes:

```typescript
// BAD — no guard, anyone can access
export default defineEventHandler((event) => {
  return event.context.auth.user; // might be anonymous!
});

// GOOD — explicit guard
export default defineEventHandler({
  onRequest: [requireAuth()],
  handler: (event) => event.context.auth.user,
});
```

## Error Handling

The `authRoutes()` router includes error handling for `AuthError` subclasses. For custom error handling:

```typescript
// BAD — leaks internals
app.options.onError = (error) => {
  return { error: error.message, stack: error.stack };
};

// GOOD — safe error responses
app.options.onError = (error, event) => {
  if (error instanceof AuthError) {
    return sendError(event, createError({
      statusCode: error.statusCode,
      message: error.detail,
    }));
  }
  return sendError(event, createError({
    statusCode: 500,
    message: "Internal server error",
  }));
};
```

## Rate Limiting

Protect auth endpoints from brute-force attacks. In Nuxt, use a server middleware:

```typescript
// ~/server/middleware/rate-limit.ts
const attempts = new Map<string, { count: number; reset: number }>();

export default defineEventHandler((event) => {
  if (!event.path.startsWith("/api/auth/login")) return;

  const ip = getHeader(event, "x-forwarded-for") ?? "unknown";
  const now = Date.now();
  const entry = attempts.get(ip);

  if (entry && entry.reset > now && entry.count >= 10) {
    throw createError({ statusCode: 429, message: "Too many attempts" });
  }

  if (!entry || entry.reset <= now) {
    attempts.set(ip, { count: 1, reset: now + 15 * 60 * 1000 });
  } else {
    entry.count++;
  }
});
```

For production, use a Redis-backed rate limiter or platform-level rate limiting.

## Request Body Validation

Validate request bodies before processing:

```typescript
import { z } from "zod";

const loginSchema = z.object({
  username: z.string().min(1).max(255),
  password: z.string().min(1).max(255),
});

export default defineEventHandler(async (event) => {
  const body = await readBody(event);
  const result = loginSchema.safeParse(body);
  if (!result.success) {
    throw createError({ statusCode: 400, message: "Invalid request body" });
  }
  // Proceed with validated data...
});
```

## HTTPS

Always serve over HTTPS in production. Configure your deployment platform or reverse proxy for TLS termination.

## Nuxt-Specific Security

### Runtime Config

Store secrets in `runtimeConfig`, never `public`:

```typescript
// nuxt.config.ts
export default defineNuxtConfig({
  runtimeConfig: {
    authSecret: "",  // Set via NUXT_AUTH_SECRET env var
    public: {
      // Never put secrets here
    },
  },
});
```

### Server-Only Code

Keep auth logic in `~/server/` to prevent it from being included in the client bundle:

```
~/server/utils/auth.ts   — Auth instance (server-only)
~/server/middleware/      — Auth middleware (server-only)
~/server/api/             — Protected API routes (server-only)
```

## Security Checklist

- [ ] Secret key loaded from environment variable or runtime config
- [ ] Secret not in `publicRuntimeConfig` (Nuxt)
- [ ] Access token TTL is 15 minutes or less
- [ ] Refresh token rotation enabled (automatic with `authRoutes()`)
- [ ] Cookie transport uses `httpOnly`, `secure`, `sameSite` flags
- [ ] CSRF protection enabled when using cookie transport
- [ ] Rate limiting on login and refresh endpoints
- [ ] HTTPS enforced in production
- [ ] Request bodies validated
- [ ] Every sensitive route has an explicit guard
- [ ] Error responses don't leak internal details
- [ ] Auth code stays in `~/server/` (Nuxt)
