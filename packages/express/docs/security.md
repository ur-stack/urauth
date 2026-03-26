# Security Best Practices

## Secret Key Management

::: danger Never hardcode secrets
Never commit your secret key to source control. Always use environment variables or a secrets manager.
:::

```typescript
// BAD — hardcoded secret
const auth = new Auth({ secretKey: "my-secret-key" });

// GOOD — from environment
const auth = new Auth({ secretKey: process.env.AUTH_SECRET! });
```

- Use a cryptographically random secret of at least 256 bits (32 bytes).
- Rotate secrets periodically. When rotating, support both the old and new secret during the transition window.
- Use different secrets per environment (dev, staging, production).

## Token Transport

### Prefer Hybrid or Cookie Transport for Browser Apps

Bearer tokens stored in `localStorage` are vulnerable to XSS. For browser-facing apps, use cookie transport with proper flags:

```typescript
app.use(middleware({ transport: "cookie", cookieName: "access_token" }));
```

When setting cookies, always use secure flags:

```typescript
res.cookie("access_token", token, {
  httpOnly: true,   // Not accessible via JavaScript
  secure: true,     // HTTPS only
  sameSite: "lax",  // CSRF protection
  maxAge: 900_000,  // Match access token TTL
  path: "/",
});
```

### Bearer Tokens for API Clients

Bearer transport is appropriate for machine-to-machine or mobile API clients that don't run in a browser context.

## CSRF Protection

When using cookie transport, you **must** add CSRF protection. Cookies are sent automatically by the browser, which makes endpoints vulnerable to cross-site request forgery.

```typescript
import csrf from "csurf";

// Apply CSRF protection to state-changing routes
app.use(csrf({ cookie: { httpOnly: true, secure: true, sameSite: "strict" } }));
```

Alternatively, use the double-submit cookie pattern or check the `Origin`/`Referer` header.

## Token Lifetime

Keep access tokens short-lived and refresh tokens long-lived:

```typescript
const auth = new Auth({
  secretKey: process.env.AUTH_SECRET!,
  algorithm: "HS256",
  accessTokenTtl: 900,      // 15 minutes
  refreshTokenTtl: 604_800,  // 7 days
});
```

- **Access tokens:** 5-15 minutes. Short enough that stolen tokens have limited utility.
- **Refresh tokens:** 1-30 days depending on risk tolerance. Always use rotation.

## Refresh Token Rotation

urAuth's `RefreshService` implements automatic rotation with family-based reuse detection. If a refresh token is used twice (indicating theft), the entire token family is revoked.

```typescript
// This is automatic when using router()
app.use("/auth", router());

// The /refresh endpoint automatically:
// 1. Validates the refresh token
// 2. Issues a new token pair
// 3. Revokes the old refresh token
// 4. Detects reuse and revokes the entire family if compromised
```

## Guard Every Route

Never rely solely on the middleware's `optional` flag for protection. Always apply explicit guards:

```typescript
// BAD — middleware is optional, route has no guard
app.use(middleware({ optional: true }));
app.get("/admin", (req, res) => {
  // req.auth might be anonymous!
  res.json(req.auth.user);
});

// GOOD — explicit guard on sensitive routes
app.get("/admin", guard(new Role("admin")), (req, res) => {
  res.json(req.auth.user);
});
```

## Don't Leak Error Details

The `errorHandler()` returns `error.detail` which is safe by design — it never includes stack traces or internal state. However, be careful with custom error handling:

```typescript
// BAD — leaks internal details
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

// GOOD — use the built-in error handler
app.use(errorHandler());
```

## Rate Limit Auth Endpoints

Auth endpoints (login, refresh) are common brute-force targets:

```typescript
import rateLimit from "express-rate-limit";

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,                   // 10 attempts per window
  message: { error: "Too many attempts, try again later" },
});

app.use("/auth/login", authLimiter);
```

## Validate Request Bodies

The auto-generated auth routes trust `req.body`. Ensure you have body parsing and validation:

```typescript
app.use(express.json({ limit: "10kb" })); // Limit body size
```

For production, add schema validation:

```typescript
import { z } from "zod";

const loginSchema = z.object({
  username: z.string().min(1).max(255),
  password: z.string().min(1).max(255),
});

app.post("/auth/login", (req, res, next) => {
  const result = loginSchema.safeParse(req.body);
  if (!result.success) {
    return res.status(400).json({ error: "Invalid request body" });
  }
  next();
});
```

## HTTPS Only

Always serve your application over HTTPS in production. Tokens sent over HTTP can be intercepted.

```typescript
// Redirect HTTP to HTTPS
app.use((req, res, next) => {
  if (req.headers["x-forwarded-proto"] !== "https" && process.env.NODE_ENV === "production") {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  next();
});
```

## Security Headers

Add security headers to prevent common attacks:

```typescript
import helmet from "helmet";

app.use(helmet());
```

This sets headers like `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`, and more.

## Audit Logging

Log authentication events for security monitoring:

```typescript
app.use("/auth/login", (req, res, next) => {
  const originalJson = res.json.bind(res);
  res.json = (body) => {
    if (res.statusCode === 200) {
      console.log(`[auth] login success: ${req.body.username} from ${req.ip}`);
    }
    return originalJson(body);
  };
  next();
});
```

## Security Checklist

- [ ] Secret key loaded from environment variable or secrets manager
- [ ] Access token TTL is 15 minutes or less
- [ ] Refresh token rotation is enabled (automatic with `router()`)
- [ ] Cookie transport uses `httpOnly`, `secure`, `sameSite` flags
- [ ] CSRF protection is enabled when using cookie transport
- [ ] Rate limiting is applied to login and refresh endpoints
- [ ] HTTPS is enforced in production
- [ ] Security headers are set (use `helmet`)
- [ ] Request body size is limited
- [ ] Error responses don't leak internal details
- [ ] Every sensitive route has an explicit guard
- [ ] Authentication events are logged for audit
