# API Reference

## expressAuth

Factory that creates all Express auth utilities from an `Auth` instance.

```typescript
function expressAuth(auth: Auth): {
  middleware: (options?: MiddlewareOptions) => RequestHandler
  guard: typeof guard
  protect: typeof protect
  router: (() => Router) & { password: () => Router }
}
```

---

## createMiddleware

Express middleware that resolves auth context from the request token and sets `req.auth`.

```typescript
function createMiddleware(auth: Auth, options?: MiddlewareOptions): RequestHandler
```

### MiddlewareOptions

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `optional` | `boolean` | `false` | Allow unauthenticated access (sets anonymous context) |
| `transport` | `"bearer" \| "cookie" \| "hybrid"` | `"bearer"` | Token extraction method |
| `cookieName` | `string` | `"access_token"` | Cookie name for cookie/hybrid transport |

---

## guard

Guard middleware that requires a `Requirement` to be satisfied.

```typescript
function guard(requirement: Requirement): RequestHandler
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `requirement` | `Requirement` | `Permission`, `Role`, `AllOf`, `AnyOf`, or any `Requirement` |

**Throws:** `ForbiddenError` (403) if the requirement is not met.

### guard.tenant

```typescript
guard.tenant(opts: { level: string }): RequestHandler
```

Requires the user to be a member of a tenant at the specified hierarchy level.

### guard.policy

```typescript
guard.policy(check: (ctx: AuthContext) => boolean): RequestHandler
```

Custom policy guard with arbitrary logic.

---

## protect

Shorthand middleware that requires authentication only (no specific permission).

```typescript
function protect(): RequestHandler
```

**Throws:** `UnauthorizedError` (401) if the request is not authenticated.

---

## router

Creates an Express Router with auth endpoints.

```typescript
function router(auth: Auth): Router
```

**Routes:**

| Method | Path | Body | Response |
|--------|------|------|----------|
| POST | `/login` | `{ username, password }` | `{ accessToken, refreshToken, tokenType }` |
| POST | `/refresh` | `{ refreshToken }` | `{ accessToken, refreshToken, tokenType }` |
| POST | `/logout` | — | `{ ok: true }` |
| POST | `/logout-all` | — | `{ ok: true }` |

### router.password

```typescript
router.password(auth: Auth): Router
```

Creates a Router with only password-based routes (login, refresh, logout, logout-all).

---

## errorHandler

Express error handler for `AuthError` subclasses.

```typescript
function errorHandler(): ErrorRequestHandler
```

Catches `AuthError` instances and sends `{ error: detail }` with the appropriate HTTP status code. Non-auth errors are passed to the next error handler.

---

## Transport Functions

### extractToken

```typescript
function extractToken(req: Request): string | null
```

Extracts the bearer token from the `Authorization` header.

### extractTokenFromCookie

```typescript
function extractTokenFromCookie(req: Request, cookieName: string): string | null
```

Extracts the token from a cookie.

### extractTokenHybrid

```typescript
function extractTokenHybrid(req: Request, cookieName: string): string | null
```

Tries bearer header first, falls back to cookie.

---

## Type Augmentation

The package augments Express's `Request` interface:

```typescript
declare global {
  namespace Express {
    interface Request {
      auth: AuthContext;
    }
  }
}
```
