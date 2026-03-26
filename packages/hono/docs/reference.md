# API Reference

## urAuthMiddleware

Hono middleware that resolves auth context from the request token and stores it in `c.get("auth")`.

```typescript
function urAuthMiddleware(auth: Auth, options?: UrAuthMiddlewareOptions): MiddlewareHandler
```

### UrAuthMiddlewareOptions

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `optional` | `boolean` | `false` | Allow unauthenticated access (sets anonymous context) |
| `transport` | `"bearer" \| "cookie" \| "hybrid"` | `"bearer"` | Token extraction method |
| `cookieName` | `string` | `"access_token"` | Cookie name for cookie/hybrid transport |

---

## guard

Guard middleware that requires a `Requirement` to be satisfied.

```typescript
function guard(auth: Auth, requirement: Requirement): MiddlewareHandler<UrAuthEnv>
```

**Throws:** `ForbiddenError` (403) if the requirement is not met.

---

## protect

Shorthand middleware that requires authentication only.

```typescript
function protect(auth: Auth): MiddlewareHandler<UrAuthEnv>
```

**Throws:** `UnauthorizedError` (401) if unauthenticated.

---

## guardPermission

Guard middleware for a specific resource/action permission.

```typescript
function guardPermission(auth: Auth, resource: string, action: string): MiddlewareHandler<UrAuthEnv>
```

---

## guardRole

Guard middleware for a specific role.

```typescript
function guardRole(auth: Auth, roleName: string): MiddlewareHandler<UrAuthEnv>
```

---

## guardTenant

Guard middleware for tenant membership.

```typescript
function guardTenant(auth: Auth, opts: { level: string }): MiddlewareHandler<UrAuthEnv>
```

---

## guardPolicy

Guard middleware with custom authorization logic.

```typescript
function guardPolicy(auth: Auth, check: (ctx: AuthContext) => boolean): MiddlewareHandler<UrAuthEnv>
```

---

## authRoutes

Creates a Hono router with auth endpoints.

```typescript
function authRoutes(auth: Auth): Hono<UrAuthEnv>
```

**Routes:**

| Method | Path | Body | Response |
|--------|------|------|----------|
| POST | `/login` | `{ username, password }` | `{ accessToken, refreshToken, tokenType }` |
| POST | `/refresh` | `{ refreshToken }` | `{ accessToken, refreshToken, tokenType }` |
| POST | `/logout` | — | `{ ok: true }` |
| POST | `/logout-all` | — | `{ ok: true }` |

Includes a built-in `onError` handler for `AuthError` subclasses.

---

## UrAuthEnv

Type definition for Hono's environment variables, providing type safety for `c.get("auth")`.

```typescript
interface UrAuthEnv {
  Variables: {
    auth: AuthContext
  }
}
```

---

## Transport Functions

### extractToken

```typescript
function extractToken(c: Context): string | null
```

### extractTokenFromCookie

```typescript
function extractTokenFromCookie(c: Context, cookieName: string): string | null
```

### extractTokenHybrid

```typescript
function extractTokenHybrid(c: Context, cookieName: string): string | null
```
