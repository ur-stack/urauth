# API Reference

## defineUrAuth

Factory that creates all H3 auth utilities from an `Auth` instance.

```typescript
function defineUrAuth(auth: Auth): DefineUrAuthResult
```

### DefineUrAuthResult

| Property | Type | Description |
|----------|------|-------------|
| `onRequest` | `(options?) => EventHandler` | onRequest handler factory |
| `requireAuth` | `() => EventHandler` | Authentication guard |
| `requirePermission` | `(resource, action) => EventHandler` | Permission guard |
| `requireRole` | `(roleName) => EventHandler` | Role guard |
| `requireGuard` | `(requirement) => EventHandler` | Requirement guard |
| `requireTenant` | `(opts) => EventHandler` | Tenant guard |
| `requirePolicy` | `(check) => EventHandler` | Custom policy guard |
| `authRoutes` | `() => Router` | Auth routes factory |

---

## createUrAuthNitroPlugin

Create a Nitro plugin for Nuxt server integration.

```typescript
function createUrAuthNitroPlugin(opts: NitroPluginOptions): {
  onRequest: EventHandler
  auth: Auth
  routes: Router | undefined
}
```

### NitroPluginOptions

| Option | Type | Description |
|--------|------|-------------|
| `auth` | `Auth` | Auth instance (required) |
| `routes` | `{ prefix?: string }` | Enable auth routes with optional prefix |
| `exclude` | `string[]` | URL patterns to exclude from auth |
| `transport` | `"bearer" \| "cookie" \| "hybrid"` | Token transport |
| `cookieName` | `string` | Cookie name for cookie/hybrid transport |

---

## createOnRequest

Create an onRequest handler that resolves auth context.

```typescript
function createOnRequest(auth: Auth, options?: OnRequestOptions): EventHandler
```

### OnRequestOptions

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `optional` | `boolean` | `false` | Allow unauthenticated access |
| `transport` | `"bearer" \| "cookie" \| "hybrid"` | `"bearer"` | Token extraction method |
| `cookieName` | `string` | `"access_token"` | Cookie name |

Sets `event.context.auth` to an `AuthContext` instance.

---

## requireAuth

Guard that requires authentication.

```typescript
function requireAuth(): EventHandler
```

**Throws:** `UnauthorizedError` (401) if unauthenticated.

---

## requirePermission

Guard that requires a specific permission.

```typescript
function requirePermission(resource: string, action: string): EventHandler
```

**Throws:** `ForbiddenError` (403) if the permission is not met.

---

## requireRole

Guard that requires a specific role.

```typescript
function requireRole(roleName: string): EventHandler
```

---

## requireGuard

Guard that requires a `Requirement` to be satisfied.

```typescript
function requireGuard(requirement: Requirement): EventHandler
```

---

## requireTenant

Guard that requires tenant membership.

```typescript
function requireTenant(opts: { level: string }): EventHandler
```

---

## requirePolicy

Guard with custom authorization logic.

```typescript
function requirePolicy(check: (ctx: AuthContext) => boolean): EventHandler
```

---

## authRoutes

Creates an H3 router with auth endpoints.

```typescript
function authRoutes(auth: Auth): Router
```

**Routes:**

| Method | Path | Body | Response |
|--------|------|------|----------|
| POST | `/login` | `{ username, password }` | `{ accessToken, refreshToken, tokenType }` |
| POST | `/refresh` | `{ refreshToken }` | `{ accessToken, refreshToken, tokenType }` |
| POST | `/logout` | — | `{ ok: true }` |
| POST | `/logout-all` | — | `{ ok: true }` |

---

## Transport Functions

### extractToken

```typescript
function extractToken(event: H3Event): string | null
```

### extractTokenFromCookie

```typescript
function extractTokenFromCookie(event: H3Event, cookieName: string): string | null
```

### extractTokenHybrid

```typescript
function extractTokenHybrid(event: H3Event, cookieName: string): string | null
```

---

## Type Augmentation

The package augments H3's event context:

```typescript
declare module "h3" {
  interface H3EventContext {
    auth: AuthContext
  }
}
```
