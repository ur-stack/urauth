# API Reference

## urAuthPlugin

Fastify plugin that integrates urAuth. Decorates `request.auth` and `app.auth`.

```typescript
const urAuthPlugin: FastifyPluginAsync<UrAuthPluginOptions>
```

### UrAuthPluginOptions

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `auth` | `Auth` | — | Auth instance from `@urauth/node` (required) |
| `transport` | `"bearer" \| "cookie" \| "hybrid"` | `"bearer"` | Token extraction method |
| `cookieName` | `string` | `"access_token"` | Cookie name for cookie/hybrid transport |

### Decorations

**`request.auth`** — `AuthContext` instance resolved on every request.

**`app.auth`** — Guard factory object:

| Method | Type | Description |
|--------|------|-------------|
| `app.auth.guard` | `(requirement: Requirement) => preHandlerHookHandler` | Requirement guard |
| `app.auth.protect` | `() => preHandlerHookHandler` | Authentication-only guard |
| `app.auth.tenant` | `(opts: { level: string }) => preHandlerHookHandler` | Tenant guard |
| `app.auth.policy` | `(check: (ctx: AuthContext) => boolean) => preHandlerHookHandler` | Custom policy guard |

---

## createGuard

Create a preHandler hook that checks a requirement.

```typescript
function createGuard(requirement: Requirement): preHandlerHookHandler
```

**Throws:** `ForbiddenError` (403) if the requirement is not met.

---

## createProtect

Create a preHandler hook that requires authentication.

```typescript
function createProtect(): preHandlerHookHandler
```

**Throws:** `UnauthorizedError` (401) if unauthenticated.

---

## createTenantGuard

Create a preHandler hook for tenant membership.

```typescript
function createTenantGuard(opts: { level: string }): preHandlerHookHandler
```

---

## createPolicyGuard

Create a preHandler hook with custom authorization logic.

```typescript
function createPolicyGuard(check: (ctx: AuthContext) => boolean): preHandlerHookHandler
```

---

## urAuthRoutes

Fastify plugin that registers auth routes.

```typescript
const urAuthRoutes: FastifyPluginAsync<UrAuthRoutesOptions>
```

### UrAuthRoutesOptions

| Option | Type | Description |
|--------|------|-------------|
| `auth` | `Auth` | Auth instance (required) |
| `prefix` | `string` | Route prefix (e.g., `"/auth"`) |

**Routes:**

| Method | Path | Body | Response |
|--------|------|------|----------|
| POST | `/login` | `{ username, password }` | `{ accessToken, refreshToken, tokenType }` |
| POST | `/refresh` | `{ refreshToken }` | `{ accessToken, refreshToken, tokenType }` |
| POST | `/logout` | — | `{ ok: true }` |
| POST | `/logout-all` | — | `{ ok: true }` |

---

## RouteAuthConfig

Route-level auth configuration via `config.auth`.

```typescript
interface RouteAuthConfig {
  require?: Requirement
  optional?: boolean
}
```

| Property | Type | Description |
|----------|------|-------------|
| `require` | `Requirement` | Requirement to satisfy (checked in onRequest hook) |
| `optional` | `boolean` | Allow unauthenticated access |

---

## Transport Functions

### extractToken

```typescript
function extractToken(req: FastifyRequest): string | null
```

### extractTokenFromCookie

```typescript
function extractTokenFromCookie(req: FastifyRequest, cookieName: string): string | null
```

### extractTokenHybrid

```typescript
function extractTokenHybrid(req: FastifyRequest, cookieName: string): string | null
```
