# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

Run from the `packages/ts` directory. Uses bun as package manager and test runner.

```bash
bun run build          # tsc — compile to dist/
bun run dev            # tsc --watch
bun test               # run all tests
bun test tests/tokens.test.ts           # single test file
bun test --filter "TokenService"        # filter by test name
```

No linter is configured for this package.

## Architecture

`@urauth/ts` is the shared TypeScript core for the urauth monorepo. It provides JWT creation/verification, token refresh with rotation, sessions, and a composable authorization system. Other TS packages (`@urauth/node`, `@urauth/vue`, `@urauth/nuxt`) depend on it via `workspace:*`.

### Module layout

- **`types.ts`** — `TokenPayload`, `TokenPair`, `Subject`
- **`config.ts`** — `AuthConfig` (secretKey, algorithm, issuer, audience, TTLs, session settings)
- **`exceptions.ts`** — `AuthError` → `InvalidTokenError`, `TokenExpiredError`, `TokenRevokedError`, `UnauthorizedError`, `ForbiddenError`
- **`actions.ts`** — `CommonAction` enum and branded `Action`/`Resource` types
- **`context.ts`** — `AuthContext` class with `hasPermission()`, `hasRole()`, `hasRelation()`, `satisfies()`; `toSubject()` bridges to the flat `Subject` interface for Vue/Nuxt

#### `tokens/`
- **`jwt.ts`** — `verifyToken()` standalone function + `TokenService` class (create access/refresh/pairs, decode, validate)
- **`refresh.ts`** — `RefreshService` with rotation and reuse detection (token families)
- **`revocation.ts`** — `RevocationService` wrapping `TokenStore`

#### `stores/`
- **`types.ts`** — `TokenStore` and `SessionStore` interfaces (async)
- **`memory.ts`** — `MemoryTokenStore` and `MemorySessionStore` for dev/testing

#### `authz/`
- **`requirement.ts`** — `Requirement` base with `.and()`/`.or()` composition, `AllOf`, `AnyOf`
- **`primitives.ts`** — `Permission`, `Role`, `Relation` (all extend `Requirement`)
- **`checker.ts`** — `AsyncPermissionChecker` interface, `StringChecker`, `RoleExpandingChecker`
- **`roles.ts`** — `RoleRegistry`, `RoleLoader`/`RoleCache` interfaces, `MemoryRoleCache`
- **`permission-enum.ts`** — `definePermissions()` factory for typed permission maps
- **`compat.ts`** — sync `PermissionChecker` interface and `canAccess()` for backward-compat with `Subject`

### Two checker interfaces

- **`PermissionChecker`** (sync, takes `Subject`) — used by Vue/Nuxt frontends via `canAccess()`
- **`AsyncPermissionChecker`** (async, takes `AuthContext`) — used by `StringChecker` and `RoleExpandingChecker` on the server

### Cross-package relationship

This package is the foundation for all TS packages in the monorepo. The Python package (`packages/py`) is the authoritative implementation — TS types and enums should stay in sync with Python equivalents.

### Permission string format

Permissions use `resource:action` format with wildcard support:
- `"*"` — grants all permissions
- `"resource:*"` — grants all actions on a resource
- `"resource:action"` — grants specific permission
