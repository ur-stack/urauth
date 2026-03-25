# @urauth/ts

Shared TypeScript core for the urauth monorepo. Provides JWT types, composable authorization primitives, role management, and hierarchical multi-tenancy — all with zero dependencies.

## Installation

```bash
pnpm add @urauth/ts
```

## What's Included

| Module | Description |
|--------|-------------|
| [Permissions](./permissions) | `Permission`, `matchPermission`, `definePermissions` — separator-agnostic format with wildcards |
| [Roles](./roles) | `RoleRegistry`, `RoleExpandingChecker` — hierarchy, DB loading, caching |
| [Relations](./relations) | `Relation`, `RelationTuple`, `defineRelations` — Zanzibar-style authorization |
| [AuthContext](./context) | Central auth context with permission/role/relation introspection |
| [Tenant](./tenant) | `TenantPath`, `TenantHierarchy`, `TenantDefaults` — hierarchical multi-tenancy |
| [Reference](./reference) | Full API surface listing |

## Quick Example

```typescript
import {
  AuthContext,
  Permission,
  Role,
  definePermissions,
  RoleRegistry,
} from "@urauth/ts";

// Define permissions
const Perms = definePermissions({
  USER_READ: "user:read",
  USER_WRITE: "user:write",
  POST_ALL: "post:*",
});

// Set up roles with hierarchy
const registry = new RoleRegistry();
registry.role("viewer", ["post:read"]);
registry.role("editor", ["post:read", "post:write"], { inherits: ["viewer"] });
registry.role("admin", ["user:*", "post:*"], { inherits: ["editor"] });

// Check permissions
const ctx = new AuthContext({
  user: { id: "1" },
  roles: [new Role("editor")],
  permissions: [new Permission("post", "read"), new Permission("post", "write")],
});

ctx.hasPermission("post:read");   // true
ctx.hasPermission("post.read");   // true (separator-agnostic)
ctx.hasRole("editor");            // true
ctx.satisfies(Perms.POST_ALL.or(new Role("admin"))); // true
```

## Cross-Package Relationship

This package is the foundation for all TypeScript packages in the monorepo:

```
@urauth/ts (this package)
  ├── @urauth/node    (adds JWT creation, token lifecycle, stores)
  ├── @urauth/vue     (Vue composables for auth state)
  ├── @urauth/nuxt    (Nuxt module with auto-imports)
  ├── @urauth/hono    (Hono middleware)
  ├── @urauth/express (Express middleware)
  ├── @urauth/fastify (Fastify plugin)
  └── @urauth/h3      (H3/Nitro middleware)
```

The Python package (`urauth`) is the authoritative implementation — TypeScript types and behavior stay in sync with Python equivalents.
