# Getting Started

## Installation

::: code-group

```bash [Python]
pip install urauth

# With FastAPI support
pip install urauth[fastapi]

# With all extras
pip install urauth[all]
```

```bash [TypeScript (any runtime)]
pnpm add @urauth/ts
```

```bash [Node.js backend]
pnpm add @urauth/node
```

```bash [Hono]
pnpm add @urauth/hono
```

```bash [Express]
pnpm add @urauth/express
```

```bash [Fastify]
pnpm add @urauth/fastify
```

```bash [Vue]
pnpm add @urauth/vue
```

```bash [Nuxt]
pnpm add @urauth/nuxt
```

:::

## Quick Start — Python

```python
from urauth import Auth, AuthConfig, Permission, RoleRegistry

# 1. Configure
config = AuthConfig(secret_key="your-secret-key")

# 2. Define roles & permissions
registry = RoleRegistry()
registry.role("admin", ["user:*", "post:*"])
registry.role("editor", ["post:read", "post:write"])

# 3. Implement your Auth subclass
class MyAuth(Auth):
    async def get_user(self, user_id):
        return await db.users.get(user_id)

    async def get_user_by_username(self, username):
        return await db.users.get_by_username(username)

    async def verify_password(self, user, password):
        return hasher.verify(password, user.hashed_password)

auth = MyAuth(config)
```

## Quick Start — TypeScript

```typescript
import {
  Permission,
  Role,
  AuthContext,
  RoleRegistry,
  definePermissions,
} from "@urauth/ts";

// 1. Define permissions
const Perms = definePermissions({
  USER_READ: "user:read",
  USER_WRITE: "user:write",
  POST_ALL: "post:*",
});

// 2. Set up roles
const registry = new RoleRegistry();
registry.role("admin", ["user:*", "post:*"]);
registry.role("editor", ["post:read", "post:write"]);

// 3. Check permissions in your app
const ctx = new AuthContext({
  user: { id: "1" },
  roles: [new Role("editor")],
  permissions: [new Permission("post", "read"), new Permission("post", "write")],
});

ctx.hasPermission("post:read");     // true
ctx.hasPermission("user:read");     // false
ctx.hasRole("editor");              // true
ctx.satisfies(
  Perms.POST_ALL.or(new Role("admin"))
);                                   // true
```

## Next Steps

- [Core Concepts](/guide/concepts) — Understand the permission model, roles, relations, and tenancy.
- [Python Docs](/packages/py/) — Full Python library documentation.
- [TypeScript Docs](/packages/ts/) — TypeScript core API reference.
