<div align="center">

# UrAuth

**Unified authentication & authorization for Python and TypeScript.**

JWT, OAuth2, RBAC, composable permissions, multi-tenant — one library across your entire stack.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB.svg)](https://www.python.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0%2B-3178C6.svg)](https://www.typescriptlang.org)

</div>

---

## Why UrAuth?

Most auth libraries solve one piece of the puzzle — a JWT helper here, a role check there. UrAuth gives you the full picture: a **single identity model** (`AuthContext`) that works the same way in your Python backend, Node.js API, and frontend framework.

- **Composable authorization** — combine permissions, roles, and relations with `&` and `|` operators
- **Framework adapters, not wrappers** — native middleware for FastAPI, Express, Fastify, Hono, and more
- **Frontend-ready** — React hooks and Vue composables that share the same permission logic as your backend
- **Multi-tenant built in** — hierarchical tenant paths, scoped roles, and tenant-aware guards
- **Protocol-driven** — swap token stores, session backends, or permission checkers without changing application code

## Packages

### Python

| Package | Install | Description |
|---------|---------|-------------|
| `urauth` | `pip install urauth` | Core library — JWT, password hashing, RBAC, permissions, events |
| `urauth[fastapi]` | `pip install urauth[fastapi]` | FastAPI adapter — dependencies, guards, routers, middleware |
| `urauth[oauth]` | `pip install urauth[oauth]` | OAuth2 social login support |

### TypeScript — Backend

| Package | Install | Description |
|---------|---------|-------------|
| `@urauth/ts` | `npm i @urauth/ts` | Shared core — types, JWT, authorization primitives, API client |
| `@urauth/node` | `npm i @urauth/node` | Node.js SDK — token service, guards, password hashing, sessions |
| `@urauth/express` | `npm i @urauth/express` | Express middleware, guards, and pre-built auth routes |
| `@urauth/fastify` | `npm i @urauth/fastify` | Fastify plugin with guards and route generation |
| `@urauth/hono` | `npm i @urauth/hono` | Hono middleware and guards |
| `@urauth/h3` | `npm i @urauth/h3` | H3/Nitro middleware for Nuxt server routes |

### TypeScript — Frontend

| Package | Install | Description |
|---------|---------|-------------|
| `@urauth/react` | `npm i @urauth/react` | React provider, `useAccess()` hook, TanStack Query integration |
| `@urauth/vue` | `npm i @urauth/vue` | Vue composables — `useAccess()`, `usePermission()`, `useTenant()` |
| `@urauth/next` | `npm i @urauth/next` | Next.js auth utilities |
| `@urauth/nuxt` | `npm i @urauth/nuxt` | Nuxt module |

### Rust

| Package | Description |
|---------|-------------|
| `urauth` (crate) | Rust backend SDK — JWT, bcrypt/argon2, authorization, sessions |

## Quick Start

### FastAPI

```python
from fastapi import Depends, FastAPI
from urauth import Auth, JWT, Password, Permission, Role, UserStore, AuthContext
from urauth.backends.memory import MemoryTokenStore
from urauth.fastapi import FastAuth

class MyUsers(UserStore):
    async def get_user(self, user_id: str):
        return await db.get_user(user_id)

    async def get_user_by_username(self, username: str):
        return await db.get_user_by_username(username)

    async def verify_password(self, user, password: str) -> bool:
        return hasher.verify(password, user.hashed_password)

auth = Auth(
    users=MyUsers(),
    method=JWT(ttl=900, refresh_ttl=604800, store=MemoryTokenStore()),
    secret_key="your-secret-key-here",
    password=Password(),
)
fast = FastAuth(auth)

app = FastAPI()
app.include_router(fast.auto_router())

# Protect routes with guards
can_read = Permission("articles", "read")

@app.get("/articles")
async def list_articles(ctx: AuthContext = Depends(fast.context)):
    return {"user": ctx.user.username, "articles": [...]}

# Compose complex requirements
admin = Role("admin")
editor = Role("editor")

@app.delete("/articles/{id}")
@fast.require((admin) | (editor & Permission("articles", "delete")))
async def delete_article(id: int):
    ...
```

### Express

```typescript
import { Auth } from "@urauth/node";
import { expressAuth } from "@urauth/express";

const core = new Auth({
  config: { secretKey: "...", algorithm: "HS256" },
  getUser: async (id) => db.findUser(id),
});

const auth = expressAuth(core);

app.use(auth.middleware());
app.get("/me", auth.protect(), (req, res) => {
  res.json(req.auth.user);
});
app.delete("/articles/:id", auth.guard(Permission("articles", "delete")), handler);
```

### React

```tsx
import { UrAuthClientProvider, useSession, useAccess } from "@urauth/react";
import { UrAuthClient } from "@urauth/ts";

const client = new UrAuthClient({ baseUrl: "/api/auth" });

function App() {
  return (
    <UrAuthClientProvider client={client}>
      <Dashboard />
    </UrAuthClientProvider>
  );
}

function Dashboard() {
  const { data: session } = useSession();
  const { can } = useAccess();

  return (
    <div>
      <h1>Welcome, {session?.user.name}</h1>
      {can("articles", "create") && <CreateArticleButton />}
    </div>
  );
}
```

### Vue

```vue
<script setup>
import { useAccess, useSession } from "@urauth/vue";

const { data: session } = useSession();
const { can } = useAccess();
</script>

<template>
  <h1>Welcome, {{ session?.user.name }}</h1>
  <CreateArticleButton v-if="can('articles', 'create')" />
</template>
```

## Core Concepts

### AuthContext — the single identity model

Every guard, checker, and hook receives the same `AuthContext` object, whether you're in Python or TypeScript:

```
AuthContext
  .user         — the authenticated user
  .roles        — assigned roles
  .permissions  — resolved permissions
  .relations    — Zanzibar-style relation tuples
  .scopes       — OAuth2 scopes
  .token        — raw token payload
  .tenant       — current tenant context
```

### Composable requirements

Build complex authorization rules by combining primitives:

```python
from urauth import Permission, Role, AllOf, AnyOf

# Simple
can_read = Permission("articles", "read")

# Composed with operators
admin_or_editor = Role("admin") | Role("editor")
can_publish = Role("editor") & Permission("articles", "publish")

# Nested
can_manage = (Role("admin")) | (Role("editor") & Permission("articles", "delete"))
```

The same pattern works in TypeScript:

```typescript
import { Permission, Role, allOf, anyOf } from "@urauth/ts";

const canManage = anyOf(
  new Role("admin"),
  allOf(new Role("editor"), new Permission("articles", "delete"))
);
```

### Wildcard permissions

Permissions support wildcards for broad grants:

| Pattern | Matches |
|---------|---------|
| `articles:read` | Exactly `articles:read` |
| `articles:*` | Any action on `articles` |
| `*:read` | Read action on any resource |
| `*` | Everything |

### Multi-tenant

Model organizational hierarchies and scope roles per tenant:

```python
from urauth import TenantHierarchy, TenantLevel

hierarchy = TenantHierarchy([
    TenantLevel("org"),
    TenantLevel("team"),
    TenantLevel("project"),
])

# Guards are tenant-aware
@auth.require(Permission("docs", "read"), tenant="acme/engineering")
async def read_docs():
    ...
```

## Repository Structure

```
urauth/
├── packages/
│   ├── py/          # Python — pip install urauth
│   ├── ts/          # @urauth/ts — shared TypeScript core
│   ├── node/        # @urauth/node — Node.js backend SDK
│   ├── express/     # @urauth/express
│   ├── fastify/     # @urauth/fastify
│   ├── hono/        # @urauth/hono
│   ├── h3/          # @urauth/h3
│   ├── react/       # @urauth/react
│   ├── vue/         # @urauth/vue
│   ├── next/        # @urauth/next
│   ├── nuxt/        # @urauth/nuxt
│   └── rust/        # urauth Rust crate
└── docs/            # Documentation & tutorials
```

## Development

### Python

```bash
cd packages/py
make install       # uv sync --all-extras
make test          # pytest
make check         # ruff lint + basedpyright typecheck
```

### TypeScript

```bash
bun install        # install all workspace deps
bun run build      # build all packages
bun test           # run tests
```

## License

MIT
