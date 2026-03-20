# urauth

Unified authentication & authorization — JWT, OAuth2, RBAC, multi-tenant.

Framework-agnostic core with adapters for FastAPI, Flask, and Django. TypeScript packages for frontend integration.

## Packages

### Python

| Package | Install | Description |
|---------|---------|-------------|
| `urauth` | `pip install urauth` | Core: JWT, password hashing, RBAC, permissions |
| `urauth[fastapi]` | `pip install urauth[fastapi]` | FastAPI adapter: dependencies, routers, middleware |
| `urauth[flask]` | _coming soon_ | Flask adapter |
| `urauth[django]` | _coming soon_ | Django adapter |

### TypeScript / JavaScript

| Package | Install | Description |
|---------|---------|-------------|
| `@urauth/ts` | `npm i @urauth/ts` | Core: JWT verification, types, exceptions |
| `@urauth/node` | `npm i @urauth/node` | Node.js backend: middleware, sessions |
| `@urauth/vue` | _coming soon_ | Vue composables |
| `@urauth/nuxt` | _coming soon_ | Nuxt module |

## Quick Start (FastAPI)

```python
from urauth import AuthConfig
from urauth.fastapi import FastAPIAuth

auth = FastAPIAuth(my_backend, AuthConfig(secret_key="..."))
app = FastAPI(lifespan=auth.lifespan())
auth.init_app(app)
app.include_router(auth.password_auth_router())

@app.get("/me")
async def me(user=auth.current_user()):
    return user
```

## Repository Structure

```
urauth/
├── packages/
│   ├── py/          # Python package (pip install urauth)
│   ├── ts/          # @urauth/ts
│   ├── node/        # @urauth/node (stub)
│   ├── vue/         # @urauth/vue (stub)
│   └── nuxt/        # @urauth/nuxt (stub)
└── pnpm-workspace.yaml
```

## License

MIT
