# fastapi-auth

**Unified authentication & authorization for FastAPI — JWT, OAuth2, RBAC, multi-tenant in ~15 lines of setup.**

---

<div class="grid cards" markdown>

-   :material-key-variant: **JWT Authentication**

    Access & refresh tokens, rotation, reuse detection, revocation — all built in.

-   :material-account-group: **OAuth2 & Social Login**

    Google, GitHub, Microsoft, Apple, Discord, GitLab — register a provider in one call.

-   :material-shield-lock: **RBAC & Permissions**

    Role hierarchies with transitive inheritance, wildcard permissions, scope checks.

-   :material-domain: **Multi-Tenant**

    Resolve tenants from JWT claims, headers, path params, or subdomains.

-   :material-swap-horizontal: **Pluggable Transports**

    Bearer, cookie, header, or hybrid — swap without changing your routes.

-   :material-connection: **Protocol-Based**

    No base classes to inherit. Implement a protocol, plug it in, done.

</div>

---

## Quick Start

```python
from dataclasses import dataclass
from fastapi import Depends, FastAPI
from fastapi_auth import AuthConfig, FastAPIAuth


@dataclass
class User:
    id: str
    username: str
    hashed_password: str
    is_active: bool = True


class MyBackend:
    """Implement three methods — that's the entire contract."""

    async def get_by_id(self, user_id):
        ...  # fetch user from your DB

    async def get_by_username(self, username):
        ...  # fetch user by username/email

    async def verify_password(self, user, password):
        ...  # compare plaintext against stored hash


auth = FastAPIAuth(
    MyBackend(),
    AuthConfig(secret_key="your-production-secret"),  # (1)!
)

app = FastAPI(lifespan=auth.lifespan())
app.include_router(auth.password_auth_router())


@app.get("/me")
async def me(user=Depends(auth.current_user())):
    return {"id": user.id, "username": user.username}
```

1. Never use the default `"CHANGE-ME-IN-PRODUCTION"` in production. Set `AUTH_SECRET_KEY` via environment variable.

## Installation

=== "Base"

    ```bash
    pip install fastapi-auth
    ```

=== "With OAuth"

    ```bash
    pip install "fastapi-auth[oauth]"
    ```

=== "With Redis"

    ```bash
    pip install "fastapi-auth[redis]"
    ```

=== "Everything"

    ```bash
    pip install "fastapi-auth[all]"
    ```

## Next Steps

Ready to build? Start with the **[Tutorial](tutorial/index.md)** — it walks you through every feature, one step at a time.

Need a specific recipe? Jump to the **[How-To Guides](how-to/index.md)**.

Looking for API details? Check the **[Reference](reference/index.md)**.
