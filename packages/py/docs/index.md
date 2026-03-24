# urauth

**Framework-agnostic authentication and authorization for Python.**

urauth gives you a single, composable auth layer that works with any Python framework. Subclass one class, override a few methods, and get JWT auth, OAuth2, RBAC, guards, and more -- with zero boilerplate.

---

<div class="grid cards" markdown>

-   :material-key-variant: **JWT Auth**

    ---

    Issue, validate, rotate, and revoke JWTs out of the box. Access + refresh token pairs with configurable TTL, family-based reuse detection, and pluggable token stores.

-   :material-account-key: **OAuth2 & Social Login**

    ---

    Google, GitHub, Microsoft, Apple, Discord, GitLab -- add social login with a single provider config. Magic link and OTP login methods included.

-   :material-shield-lock: **RBAC & Permissions**

    ---

    Define roles with permissions and inheritance via `RoleRegistry`. Use `PermissionEnum` for type-safe permission definitions. Wildcards (`*`, `user:*`) supported.

-   :material-gate: **Guards & Requirements**

    ---

    Composable `Permission`, `Role`, and `Relation` primitives with `&` (AND) and `|` (OR) operators. Every guard works as both a `@decorator` and `Depends()`.

-   :material-pipe: **Pipeline Config**

    ---

    Declare your entire auth setup in one `Pipeline` object -- strategy, login methods, MFA, password reset, account linking -- and `auto_router()` generates all routes.

-   :material-domain: **Multi-Tenant**

    ---

    Tenant-scoped authentication with configurable tenant header and JWT claims. Scoped permission checks via `scope=` and `scope_from=` parameters.

-   :material-swap-horizontal: **Pluggable Transports**

    ---

    Bearer header, HTTP-only cookie, or hybrid (try bearer then cookie). Swap transports without touching your application code.

-   :material-code-tags: **Protocol-Based**

    ---

    `TokenStore`, `SessionStore`, `PermissionChecker`, `UserProtocol` -- every extension point is a Python `Protocol`. No base classes to inherit, no vendor lock-in.

-   :material-speedometer: **Rate Limiting**

    ---

    Built-in `RateLimiter` with pluggable key strategies. Protect login endpoints from brute-force attacks without external dependencies.

</div>

---

## Quick Start

Build a complete auth system for a SaaS task manager in under 50 lines.

### 1. Define your Auth subclass

```python
from dataclasses import dataclass, field

from urauth import Auth, AuthConfig, PasswordHasher
from urauth.backends.memory import MemoryTokenStore

hasher = PasswordHasher()


# Your user model -- any object with `id` and `is_active` works
@dataclass
class User:
    id: str
    username: str
    hashed_password: str
    is_active: bool = True
    roles: list[str] = field(default_factory=list)


# Fake database
USERS_DB: dict[str, User] = {
    "1": User(id="1", username="alice", hashed_password=hasher.hash("secret"), roles=["admin"]),
    "2": User(id="2", username="bob", hashed_password=hasher.hash("secret"), roles=["member"]),
}


class MyAuth(Auth):
    async def get_user(self, user_id):
        return USERS_DB.get(str(user_id))

    async def get_user_by_username(self, username):
        return next((u for u in USERS_DB.values() if u.username == username), None)

    async def verify_password(self, user, password):
        return hasher.verify(password, user.hashed_password)
```

### 2. Wire up FastAPI

```python
from fastapi import Depends, FastAPI

from urauth import AuthContext, Permission, RoleRegistry
from urauth.fastapi import FastAuth

# Core setup
core = MyAuth(
    config=AuthConfig(secret_key="your-secret-key-change-in-production"),
    token_store=MemoryTokenStore(),
)
auth = FastAuth(core)

# Role registry
registry = RoleRegistry()
registry.role("admin", permissions=["*"])
registry.role("member", permissions=["task:read", "task:write"])

# Access control
access = auth.access_control(registry=registry)

# App
app = FastAPI(lifespan=auth.lifespan())
auth.init_app(app)
app.include_router(auth.password_auth_router())


# Protected routes
@app.get("/me")
async def get_me(user=Depends(auth.current_user)):
    return {"id": user.id, "username": user.username}


@app.get("/tasks")
@access.guard("task", "read")
async def list_tasks(request):
    return [{"id": "1", "title": "Ship v1"}]


@app.post("/tasks")
@auth.require(Permission("task", "write"))
async def create_task(ctx: AuthContext = Depends(auth.context)):
    return {"created_by": ctx.user.username}
```

---

## Installation

=== "Base"

    ```bash
    pip install urauth
    ```

    Core auth primitives, JWT tokens, password hashing. No framework dependency.

=== "FastAPI"

    ```bash
    pip install "urauth[fastapi]"
    ```

    Adds `FastAuth`, guards, access control, transports, and pre-built routers.

=== "OAuth"

    ```bash
    pip install "urauth[oauth]"
    ```

    Adds OAuth2 client support for social login providers.

=== "Redis"

    ```bash
    pip install "urauth[redis]"
    ```

    Adds Redis-backed token store and session store for production deployments.

=== "Everything"

    ```bash
    pip install "urauth[all]"
    ```

    All optional dependencies: FastAPI, OAuth, Redis.

---

## Next Steps

<div class="grid cards" markdown>

-   :material-school: **[Tutorial](tutorial/index.md)**

    ---

    Step-by-step guide from first install to multi-tenant RBAC. Start here if you are new to urauth.

-   :material-book-open-variant: **[How-To Guides](how-to/index.md)**

    ---

    Task-oriented recipes for common scenarios like custom token stores, database-backed roles, and testing.

-   :material-api: **[Reference](reference/index.md)**

    ---

    Complete API reference for every class, method, and protocol.

</div>
