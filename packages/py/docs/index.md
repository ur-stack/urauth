# urauth

**Framework-agnostic authentication and authorization for Python.**

urauth gives you a single, composable auth layer that works with any Python framework. Subclass `Auth`, pick your auth method, and get JWT auth, OAuth2, RBAC, guards, and more -- with zero boilerplate.

### JWT Auth

Issue, validate, rotate, and revoke JWTs out of the box. Access + refresh token pairs with configurable TTL, family-based reuse detection, and pluggable token stores.

### OAuth2 & Social Login

Google, GitHub, Microsoft, Apple, Discord, GitLab -- add social login with a single provider config. Magic link and OTP login methods included.

### Access Control

Define roles with permissions and inheritance via `RoleRegistry`. Use `PermissionEnum` for type-safe permission definitions. Wildcards (`*`, `user:*`) supported.

### Guards & Requirements

Composable `Permission`, `Role`, and `Relation` primitives with `&` (AND) and `|` (OR) operators. Every guard works as both a `@decorator` and `Depends()`.

### Auth Methods & Login Methods

Configure your auth method (`JWT`, `Session`, `BasicAuth`, `APIKey`, `Fallback`) and login methods (`Password`, `OTP`, `MagicLink`, `Passkey`, `OAuth`, `MFA`) directly on the `Auth` instance, and `auto_router()` generates all routes.

### Multi-Tenant & Hierarchy

Flat or hierarchical tenants (Organization -> Department -> Team). Configurable resolution from JWT claims, headers, paths, or subdomains. Cascading permissions and default role provisioning. Use `namespace=` for multi-project auth separation.

### Pluggable Transports

Bearer header, HTTP-only cookie, or hybrid (try bearer then cookie). Swap transports without touching your application code.

### Protocol-Based

`TokenStore`, `SessionStore`, `PermissionChecker`, `UserProtocol` -- every extension point is a Python `Protocol`. No base classes to inherit, no vendor lock-in.

### Rate Limiting

Built-in `RateLimiter` with pluggable key strategies. Protect login endpoints from brute-force attacks without external dependencies.

## Quick Start

Build a complete auth system for a SaaS task manager in under 50 lines.

### 1. Define your Auth subclass

```python
from dataclasses import dataclass, field

from urauth import Auth, AuthContext, JWT, Password, PasswordHasher, Permission, RoleRegistry
from urauth.backends.memory import MemoryTokenStore
from urauth.fastapi import FastAuth

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

# Core setup
core = MyAuth(
    method=JWT(ttl=900, refresh_ttl=604800, store=MemoryTokenStore()),
    secret_key="your-secret-key-change-in-production",
    password=Password(),
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
app.include_router(auth.auto_router())


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

## Installation

| Extra | Command | Includes |
|-------|---------|---------|
| Base | `pip install urauth` | Core primitives, JWT, password hashing |
| FastAPI | `pip install "urauth[fastapi]"` | `FastAuth`, guards, access control, transports, pre-built routers |
| OAuth | `pip install "urauth[oauth]"` | OAuth2 client for social login providers |
| Redis | `pip install "urauth[redis]"` | Redis-backed token store and session store |
| All | `pip install "urauth[all]"` | Everything above |

## Next Steps

### [Tutorial](tutorial/index.md)

Step-by-step guide from first install to multi-tenant RBAC. Start here if you are new to urauth.

### [How-To Guides](how-to/index.md)

Task-oriented recipes for common scenarios like custom token stores, database-backed roles, and testing.

### [Best Practices](best-practices/index.md)

Security, architecture, multi-tenancy, and testing recommendations with real-world examples.

### [Reference](reference/index.md)

Complete API reference for every class, method, and protocol.

