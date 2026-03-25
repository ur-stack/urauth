# Multi-Tenant

urauth supports multi-tenant applications where users belong to specific tenants (organizations, workspaces, teams).

## Enable Multi-Tenant

Set `tenant_enabled=True` in `AuthConfig`:

```python
from urauth.auth import Auth
from urauth.backends.memory import MemoryTokenStore
from urauth.config import AuthConfig
from urauth.fastapi.auth import FastAuth

config = AuthConfig(
    secret_key="your-secret",
    tenant_enabled=True,
)

class MyAuth(Auth):
    async def get_user(self, user_id):
        ...

    async def get_user_by_username(self, username):
        ...

    async def verify_password(self, user, password):
        ...


core = MyAuth(config=config, token_store=MemoryTokenStore())
auth = FastAuth(core)
```

## Tenant Resolution Chain

The `TenantResolver` tries to resolve the tenant ID from multiple sources, in order:

=== "JWT Claim"

    The tenant ID is embedded in the access token:

    ```python
    from urauth.tokens.lifecycle import IssueRequest

    # When issuing tokens, include tenant_id
    pair = await core.lifecycle.issue(IssueRequest(
        user_id="1",
        tenant_id="acme-corp",
    ))
    ```

    The resolver reads the `tenant_id` claim from the JWT.

=== "Header"

    Send the tenant ID as a request header:

    ```bash
    curl http://localhost:8000/api/data \
      -H "Authorization: Bearer eyJ..." \
      -H "X-Tenant-ID: acme-corp"
    ```

    Configure the header name:

    ```python
    config = AuthConfig(
        tenant_enabled=True,
        tenant_header="X-Tenant-ID",  # default
    )
    ```

=== "Path Parameter"

    Include the tenant in the URL path:

    ```python
    from fastapi import Depends

    @app.get("/tenants/{tenant_id}/data")
    async def get_data(
        tenant_id: str,
        tenant=Depends(resolver.current_tenant()),
    ):
        ...
    ```

=== "Subdomain"

    Resolve from the request hostname:

    ```
    https://acme-corp.yourapp.com/api/data
    ```

    The resolver extracts the first segment of the hostname (`acme-corp`).

The resolver tries each source in order (JWT -> header -> path -> subdomain) and returns the first non-empty value.

## Using the Tenant Dependency

```python
from urauth.fastapi.authz.multi_tenant import TenantResolver

resolver = TenantResolver(config)

@app.get("/data")
async def get_data(tenant_id: str = Depends(resolver.current_tenant())):
    return {"tenant": tenant_id, "data": "..."}
```

!!! warning
    If no tenant can be resolved from any source, the dependency raises `403 Forbidden`.

## The TenantUser Protocol

For users that carry tenant information, add a `tenant_id` attribute to your user model:

```python
from dataclasses import dataclass, field


@dataclass
class User:
    id: str
    username: str
    hashed_password: str
    is_active: bool = True
    roles: list[str] = field(default_factory=list)
    tenant_id: str = ""
```

The `TenantUser` protocol requires `id`, `is_active`, and `tenant_id` properties. Any object with those attributes satisfies it.

## Combining with RBAC

Tenants and roles work together naturally. A user can be an `admin` in one tenant and a `viewer` in another:

```python
from fastapi import Depends
from starlette.requests import Request

from urauth.authz.primitives import Role
from urauth.fastapi.authz.multi_tenant import TenantResolver

resolver = TenantResolver(config)

@app.get("/tenant/settings")
@auth.require(Role("admin"))
async def tenant_settings(
    request: Request,
    tenant_id: str = Depends(resolver.current_tenant()),
    ctx=Depends(auth.context),
):
    return {"tenant": tenant_id, "user": ctx.user.id}
```

You can also use `AccessControl` guards alongside the tenant resolver:

```python
access = auth.access_control(registry=registry)

@app.get("/tenant/users")
@access.guard(Perms.USER_READ)
async def tenant_users(
    request: Request,
    tenant_id: str = Depends(resolver.current_tenant()),
):
    return {"tenant": tenant_id, "users": [...]}
```

For tenant-scoped role loading, override `get_user_roles` to return roles specific to the resolved tenant:

```python
class MyAuth(Auth):
    async def get_user_roles(self, user):
        from urauth.authz.primitives import Role

        # Load roles for the user's current tenant
        rows = await db.execute(
            "SELECT role_name FROM tenant_user_roles "
            "WHERE user_id = :uid AND tenant_id = :tid",
            {"uid": user.id, "tid": user.tenant_id},
        )
        return [Role(row.role_name) for row in rows]
```

## Recap

- Set `tenant_enabled=True` in `AuthConfig`.
- `TenantResolver` (imported from `urauth.fastapi.authz.multi_tenant`) resolves tenant IDs from JWT claims, headers, path params, or subdomains.
- `resolver.current_tenant()` is a FastAPI dependency that returns the resolved tenant ID.
- Returns `403` if no tenant can be resolved.
- Add a `tenant_id` attribute to your user model to satisfy the `TenantUser` protocol.
- Combine tenant resolution with `auth.require()`, `access.guard()`, and tenant-scoped role loading for per-tenant authorization.
