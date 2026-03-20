# Multi-Tenant

fastapi-auth supports multi-tenant applications where users belong to specific tenants (organizations, workspaces, teams).

## Enable Multi-Tenant

```python
from fastapi_auth import AuthConfig

config = AuthConfig(
    secret_key="your-secret",
    tenant_enabled=True,
)
```

## Tenant Resolution Chain

The `TenantResolver` tries to resolve the tenant ID from multiple sources, in order:

=== "JWT Claim"

    The tenant ID is embedded in the access token:

    ```python
    # When creating tokens, include tenant_id
    token_service.create_access_token(
        user_id="1",
        tenant_id="acme-corp",
    )
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

The resolver tries each source in order (JWT → header → path → subdomain) and returns the first non-empty value.

## Using the Tenant Dependency

```python
from fastapi_auth.authz.multi_tenant import TenantResolver

resolver = TenantResolver(config)

@app.get("/data")
async def get_data(tenant_id: str = Depends(resolver.current_tenant())):
    return {"tenant": tenant_id, "data": "..."}
```

!!! warning
    If no tenant can be resolved from any source, the dependency raises `403 Forbidden`.

## The TenantUser Protocol

For users that carry tenant information, implement the `TenantUser` protocol:

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

`TenantUser` extends `UserWithRoles` and adds a `tenant_id` property.

## Combining with RBAC

Tenants and roles work together naturally. A user can be an `admin` in one tenant and a `viewer` in another:

```python
@app.get("/tenant/settings")
async def tenant_settings(
    user=Depends(auth.current_user(roles=["admin"])),
    tenant_id: str = Depends(resolver.current_tenant()),
):
    return {"tenant": tenant_id, "user": user.id}
```

## Recap

- Set `tenant_enabled=True` in `AuthConfig`.
- `TenantResolver` resolves tenant IDs from JWT claims, headers, path params, or subdomains.
- `resolver.current_tenant()` is a FastAPI dependency that returns the resolved tenant ID.
- Returns `403` if no tenant can be resolved.
- Implement `TenantUser` protocol for users with tenant context.
