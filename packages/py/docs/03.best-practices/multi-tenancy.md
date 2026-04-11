# Multi-Tenancy

## Choose the Right Tenant Model

| Pattern | When to use | urauth approach |
|---------|------------|-----------------|
| **Flat tenant** | Simple SaaS with isolated workspaces | `tenant_enabled=True`, `TenantResolver.current_tenant()` |
| **Hierarchical tenant** | Enterprise with org/department/team structure | `tenant_hierarchy_enabled=True`, `TenantResolver.current_tenant_path()` |
| **No tenant** | Single-tenant or B2C apps | Default (disabled) |

## Embed Tenant in Tokens, Not Just Headers

Relying solely on headers for tenant context is fragile -- clients can send wrong headers. Embed the tenant in the JWT at login time:

```python
# At login, determine the user's tenant and embed it
pair = await core.lifecycle.issue(IssueRequest(
    user_id=user.id,
    tenant_path={"organization": "acme", "team": "backend"},
))
```

The JWT then carries the tenant context, and `TenantResolver` reads it first before falling back to headers.

## Use TenantDefaults to Bootstrap Tenants

When provisioning new tenants (customer signup, org creation), always create default roles. This ensures every tenant has a consistent starting point:

```python
from urauth.tenant import TenantDefaults, RoleTemplate

defaults = TenantDefaults()
defaults.register("organization", [
    RoleTemplate("owner", permissions=["org:*"], description="Full access"),
    RoleTemplate("admin", permissions=["org:manage", "user:*", "task:*"]),
    RoleTemplate("member", permissions=["task:read", "task:write"]),
    RoleTemplate("viewer", permissions=["task:read"]),
])
```

## Scope Permissions to Tenant Levels

Override `get_tenant_permissions()` to load permissions per hierarchy level. This enables cascading inheritance -- an org-level admin is automatically admin in all departments and teams:

```python
class MyAuth(Auth):
    async def get_tenant_permissions(self, user, level, tenant_id):
        rows = await db.fetch_permissions(user.id, tenant_id)
        return [Permission(r.permission) for r in rows]
```

## Guard with require_tenant()

Always use `require_tenant()` on endpoints that operate on tenant data. This prevents accidental cross-tenant data access:

```python
@app.get("/org/settings")
@auth.require_tenant(level="organization", requirement=Permission("org", "admin"))
async def org_settings(ctx: AuthContext = Depends(auth.context)):
    org_id = ctx.at_level("organization")
    return await load_settings(org_id)
```
