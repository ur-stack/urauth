# Real-World Examples

Complete implementations for three common application types, showing how urauth's features come together in production scenarios.

## SaaS Platform (Project Management Tool)

A multi-tenant SaaS where organizations have projects and teams:

```python
from urauth import (
    Auth, AuthConfig, Permission, RoleRegistry, PermissionEnum,
    TenantHierarchy, TenantDefaults, RoleTemplate,
)
from urauth.backends.memory import MemoryTokenStore
from urauth.fastapi import FastAuth
from urauth.fastapi.authz.multi_tenant import TenantResolver

# 1. Define permissions
class Perms(PermissionEnum):
    PROJECT_READ = ("project", "read")
    PROJECT_WRITE = ("project", "write")
    PROJECT_DELETE = ("project", "delete")
    MEMBER_INVITE = ("member", "invite")
    MEMBER_REMOVE = ("member", "remove")
    ORG_ADMIN = ("org", "admin")

# 2. Define role hierarchy
registry = RoleRegistry()
registry.role("viewer", permissions=["project:read"])
registry.role("contributor", permissions=["project:write"], inherits=["viewer"])
registry.role("manager", permissions=["member:invite", "member:remove"], inherits=["contributor"])
registry.role("org_admin", permissions=["org:admin", "project:delete"], inherits=["manager"])

# 3. Define tenant hierarchy
hierarchy = TenantHierarchy(["organization", "project"])

# 4. Default roles for new tenants
defaults = TenantDefaults()
defaults.register("organization", [
    RoleTemplate("org_admin", permissions=["org:admin"]),
    RoleTemplate("member", permissions=["project:read"]),
])
defaults.register("project", [
    RoleTemplate("manager", permissions=["project:write", "member:invite"]),
    RoleTemplate("contributor", permissions=["project:write"]),
    RoleTemplate("viewer", permissions=["project:read"]),
])

# 5. Configure
config = AuthConfig(
    secret_key="your-production-secret",
    tenant_enabled=True,
    tenant_hierarchy_enabled=True,
    tenant_hierarchy_levels=["organization", "project"],
)

# 6. Set up auth
class SaaSAuth(Auth):
    async def get_user(self, user_id):
        return await db.get_user(user_id)

    async def get_user_by_username(self, username):
        return await db.get_user_by_email(username)

    async def verify_password(self, user, password):
        return hasher.verify(password, user.hashed_password)

    async def get_tenant_permissions(self, user, level, tenant_id):
        """Load permissions from tenant membership."""
        rows = await db.get_member_permissions(user.id, tenant_id)
        return [Permission(r) for r in rows]

core = SaaSAuth(config=config, token_store=MemoryTokenStore())
auth = FastAuth(core)
access = auth.access_control(registry=registry)
resolver = TenantResolver(config)

# 7. Use in routes
@app.get("/projects")
@auth.require_tenant(level="organization")
@access.guard(Perms.PROJECT_READ)
async def list_projects(request: Request, ctx: AuthContext = Depends(auth.context)):
    org_id = ctx.at_level("organization")
    return await db.get_projects(org_id)

@app.post("/projects/{project_id}/members")
@auth.require_tenant()
@access.guard(Perms.MEMBER_INVITE)
async def invite_member(project_id: str, request: Request):
    ...
```

## Enterprise Application (Multi-Division Company)

An internal enterprise app with a deep organizational hierarchy:

```python
from urauth import TenantHierarchy, TenantDefaults, RoleTemplate

# Deep hierarchy: Company -> Division -> Department -> Team
hierarchy = TenantHierarchy(["company", "division", "department", "team"])

# Cascading defaults -- each level gets appropriate roles
defaults = TenantDefaults()
defaults.register("company", [
    RoleTemplate("company_admin", permissions=["company:*"]),
    RoleTemplate("hr", permissions=["user:read", "user:manage"]),
    RoleTemplate("employee", permissions=["task:read"]),
])
defaults.register("division", [
    RoleTemplate("division_lead", permissions=["division:manage", "budget:read"]),
    RoleTemplate("division_member", permissions=["task:read", "task:write"]),
])
defaults.register("department", [
    RoleTemplate("department_head", permissions=["department:manage", "review:write"]),
    RoleTemplate("department_member", permissions=["task:read", "task:write"]),
])
defaults.register("team", [
    RoleTemplate("team_lead", permissions=["team:manage", "task:assign"]),
    RoleTemplate("team_member", permissions=["task:read", "task:write"]),
])

# Cascading permissions: a company_admin is admin everywhere
class EnterpriseAuth(Auth):
    async def get_tenant_permissions(self, user, level, tenant_id):
        """Permissions at higher levels cascade to all children."""
        return await db.get_member_permissions(user.id, tenant_id)

# Usage in routes
@app.get("/team/{team_id}/tasks")
@auth.require_tenant(level="team")
async def team_tasks(team_id: str, ctx: AuthContext = Depends(auth.context)):
    # User has permissions from company + division + department + team
    # A company_admin can see any team's tasks
    return await db.get_tasks(team_id)

@app.get("/division/{div_id}/budget")
@auth.require_tenant(level="division", requirement=Permission("budget", "read"))
async def division_budget(div_id: str, ctx: AuthContext = Depends(auth.context)):
    return await db.get_budget(div_id)
```

## Marketplace (Multi-Sided Platform)

A marketplace with vendors, stores, and staff:

```python
from urauth import (
    Permission, Role, Relation, RelationTuple, RoleRegistry,
    TenantHierarchy, TenantDefaults, RoleTemplate,
)

# Hierarchy: Platform -> Vendor -> Store
hierarchy = TenantHierarchy(["platform", "vendor", "store"])

# Platform-level roles
registry = RoleRegistry()
registry.role("platform_admin", permissions=["*"])
registry.role("vendor_owner", permissions=["vendor:*", "store:*", "product:*", "order:*"])
registry.role("store_manager", permissions=["store:manage", "product:*", "order:*"])
registry.role("store_staff", permissions=["product:read", "order:read", "order:fulfill"])

# Default roles when a new vendor signs up
defaults = TenantDefaults()
defaults.register("vendor", [
    RoleTemplate("owner", permissions=["vendor:*"]),
    RoleTemplate("manager", permissions=["store:manage", "product:*"]),
    RoleTemplate("accountant", permissions=["order:read", "payout:read"]),
])
defaults.register("store", [
    RoleTemplate("store_manager", permissions=["store:manage", "product:*", "order:*"]),
    RoleTemplate("staff", permissions=["product:read", "order:read", "order:fulfill"]),
])

# Combine hierarchy with Zanzibar-style relations for resource-level access
class MarketplaceAuth(Auth):
    async def get_user_relations(self, user):
        """Load resource-level ownership relations."""
        rels = await db.get_user_relations(user.id)
        return [RelationTuple(Relation(r.resource, r.type), r.resource_id) for r in rels]

    async def get_tenant_permissions(self, user, level, tenant_id):
        return await db.get_member_permissions(user.id, tenant_id)

# Routes
@app.get("/vendor/{vendor_id}/stores")
@auth.require_tenant(level="vendor")
async def list_stores(vendor_id: str, ctx: AuthContext = Depends(auth.context)):
    return await db.get_stores(vendor_id)

@app.put("/products/{product_id}")
@auth.require_tenant()
@auth.require(Role("store_manager") | Relation("product", "owner"))
async def update_product(product_id: str, ctx: AuthContext = Depends(auth.context)):
    ...
```
