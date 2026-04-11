# Tenant Hierarchy

Multi-level tenant hierarchy support. Defines configurable hierarchies (Organization -> Department -> Team), runtime tenant paths, database-backed resolution protocols, and default role provisioning for new tenants.

## TenantHierarchy

Schema definition for the tenant hierarchy, configured once at startup. Defines the ordered sequence of levels and provides navigation methods.


> **`urauth.tenant.hierarchy.TenantHierarchy`** — See source code for full API.


## TenantLevel

A named level in the hierarchy (e.g., "organization", "department", "team").


> **`urauth.tenant.hierarchy.TenantLevel`** — See source code for full API.


## TenantNode

A single segment in a tenant path: a concrete tenant at a specific level.


> **`urauth.tenant.hierarchy.TenantNode`** — See source code for full API.


## TenantPath

Ordered path from root to leaf in the tenant hierarchy. Replaces the flat `tenant_id` string with full hierarchy context. The `leaf_id` property provides backward compatibility with code that expects a single tenant ID.


> **`urauth.tenant.hierarchy.TenantPath`** — See source code for full API.


## TenantStore

Protocol for tenant hierarchy persistence. Implement this to back the hierarchy with your database.


> **`urauth.tenant.protocols.TenantStore`** — See source code for full API.


## TenantRoleProvisioner

Protocol for creating default roles when a tenant is provisioned.


> **`urauth.tenant.protocols.TenantRoleProvisioner`** — See source code for full API.


## RoleTemplate

Blueprint for a default role to create in a new tenant.


> **`urauth.tenant.defaults.RoleTemplate`** — See source code for full API.


## TenantDefaults

Registry mapping tenant level names to default role templates. Provides `register()` to define templates and `provision()` to create them via a `TenantRoleProvisioner`.


> **`urauth.tenant.defaults.TenantDefaults`** — See source code for full API.


## TenantGuard

FastAPI guard ensuring the authenticated user is within a tenant context. Optionally restricts to a specific hierarchy level and/or requires an additional authorization requirement. Works as both a `@decorator` and `Depends()`.


> **`urauth.fastapi.authz.tenant_guard.TenantGuard`** — See source code for full API.


## HierarchicalTenantUser

Protocol for users scoped to a hierarchical tenant with full path context.


> **`urauth.types.HierarchicalTenantUser`** — See source code for full API.

