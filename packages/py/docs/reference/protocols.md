# Protocols

urauth uses runtime-checkable protocols instead of abstract base classes. Implement the required methods on any class to satisfy the interface -- no inheritance needed.

## TokenStore

Tracks issued and revoked tokens for refresh rotation and reuse detection.


> **`urauth.backends.base.TokenStore`** — See source code for full API.


## SessionStore

Server-side session storage.


> **`urauth.backends.base.SessionStore`** — See source code for full API.


## UserProtocol

The minimal interface a user object must satisfy.


> **`urauth.types.UserProtocol`** — See source code for full API.


## UserWithRoles

A user with role information for role-based access control.


> **`urauth.types.UserWithRoles`** — See source code for full API.


## TenantUser

A user with tenant context for multi-tenant applications.


> **`urauth.types.TenantUser`** — See source code for full API.


## HierarchicalTenantUser

A user with full hierarchy context for hierarchical multi-tenant applications.


> **`urauth.types.HierarchicalTenantUser`** — See source code for full API.


## TenantStore

Protocol for tenant hierarchy persistence. Implement this to resolve tenant paths from your database.


> **`urauth.tenant.protocols.TenantStore`** — See source code for full API.


## TenantRoleProvisioner

Protocol for creating default roles when a new tenant is provisioned.


> **`urauth.tenant.protocols.TenantRoleProvisioner`** — See source code for full API.


## PermissionChecker

The protocol for permission checking against an `AuthContext`.


> **`urauth.authz.checker.PermissionChecker`** — See source code for full API.


## RoleLoader

Loads role definitions from an external source (e.g., a database).


> **`urauth.authz.loader.RoleLoader`** — See source code for full API.


## RoleCache

Caches resolved role-to-permission mappings to avoid repeated lookups.


> **`urauth.authz.loader.RoleCache`** — See source code for full API.

