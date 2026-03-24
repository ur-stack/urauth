# Protocols

urauth uses runtime-checkable protocols instead of abstract base classes. Implement the required methods on any class to satisfy the interface -- no inheritance needed.

## TokenStore

Tracks issued and revoked tokens for refresh rotation and reuse detection.

::: urauth.backends.base.TokenStore

## SessionStore

Server-side session storage.

::: urauth.backends.base.SessionStore

## UserProtocol

The minimal interface a user object must satisfy.

::: urauth.types.UserProtocol

## UserWithRoles

A user with role information for role-based access control.

::: urauth.types.UserWithRoles

## TenantUser

A user with tenant context for multi-tenant applications.

::: urauth.types.TenantUser

## PermissionChecker

The protocol for permission checking against an `AuthContext`.

::: urauth.authz.checker.PermissionChecker

## RoleLoader

Loads role definitions from an external source (e.g., a database).

::: urauth.authz.loader.RoleLoader

## RoleCache

Caches resolved role-to-permission mappings to avoid repeated lookups.

::: urauth.authz.loader.RoleCache
