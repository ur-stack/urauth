# Protocols

fastapi-auth uses runtime-checkable protocols instead of base classes. Implement the required methods on any class.

## UserBackend

The primary interface for user data access.

::: fastapi_auth.backends.base.UserBackend

## TokenStore

Tracks issued and revoked tokens for refresh rotation and reuse detection.

::: fastapi_auth.backends.base.TokenStore

## SessionStore

Server-side session storage.

::: fastapi_auth.backends.base.SessionStore

## UserProtocol

The minimal interface a user object must satisfy.

::: fastapi_auth.types.UserProtocol

## UserWithRoles

A user with role information for RBAC.

::: fastapi_auth.types.UserWithRoles

## TenantUser

A user with tenant context for multi-tenant applications.

::: fastapi_auth.types.TenantUser
