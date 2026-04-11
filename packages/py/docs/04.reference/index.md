# API Reference

Complete API reference for the `urauth` Python package. All documentation is auto-generated from source code docstrings.

## Modules

| Module | Description |
|--------|-------------|
| [Auth](auth.md) | Framework-agnostic base class with sync/async support |
| [FastAuth](fastauth.md) | FastAPI adapter -- single entry point for FastAPI integration |
| [AuthContext](context.md) | Single identity model holding user, roles, permissions, and request |
| [Configuration](config.md) | Auth() flat config, AuthConfig (internal), UserDataMixin |
| [Protocols](protocols.md) | Runtime-checkable protocols: TokenStore, SessionStore, UserProtocol, PermissionChecker |
| [Primitives](primitives.md) | Typed, composable auth primitives: Permission, Role, Relation, RelationTuple, RelationEnum, Action, Resource |
| [Role Registry](role-registry.md) | RoleRegistry, checkers, and role caches |
| [Access Control](access-control.md) | AccessControl, guards, and checker-based authorization |
| [Auth Methods](pipeline.md) | Auth methods (JWT, Session, etc.), login methods (Password, OTP, etc.), result types |
| [Tokens](tokens.md) | TokenLifecycle, TokenService, IssueRequest, IssuedTokenPair |
| [Transport](transport.md) | Pluggable token extraction: bearer, cookie, hybrid |
| [Rate Limiting](ratelimit.md) | Framework-agnostic and FastAPI rate limiting |
| [Tenant Hierarchy](tenant.md) | TenantHierarchy, TenantPath, TenantDefaults, RoleTemplate, TenantGuard |
| [OAuth2](oauth2.md) | OAuth2 provider models and tenant resolution |
| [Sessions](sessions.md) | In-memory and Redis session and token stores |
| [Middleware](middleware.md) | CSRF protection and automatic token refresh |
| [Exceptions](exceptions.md) | Auth error hierarchy |
| [Testing](testing.md) | Test utilities for FastAPI integration tests |
