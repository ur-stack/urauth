# Role Registry

Composable role management with inheritance, permission mapping, and pluggable checkers. Define roles with `RoleRegistry`, compose them with `include()`, and optionally back them with a database via `with_loader()`.

All checkers use semantic matching and are separator-agnostic -- permissions like `"task:read"` and `"task.read"` are matched equivalently without requiring an explicit `separator` parameter.

## RoleRegistry

Defines roles with their associated permissions and supports inheritance between roles.


> **`urauth.authz.roles.RoleRegistry`** — See source code for full API.


## RoleExpandingChecker

A permission checker that expands roles into their constituent permissions before checking access.


> **`urauth.authz.checker.RoleExpandingChecker`** — See source code for full API.


## StringChecker

The default permission checker that uses string matching with wildcard support.


> **`urauth.authz.checker.StringChecker`** — See source code for full API.


## MemoryRoleCache

An in-memory cache for resolved role-to-permission mappings. Suitable for development and single-process deployments.


> **`urauth.authz.cache.MemoryRoleCache`** — See source code for full API.


## RedisRoleCache

A Redis-backed cache for resolved role-to-permission mappings. Suitable for production multi-process deployments.


> **`urauth.authz.cache.RedisRoleCache`** — See source code for full API.

