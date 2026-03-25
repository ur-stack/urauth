# Access Control

Role-Based Access Control (RBAC) lets you define roles with fine-grained permissions and inheritance. urauth uses a `RoleRegistry` to declare roles statically or load them from a database, and a checker-based system to evaluate permissions at runtime.

## RoleRegistry Basics

The `RoleRegistry` is where you define roles and their permissions:

```python
from urauth.authz.roles import RoleRegistry

registry = RoleRegistry()

registry.role("admin", permissions=["*"])
registry.role("editor", permissions=["task:read", "task:write", "task:delete"], inherits=["viewer"])
registry.role("viewer", permissions=["task:read", "dashboard:read"])
```

Key concepts:

- Each role has a set of **permissions** (strings in `"resource:action"` format).
- The `inherits` parameter creates a **hierarchy** -- an editor automatically gets all of viewer's permissions.
- The wildcard `"*"` grants all permissions.

## PermissionEnum for Type Safety

Instead of raw permission strings, use `PermissionEnum` for compile-time checks and autocomplete:

```python
from urauth.authz.permission_enum import PermissionEnum

class Perms(PermissionEnum):
    TASK_READ = ("task", "read")
    TASK_WRITE = ("task", "write")
    TASK_DELETE = ("task", "delete")
    DASHBOARD_READ = ("dashboard", "read")
    USER_READ = ("user", "read")
    USER_WRITE = ("user", "write")
```

The permission format is flexible -- you can use any separator from `@#.:|\/&$`, and they are all semantically equivalent:

```python
class Perms(PermissionEnum):
    TASK_READ = ("task", "read")       # two-arg tuple
    TASK_WRITE = "task:write"          # colon separator
    TASK_DELETE = "task.delete"        # dot separator
    USER_READ = "user|read"            # pipe separator
```

All of these produce `Permission` objects that compare equal when the resource and action match: `Permission("task:read") == Permission("task.read")` is `True`.

If you need a custom parsing strategy, set the `__parser__` class attribute on your `PermissionEnum` subclass.

Each member's `.value` is a `Permission` object. Use them in role definitions:

```python
registry = RoleRegistry()
registry.role("admin", permissions=[Perms.TASK_READ, Perms.TASK_WRITE, Perms.USER_READ, Perms.USER_WRITE])
registry.role("viewer", permissions=[Perms.TASK_READ, Perms.DASHBOARD_READ])
```

Or mix strings and enums:

```python
registry.role("admin", permissions=["*"])
registry.role("editor", permissions=[Perms.TASK_READ, Perms.TASK_WRITE, "task:delete"], inherits=["viewer"])
```

## Wire to FastAuth

Create an `AccessControl` instance from the registry:

```python
from urauth.auth import Auth
from urauth.config import AuthConfig
from urauth.backends.memory import MemoryTokenStore
from urauth.fastapi.auth import FastAuth

class MyAuth(Auth):
    async def get_user(self, user_id):
        ...

    async def get_user_by_username(self, username):
        ...

    async def verify_password(self, user, password):
        ...

    async def get_user_roles(self, user):
        """Load roles from your database."""
        from urauth.authz.primitives import Role
        return [Role(name) for name in user.roles]


core = MyAuth(config=AuthConfig(secret_key="..."), token_store=MemoryTokenStore())
auth = FastAuth(core)
access = auth.access_control(registry=registry)
```

The `access_control()` method builds a `RoleExpandingChecker` from the registry, which handles role expansion and permission matching.

## Using Guards

Guards work as both decorators and FastAPI dependencies.

### With PermissionEnum

```python
from fastapi import Depends, FastAPI
from starlette.requests import Request

app = FastAPI()

@app.get("/tasks")
@access.guard(Perms.TASK_READ)
async def list_tasks(request: Request):
    return {"tasks": [...]}

@app.post("/tasks")
@access.guard(Perms.TASK_WRITE)
async def create_task(request: Request):
    return {"created": True}
```

### With string arguments

```python
@app.get("/tasks")
@access.guard("task", "read")
async def list_tasks(request: Request):
    return {"tasks": [...]}
```

### As a dependency

```python
@app.delete(
    "/tasks/{task_id}",
    dependencies=[Depends(access.guard(Perms.TASK_DELETE))],
)
async def delete_task(task_id: str):
    return {"deleted": task_id}
```


> **`info`** — See source code for full API.

When using `@access.guard()` as a decorator, the endpoint function must have a `request: Request` parameter so the guard can resolve the auth context.

:::
## Composable Requirements

For complex authorization rules, use `Permission`, `Role`, and the `&` (AND) / `|` (OR) operators directly with `auth.require()`:

```python
from urauth.authz.primitives import Permission, Role

can_read_tasks = Permission("task", "read")
can_write_tasks = Permission("task", "write")
is_admin = Role("admin")
is_editor = Role("editor")

# Must have BOTH the permission AND the role
@app.put("/tasks/{task_id}")
@auth.require(can_write_tasks & is_editor)
async def update_task(request: Request):
    ...

# Must have EITHER admin role OR both permission and editor role
@app.delete("/tasks/{task_id}")
@auth.require(is_admin | (can_write_tasks & is_editor))
async def delete_task(request: Request):
    ...
```

Use `require_any` as a shorthand for OR-ing multiple requirements:

```python
admin_perm = Permission("admin", "access")
editor_and_owner = Permission("task", "write") & Role("editor")

@app.delete("/tasks/{task_id}")
@auth.require_any(admin_perm, editor_and_owner)
async def delete_task(request: Request):
    ...
```

## Loading Roles from Your Database

Override `get_user_roles()` in your `Auth` subclass to load roles dynamically:

```python
from urauth.authz.primitives import Role

class MyAuth(Auth):
    async def get_user_roles(self, user):
        # Query your database
        role_records = await db.execute(
            "SELECT role_name FROM user_roles WHERE user_id = :uid",
            {"uid": user.id},
        )
        return [Role(record.role_name) for record in role_records]
```

The default implementation reads `user.roles` and wraps each string as a `Role` object. If your user model already has a `roles` attribute with string names, the default works without any override.

## Registry Composition

Merge registries from different modules using `include()`:

```python
# tasks/permissions.py
task_registry = RoleRegistry()
task_registry.role("task_admin", permissions=["task:*"])
task_registry.role("task_viewer", permissions=["task:read"])

# users/permissions.py
user_registry = RoleRegistry()
user_registry.role("user_admin", permissions=["user:*"])
user_registry.role("user_viewer", permissions=["user:read"])

# main.py
registry = RoleRegistry()
registry.role("admin", permissions=["*"])
registry.include(task_registry)
registry.include(user_registry)
```

`include()` uses **union semantics** -- if the same role exists in both registries, their permissions are merged (unioned). Hierarchy entries are also merged.

## DB-Backed Roles

For roles that change at runtime (e.g., admin-configurable roles), use `with_loader()`:

```python
from urauth.authz.loader import RoleLoader, RoleCache

class DBRoleLoader:
    """Load roles from your database."""

    async def load_roles(self) -> dict[str, set[str]]:
        rows = await db.execute("SELECT role_name, permission FROM role_permissions")
        roles: dict[str, set[str]] = {}
        for row in rows:
            roles.setdefault(row.role_name, set()).add(row.permission)
        return roles

    async def load_hierarchy(self) -> dict[str, list[str]]:
        rows = await db.execute("SELECT parent_role, child_role FROM role_hierarchy")
        hierarchy: dict[str, list[str]] = {}
        for row in rows:
            hierarchy.setdefault(row.parent_role, []).append(row.child_role)
        return hierarchy


class MemoryRoleCache:
    """Simple in-memory cache for role data."""

    def __init__(self):
        self._data = {}

    async def get(self, key):
        return self._data.get(key)

    async def set(self, key, value, ttl):
        self._data[key] = value

    async def invalidate(self, key):
        self._data.pop(key, None)
```

Wire it up and load during app startup:

```python
from contextlib import asynccontextmanager

registry = RoleRegistry()
registry.role("admin", permissions=["*"])  # static roles still work
registry.with_loader(DBRoleLoader(), cache=MemoryRoleCache(), cache_ttl=300)

@asynccontextmanager
async def lifespan(app):
    await registry.load()  # load DB roles at startup
    yield

app = FastAPI(lifespan=lifespan)
```

Static roles defined with `registry.role()` take precedence over DB-loaded roles with the same name. Call `await registry.reload()` to invalidate the cache and re-load from the database.

## Wildcard Permissions

Wildcards let you grant broad access without listing every permission:

| Pattern | Matches |
|---------|---------|
| `"*"` | Everything -- all resources and actions |
| `"task:*"` | All actions on the `task` resource (`task:read`, `task:write`, `task:delete`, etc.) |
| `"task:read"` | Exact match only |

```python
registry.role("admin", permissions=["*"])                    # can do anything
registry.role("task_admin", permissions=["task:*"])          # all task operations
registry.role("viewer", permissions=["task:read", "user:read"])  # specific permissions
```

## How Permission Resolution Works

urauth provides two checkers. Both use **semantic matching** -- they compare the `(resource, action)` pair regardless of which separator was used to define the permission. There is no `separator` parameter on checkers.

### StringChecker (default)

The `StringChecker` matches the required permission against the permissions in the `AuthContext` using semantic comparison. It supports exact match and wildcards (`Permission("*")` for global wildcard, `"resource:*"` for resource-level wildcard).

Use `StringChecker` when permissions are stored directly on users or in JWT claims.

### RoleExpandingChecker

The `RoleExpandingChecker` is produced by `registry.build_checker()` and used automatically when you call `auth.access_control(registry=registry)`. It:

1. Reads the user's role names from `AuthContext.roles`
2. Expands roles using the hierarchy (e.g., `["editor"]` becomes `{"editor", "viewer"}`)
3. Collects all permissions from the expanded role set
4. Also includes direct permissions from `AuthContext.permissions`
5. Checks the required permission against the collected set using semantic matching (with wildcard support)

The expansion is computed once at startup and cached, so hierarchy lookups are O(1) at request time.

The underlying `match_permission()` function accepts `Permission | str` and performs separator-agnostic comparison -- `"task:read"`, `"task.read"`, and `Permission("task", "read")` all match each other.

## Recap

- `RoleRegistry` defines roles with permissions and inheritance.
- `PermissionEnum` provides type-safe permission definitions.
- `auth.access_control(registry=registry)` creates an `AccessControl` with a `RoleExpandingChecker`.
- `@access.guard(Perms.X)` and `@access.guard("resource", "action")` protect endpoints.
- `auth.require()` supports composable requirements with `&` (AND) and `|` (OR).
- Override `get_user_roles()` to load roles from your database.
- `registry.include()` merges registries with union semantics.
- `registry.with_loader()` + `await registry.load()` enables DB-backed roles with caching.
- Wildcards (`"*"`, `"resource:*"`) grant broad access.
- `RoleExpandingChecker` resolves roles to permissions via hierarchy; `StringChecker` matches directly.

**Next:** [Relations](relations.md)
