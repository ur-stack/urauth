# Access Control

urauth provides two authorization systems that serve different purposes:

- **Guards** (`auth.require()`) -- evaluate composable `Requirement` objects directly against the `AuthContext`. Best for simple permission/role/relation checks.
- **Access Control** (`access.guard()`) -- delegate authorization to a `PermissionChecker`, which can expand roles via a hierarchy, resolve permissions from a registry, and support scoped access. Best for applications with role inheritance and centralized permission management.

This tutorial covers the checker-based access control system.

## Setup

Access control requires three things:

1. A `PermissionEnum` defining your permissions.
2. A `RoleRegistry` mapping roles to permissions.
3. An `AccessControl` instance wired to your `FastAuth`.

### Step 1: Define Permissions

Use `PermissionEnum` to define your permissions as typed enums. Each member becomes a `Permission` object. The format is flexible -- use a `(resource, action)` tuple or a single string with any separator from `@#.:|\/&$`:

```python
from urauth import PermissionEnum


class Perms(PermissionEnum):
    # Task permissions
    TASK_READ = ("task", "read")
    TASK_WRITE = "task:write"       # colon separator
    TASK_DELETE = "task.delete"     # dot separator -- also works

    # User permissions
    USER_READ = ("user", "read")
    USER_WRITE = ("user", "write")
    USER_DELETE = ("user", "delete")

    # Admin permissions
    ADMIN_DASHBOARD = ("admin", "dashboard")
    ADMIN_SETTINGS = ("admin", "settings")
```

Each member's `.value` is a `Permission` instance. Equality is semantic -- `Perms.TASK_READ == Permission("task.read")` is `True` regardless of separator. The `Permission("*")` value acts as a global wildcard.

### Step 2: Define Roles

Use `RoleRegistry` to define roles, their permissions, and inheritance:

```python
from urauth import RoleRegistry

registry = RoleRegistry()

# Viewer can only read
registry.role("viewer", permissions=[
    Perms.TASK_READ,
    Perms.USER_READ,
])

# Editor inherits viewer and adds write
registry.role("editor", permissions=[
    Perms.TASK_WRITE,
], inherits=["viewer"])

# Admin gets everything
registry.role("admin", permissions=["*"])
```

Key features of `RoleRegistry`:

- **Inheritance**: `inherits=["viewer"]` means the `editor` role also gets all of `viewer`'s permissions.
- **Wildcards**: `"*"` grants all permissions.
- **Resource wildcards**: `"task:*"` grants all actions on the `task` resource.
- **Composable registries**: Use `registry.include(other_registry)` to merge registries from different modules.

### Step 3: Create AccessControl

Wire the registry to your `FastAuth` instance:

```python
access = auth.access_control(registry=registry)
```

This creates an `AccessControl` object that:

1. Resolves the `AuthContext` from the request (same as `auth.context`).
2. Expands the user's roles through the hierarchy.
3. Collects all permissions (direct + role-derived).
4. Checks the requested permission against the collected set.

## Using access.guard()

Like all urauth guards, `access.guard()` works as both a decorator and a dependency.

### With PermissionEnum

```python
from starlette.requests import Request

@app.get("/tasks")
@access.guard(Perms.TASK_READ)
async def list_tasks(request: Request):
    return get_all_tasks()
```

::: warning Request parameter required
When using `@access.guard()` as a **decorator**, the endpoint function must have a `request: Request` parameter. The guard needs it to resolve the auth context.

:::
### With resource and action strings

```python
@app.get("/tasks")
@access.guard("task", "read")
async def list_tasks(request: Request):
    return get_all_tasks()
```

### With a Permission object

```python
from urauth import Permission

@app.get("/tasks")
@access.guard(Permission("task", "read"))
async def list_tasks(request: Request):
    return get_all_tasks()
```

### As a dependency

When used as a dependency, no `request` parameter is needed in your function -- FastAPI injects the request into the guard automatically:

```python
@app.get("/tasks", dependencies=[Depends(access.guard(Perms.TASK_READ))])
async def list_tasks():
    return get_all_tasks()
```

```python
@app.delete(
    "/tasks/{task_id}",
    dependencies=[Depends(access.guard(Perms.TASK_DELETE))],
)
async def delete_task(task_id: str):
    await remove_task(task_id)
    return {"deleted": task_id}
```

## Inline Checks

Sometimes you need conditional logic based on permissions rather than an all-or-nothing guard. Use `access.check()` for inline boolean checks:

```python
@app.get("/tasks")
async def list_tasks(request: Request, ctx: AuthContext = Depends(auth.context)):
    tasks = get_all_tasks()

    # Check if user can delete -- returns bool, never raises
    can_delete = await access.check(Perms.TASK_DELETE, request=request)
    can_write = await access.check("task", "write", request=request)

    return {
        "tasks": tasks,
        "actions": {
            "can_delete": can_delete,
            "can_write": can_write,
        },
    }
```

`access.check()` has the same overloaded signatures as `access.guard()` -- it accepts a `PermissionEnum`, a `Permission` object, or `(resource, action)` strings. The key difference: `check()` returns a `bool` and never raises an exception.

## Custom Checkers

The `PermissionChecker` protocol defines a single method. Implement it to plug in any authorization backend:

```python
from urauth import AuthContext
from urauth.authz.checker import PermissionChecker


class OPAChecker:
    """Check permissions against an Open Policy Agent server."""

    def __init__(self, opa_url: str):
        self._url = opa_url

    async def has_permission(
        self,
        ctx: AuthContext,
        resource: str,
        action: str,
        *,
        scope: str | None = None,
        **kwargs,
    ) -> bool:
        import httpx

        response = await httpx.AsyncClient().post(
            f"{self._url}/v1/data/authz/allow",
            json={
                "input": {
                    "user": str(ctx.user.id),
                    "roles": [str(r) for r in ctx.roles],
                    "resource": resource,
                    "action": action,
                    "scope": scope,
                }
            },
        )
        return response.json().get("result", False)


# Use it
access = auth.access_control(checker=OPAChecker("http://localhost:8181"))
```

You can also pass a custom checker alongside a registry:

```python
access = auth.access_control(checker=my_custom_checker)
```

Or let the registry build its default `RoleExpandingChecker`:

```python
access = auth.access_control(registry=registry)
# Equivalent to:
access = auth.access_control(checker=registry.build_checker())
```

Both built-in checkers (`StringChecker` and `RoleExpandingChecker`) use semantic matching -- they compare permissions by their `(resource, action)` pair regardless of separator. There is no `separator` configuration parameter.

## Scoped Access

For multi-tenant or resource-scoped authorization, use `scope=` or `scope_from=`:

### Static scope

```python
# Only check permissions within the "org-123" scope
@app.get("/org/tasks")
@access.guard(Perms.TASK_READ, scope="org-123")
async def org_tasks(request: Request):
    return get_org_tasks("org-123")
```

### Dynamic scope from path parameter

```python
# Scope is read from the {org_id} path parameter
@app.get("/orgs/{org_id}/tasks")
@access.guard(Perms.TASK_READ, scope_from="org_id")
async def org_tasks(org_id: str, request: Request):
    return get_org_tasks(org_id)
```

When a scope is provided, the checker looks at `ctx.scopes[scope]` for permissions specific to that scope, rather than the user's global permissions. This lets you model per-organization or per-project permission sets.

## on_deny Callback

You can provide a callback that runs when access is denied:

```python
def log_access_denied():
    logger.warning("Access denied")

access = auth.access_control(registry=registry, on_deny=log_access_denied)
```

The `on_deny` callback is called before the `403` response is raised. It receives no arguments.

You can also disable automatic error raising and handle denials yourself:

```python
access = auth.access_control(registry=registry, auto_error=False)

@app.get("/tasks")
@access.guard(Perms.TASK_READ)
async def list_tasks(request: Request):
    # If auto_error=False, the guard returns False instead of raising
    # but the decorator still prevents execution by returning None
    return get_all_tasks()
```

## Composable Registries

For larger applications, define registries per module and merge them:

```python title="tasks/permissions.py"
from urauth import RoleRegistry, PermissionEnum


class TaskPerms(PermissionEnum):
    TASK_READ = ("task", "read")
    TASK_WRITE = ("task", "write")
    TASK_DELETE = ("task", "delete")


task_registry = RoleRegistry()
task_registry.role("task_viewer", permissions=[TaskPerms.TASK_READ])
task_registry.role("task_editor", permissions=[TaskPerms.TASK_WRITE], inherits=["task_viewer"])
```

```python title="users/permissions.py"
from urauth import RoleRegistry, PermissionEnum


class UserPerms(PermissionEnum):
    USER_READ = ("user", "read")
    USER_WRITE = ("user", "write")


user_registry = RoleRegistry()
user_registry.role("user_viewer", permissions=[UserPerms.USER_READ])
user_registry.role("user_admin", permissions=[UserPerms.USER_READ, UserPerms.USER_WRITE])
```

```python title="app.py"
from urauth import RoleRegistry

from tasks.permissions import task_registry
from users.permissions import user_registry

# Merge into a single registry
registry = RoleRegistry()
registry.include(task_registry)
registry.include(user_registry)

# Admin role defined at the top level
registry.role("admin", permissions=["*"])

access = auth.access_control(registry=registry)
```

## Database-Backed Roles

For applications where roles are managed in a database, use `with_loader()`:

```python
from urauth.authz.loader import RoleLoader


class DBRoleLoader:
    """Load roles from your database."""

    async def load_roles(self) -> dict[str, set[str]]:
        rows = await db.execute("SELECT role_name, permission FROM role_permissions")
        result: dict[str, set[str]] = {}
        for row in rows:
            result.setdefault(row.role_name, set()).add(row.permission)
        return result

    async def load_hierarchy(self) -> dict[str, list[str]]:
        rows = await db.execute("SELECT parent_role, child_role FROM role_hierarchy")
        result: dict[str, list[str]] = {}
        for row in rows:
            result.setdefault(row.parent_role, []).append(row.child_role)
        return result


registry = RoleRegistry()
# Static roles still work alongside loaded ones
registry.role("superadmin", permissions=["*"])
# DB roles are loaded and cached
registry.with_loader(DBRoleLoader(), cache_ttl=300)

# Call load() during startup
await registry.load()

access = auth.access_control(registry=registry)
```

## Full Example

```python title="app.py"
from dataclasses import dataclass, field

from fastapi import Depends, FastAPI
from starlette.requests import Request

from urauth import Auth, AuthConfig, AuthContext, PasswordHasher, PermissionEnum, Role, RoleRegistry
from urauth.backends.memory import MemoryTokenStore
from urauth.fastapi import FastAuth

hasher = PasswordHasher()


# ── Permissions ───────────────────────────────────────────

class Perms(PermissionEnum):
    TASK_READ = ("task", "read")
    TASK_WRITE = ("task", "write")
    TASK_DELETE = ("task", "delete")
    USER_READ = ("user", "read")
    USER_MANAGE = ("user", "manage")


# ── Roles ─────────────────────────────────────────────────

registry = RoleRegistry()
registry.role("viewer", permissions=[Perms.TASK_READ, Perms.USER_READ])
registry.role("editor", permissions=[Perms.TASK_WRITE], inherits=["viewer"])
registry.role("admin", permissions=["*"])


# ── Models ────────────────────────────────────────────────

@dataclass
class User:
    id: str
    username: str
    hashed_password: str
    is_active: bool = True
    roles: list[str] = field(default_factory=list)


USERS = {
    "alice": User("1", "alice", hasher.hash("secret"), roles=["admin"]),
    "bob": User("2", "bob", hasher.hash("secret"), roles=["editor"]),
    "charlie": User("3", "charlie", hasher.hash("secret"), roles=["viewer"]),
}


# ── Auth ──────────────────────────────────────────────────

class MyAuth(Auth):
    async def get_user(self, user_id):
        return next((u for u in USERS.values() if u.id == str(user_id)), None)

    async def get_user_by_username(self, username):
        return USERS.get(username)

    async def verify_password(self, user, password):
        return hasher.verify(password, user.hashed_password)

    async def get_user_roles(self, user):
        return [Role(r) for r in user.roles]


# ── App setup ─────────────────────────────────────────────

core = MyAuth(
    config=AuthConfig(secret_key="access-control-secret"),
    token_store=MemoryTokenStore(),
)
auth = FastAuth(core)
access = auth.access_control(registry=registry)

app = FastAPI(lifespan=auth.lifespan())
auth.init_app(app)
app.include_router(auth.password_auth_router())


# ── Routes ────────────────────────────────────────────────

# Viewer, editor, admin can all read (viewer has TASK_READ, editor inherits it)
@app.get("/tasks")
@access.guard(Perms.TASK_READ)
async def list_tasks(request: Request):
    return [
        {"id": "1", "title": "Ship v1"},
        {"id": "2", "title": "Write docs"},
    ]


# Editor and admin can write (editor has TASK_WRITE, admin has *)
@app.post("/tasks")
@access.guard(Perms.TASK_WRITE)
async def create_task(request: Request, ctx: AuthContext = Depends(auth.context)):
    return {"created_by": ctx.user.username}


# Only admin can delete (admin has *)
@app.delete(
    "/tasks/{task_id}",
    dependencies=[Depends(access.guard(Perms.TASK_DELETE))],
)
async def delete_task(task_id: str):
    return {"deleted": task_id}


# Conditional rendering using inline check
@app.get("/tasks/{task_id}")
async def get_task(task_id: str, request: Request, ctx: AuthContext = Depends(auth.context)):
    task = {"id": task_id, "title": "Ship v1"}
    can_edit = await access.check(Perms.TASK_WRITE, request=request)
    can_delete = await access.check(Perms.TASK_DELETE, request=request)

    return {
        **task,
        "actions": {
            "can_edit": can_edit,
            "can_delete": can_delete,
        },
    }
```

## Guards vs Access Control: When to Use Which

| Feature | `auth.require()` | `access.guard()` |
|---------|-------------------|-------------------|
| Evaluates against | `AuthContext` directly | `PermissionChecker` (registry-aware) |
| Role inheritance | No (checks exact role) | Yes (expands via hierarchy) |
| Composition | `&` / `|` on primitives | Single permission per guard |
| Custom backends | Override `Auth` methods | Implement `PermissionChecker` protocol |
| Scoped access | No | Yes (`scope=`, `scope_from=`) |
| Best for | Simple rules, relation checks | RBAC with inheritance, multi-tenant |

You can use both in the same application. Guards and access control share the same cached `AuthContext` per request.

## Recap

- `PermissionEnum` defines typed permissions using `(resource, action)` tuples or single strings with any separator (e.g., `"task:read"`, `"task.read"`).
- `RoleRegistry` maps roles to permissions with inheritance and composition via `include()`.
- `access = auth.access_control(registry=registry)` creates the access control instance.
- `@access.guard(Perms.X)` works as both a decorator and `Depends()`.
- `await access.check(Perms.X, request=request)` returns a `bool` for inline conditional logic.
- Implement `PermissionChecker` to plug in any authorization backend (OPA, Zanzibar, custom DB).
- Use `scope=` / `scope_from=` for tenant-scoped or resource-scoped permission checks.

**Next:** [Refresh Tokens](refresh-tokens.md)
