# Guards & Requirements

urauth's guard system lets you declare authorization rules that are composable, reusable, and work in two modes: as `@decorator` on your endpoint function, or as `Depends()` in your route dependencies. This tutorial covers the full system.

## The Dual-Use Pattern

Every guard in urauth works in two ways:

```python
from urauth import Permission

can_read_tasks = Permission("task", "read")

# 1. Decorator style -- guards the endpoint directly
@app.get("/tasks")
@auth.require(can_read_tasks)
async def list_tasks(ctx: AuthContext = Depends(auth.context)):
    return get_all_tasks()

# 2. Dependency style -- added to route dependencies
@app.get("/tasks", dependencies=[Depends(auth.require(can_read_tasks))])
async def list_tasks():
    return get_all_tasks()
```

Both approaches do the same thing: resolve the `AuthContext` from the request, check the requirement, and raise `403 Forbidden` if it fails. The decorator style is more visible; the dependency style is cleaner when you do not need the context in the function body.

## Composable Primitives

urauth provides three primitive types that all work as requirements:

### Permission

A typed `(resource, action)` pair:

```python
from urauth import Permission

can_read_tasks = Permission("task", "read")
can_write_tasks = Permission("task", "write")
can_delete_users = Permission("user", "delete")
```

A `Permission` evaluates to `True` when `ctx.has_permission()` matches. This supports wildcards: a user with `"*"` matches everything, and `"task:*"` matches any action on the `task` resource.

### Role

A named role:

```python
from urauth import Role

admin = Role("admin")
editor = Role("editor")
viewer = Role("viewer")
```

A `Role` evaluates to `True` when `ctx.has_role()` matches the role name.

### Relation

A Zanzibar-style relation to a resource (resource-first argument order):

```python
from urauth import Relation

owns_task = Relation("task", "owner")
member_of_org = Relation("organization", "member")
```

You can also use the single-string form with any separator: `Relation("task#owner")`.

A `Relation` evaluates to `True` when the context holds any relation matching the type (regardless of resource ID). For checking against a specific resource ID, use `auth.require_relation()` (covered below).

## Boolean Composition

All three primitive types support `&` (AND) and `|` (OR) operators to build complex rules:

### AND -- all must be satisfied

```python
# User must have task:read AND be a member
can_read_tasks & Role("member")

# User must be an editor AND have task:write
editor & can_write_tasks
```

### OR -- any one must be satisfied

```python
# User must be admin OR have task:read
admin | can_read_tasks

# User can be admin, editor, or viewer
admin | editor | viewer
```

### Combined -- group with parentheses

```python
# Admin can do anything, OR (editor with the specific permission)
admin | (editor & can_write_tasks)

# Must be a member AND have (read OR write)
Role("member") & (can_read_tasks | can_write_tasks)
```

Composition returns `AllOf` (for `&`) and `AnyOf` (for `|`) objects, which are themselves `Requirement` instances. You can nest them arbitrarily.

## auth.require() -- RequirementGuard

The `require()` method creates a guard for any `Requirement` -- a single primitive or a composite.

### Single permission

```python
from urauth import Permission

can_read = Permission("task", "read")

@app.get("/tasks")
@auth.require(can_read)
async def list_tasks(ctx: AuthContext = Depends(auth.context)):
    return get_all_tasks()
```

### Single role

```python
from urauth import Role

admin = Role("admin")

@app.get("/admin/dashboard")
@auth.require(admin)
async def admin_dashboard(ctx: AuthContext = Depends(auth.context)):
    return get_dashboard_data()
```

### Composite requirement

```python
from urauth import Permission, Role

admin = Role("admin")
can_write = Permission("task", "write")
member = Role("member")

# Admin, OR a member with task:write
rule = admin | (member & can_write)

@app.post("/tasks")
@auth.require(rule)
async def create_task(ctx: AuthContext = Depends(auth.context)):
    return {"created_by": ctx.user.id}
```

### As a dependency

When you do not need the context inside the function, use the dependency form:

```python
@app.delete(
    "/tasks/{task_id}",
    dependencies=[Depends(auth.require(Permission("task", "delete")))],
)
async def delete_task(task_id: str):
    await remove_task(task_id)
    return {"deleted": task_id}
```

## auth.require_any() -- OR Shorthand

`require_any()` is a convenience for requiring any one of several requirements. It is equivalent to combining them with `|`:

```python
from urauth import Permission, Role

admin = Role("admin")
can_read = Permission("task", "read")
can_write = Permission("task", "write")

# These two are equivalent:
@auth.require_any(admin, can_read, can_write)
@auth.require(admin | can_read | can_write)
```

Use whichever reads more clearly for your case:

```python
@app.get("/tasks")
@auth.require_any(
    Role("admin"),
    Permission("task", "read"),
)
async def list_tasks(ctx: AuthContext = Depends(auth.context)):
    return get_all_tasks()
```

## auth.require_relation() -- RelationGuard

`require_relation()` checks that a user has a specific Zanzibar-style relation to a resource identified by a path parameter.

```python
from urauth import Relation

owns_task = Relation("task", "owner")

@app.put("/tasks/{task_id}")
@auth.require_relation(owns_task, resource_id_from="task_id")
async def update_task(task_id: str, ctx: AuthContext = Depends(auth.context)):
    return await save_task(task_id, ctx.user.id)
```

How it works:

1. The guard resolves `AuthContext` from the request.
2. It reads `task_id` from the request's path parameters.
3. It calls `Auth.check_relation(user, owns_task, task_id)` on your `Auth` subclass.
4. If the check returns `False`, it raises `403 Forbidden`.

To make this work, override `check_relation()` or `get_user_relations()` in your `Auth` subclass:

```python
from urauth import Auth, Relation

owns_task = Relation("task", "owner")


class MyAuth(Auth):
    async def get_user(self, user_id):
        return await db.users.get(user_id)

    async def get_user_by_username(self, username):
        return await db.users.find_by_username(username)

    async def verify_password(self, user, password):
        return hasher.verify(password, user.hashed_password)

    # Option 1: Return all relations for the user
    async def get_user_relations(self, user):
        tasks = await db.tasks.find_by_owner(user.id)
        return [(owns_task, str(t.id)) for t in tasks]

    # Option 2: Check a specific relation directly (more efficient)
    async def check_relation(self, user, relation, resource_id):
        if relation == owns_task:
            task = await db.tasks.get(resource_id)
            return task is not None and task.owner_id == user.id
        return False
```

The `resource_id_from` parameter can reference any path parameter in the route:

```python
@app.delete("/orgs/{org_id}/tasks/{task_id}")
@auth.require_relation(Relation("organization", "admin"), resource_id_from="org_id")
async def delete_task(org_id: str, task_id: str, ctx: AuthContext = Depends(auth.context)):
    ...
```

## auth.policy() -- PolicyGuard

For authorization rules that do not map to permissions, roles, or relations, use `auth.policy()` with a custom check function:

```python
# Sync check
@app.get("/premium")
@auth.policy(lambda ctx: getattr(ctx.user, "is_premium", False))
async def premium_content(ctx: AuthContext = Depends(auth.context)):
    return {"content": "premium stuff"}
```

The check function receives an `AuthContext` and returns a truthy value. Async check functions are supported:

```python
async def check_api_quota(ctx: AuthContext) -> bool:
    usage = await get_usage(ctx.user.id)
    return usage.requests_today < ctx.user.daily_limit

@app.post("/api/generate")
@auth.policy(check_api_quota)
async def generate(ctx: AuthContext = Depends(auth.context)):
    return await run_generation(ctx.user.id)
```

Policy guards also work as dependencies:

```python
is_premium = auth.policy(lambda ctx: getattr(ctx.user, "is_premium", False))

@app.get("/premium", dependencies=[Depends(is_premium)])
async def premium_content():
    return {"content": "premium stuff"}
```

## Real-World Example: SaaS Task Manager

Here is a complete example combining multiple guard types for a task management API:

```python title="app.py"
from dataclasses import dataclass, field

from fastapi import Depends, FastAPI
from starlette.requests import Request

from urauth import Auth, AuthContext, JWT, Password, PasswordHasher, Permission, Relation, Role
from urauth.backends.memory import MemoryTokenStore
from urauth.fastapi import FastAuth

hasher = PasswordHasher()


# ── Models ────────────────────────────────────────────────

@dataclass
class User:
    id: str
    username: str
    hashed_password: str
    is_active: bool = True
    is_premium: bool = False
    roles: list[str] = field(default_factory=list)


@dataclass
class Task:
    id: str
    title: str
    owner_id: str


# ── Database ──────────────────────────────────────────────

USERS = {
    "alice": User("1", "alice", hasher.hash("secret"), roles=["admin"], is_premium=True),
    "bob": User("2", "bob", hasher.hash("secret"), roles=["member"]),
}

TASKS = {
    "t1": Task("t1", "Ship v1", owner_id="1"),
    "t2": Task("t2", "Write docs", owner_id="2"),
}


# ── Requirements ──────────────────────────────────────────

admin = Role("admin")
member = Role("member")
can_read = Permission("task", "read")
can_write = Permission("task", "write")
can_delete = Permission("task", "delete")
owns_task = Relation("task", "owner")


# ── Auth subclass ─────────────────────────────────────────

class MyAuth(Auth):
    async def get_user(self, user_id):
        return next((u for u in USERS.values() if u.id == str(user_id)), None)

    async def get_user_by_username(self, username):
        return USERS.get(username)

    async def verify_password(self, user, password):
        return hasher.verify(password, user.hashed_password)

    async def get_user_roles(self, user):
        return [Role(r) for r in user.roles]

    async def get_user_permissions(self, user):
        if "admin" in user.roles:
            return [Permission("task", "*")]
        return [can_read, can_write]

    async def check_relation(self, user, relation, resource_id):
        if relation == owns_task:
            task = TASKS.get(resource_id)
            return task is not None and task.owner_id == user.id
        return False


# ── App setup ─────────────────────────────────────────────

core = MyAuth(
    method=JWT(ttl=900, store=MemoryTokenStore()),
    secret_key="task-manager-secret",
    password=Password(),
)
auth = FastAuth(core)

app = FastAPI(lifespan=auth.lifespan())
auth.init_app(app)
app.include_router(auth.auto_router())


# ── Routes ────────────────────────────────────────────────

# Anyone authenticated can read
@app.get("/tasks")
@auth.require(can_read)
async def list_tasks(ctx: AuthContext = Depends(auth.context)):
    return list(TASKS.values())


# Must be member with write permission, OR admin
@app.post("/tasks")
@auth.require(admin | (member & can_write))
async def create_task(ctx: AuthContext = Depends(auth.context)):
    return {"created_by": ctx.user.username}


# Only task owner can update
@app.put("/tasks/{task_id}")
@auth.require_relation(owns_task, resource_id_from="task_id")
async def update_task(task_id: str, request: Request, ctx: AuthContext = Depends(auth.context)):
    return {"updated": task_id, "by": ctx.user.username}


# Only admin can delete
@app.delete(
    "/tasks/{task_id}",
    dependencies=[Depends(auth.require(admin))],
)
async def delete_task(task_id: str):
    return {"deleted": task_id}


# Premium-only feature using policy guard
@app.get("/tasks/analytics")
@auth.policy(lambda ctx: ctx.user.is_premium)
async def task_analytics(ctx: AuthContext = Depends(auth.context)):
    return {"total_tasks": len(TASKS), "insight": "You are productive!"}
```

## Recap

| Guard | Created via | Checks |
|-------|-------------|--------|
| RequirementGuard | `auth.require(requirement)` | `ctx.satisfies(requirement)` |
| RequirementGuard (OR) | `auth.require_any(*requirements)` | Any requirement satisfied |
| RelationGuard | `auth.require_relation(relation, resource_id_from=...)` | `Auth.check_relation()` with path param |
| PolicyGuard | `auth.policy(check_fn)` | Custom sync/async function returns truthy |

- All guards work as both `@decorator` and `Depends()`.
- Primitives (`Permission`, `Role`, `Relation`) support `&` (AND) and `|` (OR) composition.
- Guards raise `401 Unauthorized` if the user is not authenticated, and `403 Forbidden` if the check fails.
- `auth.require()` has an alias: `auth.req()`. Similarly, `auth.require_any()` has `auth.req_any()`, and `auth.require_relation()` has `auth.req_relation()`.

**Next:** [Access Control](access-control.md)
