# Protecting Routes

Now that you have authentication working, let's explore the different ways to protect your routes and inspect the authenticated user's identity.

## Basic Protection

The simplest form -- require an authenticated user:

```python
from fastapi import Depends

@app.get("/me")
async def me(user=Depends(auth.current_user)):
    return {"id": user.id, "username": user.username}
```

If no valid token is provided, the endpoint returns `401 Unauthorized`. The `user` object is whatever your `Auth.get_user()` method returns.

!!! warning "`current_user` is a property"
    Write `Depends(auth.current_user)` -- no parentheses. It is a property on `FastAuth` that returns a dependency function, not a method you call.

## Full Context

When you need more than just the user object -- roles, permissions, relations, token claims -- use `auth.context`:

```python
from urauth import AuthContext

@app.get("/me/full")
async def me_full(ctx: AuthContext = Depends(auth.context)):
    return {
        "user_id": ctx.user.id,
        "roles": [str(r) for r in ctx.roles],
        "permissions": [str(p) for p in ctx.permissions],
        "authenticated": ctx.is_authenticated(),
    }
```

`AuthContext` is the single identity model in urauth. It holds everything about the current user's session:

| Attribute | Type | Description |
|-----------|------|-------------|
| `user` | `Any` | The user object from `Auth.get_user()` |
| `roles` | `list[Role]` | User's roles (from `Auth.get_user_roles()`) |
| `permissions` | `list[Permission]` | All permissions (direct + role-derived) |
| `relations` | `list[tuple[Relation, str]]` | Zanzibar-style relations |
| `token` | `TokenPayload \| None` | Decoded JWT claims |
| `request` | `Request \| None` | The originating request |

The context is cached on the request -- calling `Depends(auth.context)` multiple times in the same request only builds it once.

## Optional Authentication

Sometimes you want to show different content for logged-in vs anonymous users. Use the `@auth.optional` decorator:

```python
@app.get("/feed")
@auth.optional
async def feed(ctx: AuthContext = Depends(auth.context)):
    if ctx.is_authenticated():
        return {"feed": "personalized", "user": ctx.user.username}
    return {"feed": "public"}
```

When `@auth.optional` is applied, `auth.context` returns an anonymous `AuthContext` instead of raising `401` when no token is provided. The anonymous context has `user=None` and `is_authenticated()` returns `False`.

!!! note
    `@auth.optional` is a property that returns a decorator. Apply it directly to the endpoint function -- it marks the endpoint so `auth.context` knows to allow unauthenticated requests.

## AuthContext Introspection

`AuthContext` provides several methods for checking the user's identity without reaching into the internals:

### Check authentication status

```python
@app.get("/status")
@auth.optional
async def status(ctx: AuthContext = Depends(auth.context)):
    if not ctx.is_authenticated():
        return {"status": "anonymous"}
    return {"status": "authenticated", "user": ctx.user.username}
```

### Check permissions

```python
@app.get("/tasks")
async def list_tasks(ctx: AuthContext = Depends(auth.context)):
    tasks = get_all_tasks()

    # Only show admin actions if user has the permission
    can_delete = ctx.has_permission("task:delete")

    return {
        "tasks": tasks,
        "can_delete": can_delete,
    }
```

`has_permission()` supports wildcards. If the user has `"*"` they match everything. If they have `"task:*"` they match any action on the `task` resource.

### Check roles

```python
@app.get("/dashboard")
async def dashboard(ctx: AuthContext = Depends(auth.context)):
    data = {"stats": get_basic_stats()}

    if ctx.has_role("admin"):
        data["admin_stats"] = get_admin_stats()

    if ctx.has_any_role("admin", "editor"):
        data["pending_reviews"] = get_pending_reviews()

    return data
```

### Check relations

```python
from urauth import Relation

owns_task = Relation("owner", "task")

@app.get("/tasks/{task_id}")
async def get_task(task_id: str, ctx: AuthContext = Depends(auth.context)):
    task = get_task_by_id(task_id)

    return {
        "task": task,
        "is_owner": ctx.has_relation(owns_task, task_id),
    }
```

### Evaluate composite requirements

```python
from urauth import Permission, Role

can_read = Permission("task", "read")
admin = Role("admin")

@app.get("/tasks")
async def list_tasks(ctx: AuthContext = Depends(auth.context)):
    # Complex requirement: must have task:read OR be an admin
    if not ctx.satisfies(can_read | admin):
        return {"tasks": []}
    return {"tasks": get_all_tasks()}
```

`ctx.satisfies()` evaluates any `Requirement` -- including composites built with `&` and `|`.

## Requirement Guards (Preview)

For declarative authorization, urauth provides guards that work as both decorators and dependencies. Here is a quick preview -- the [Guards & Requirements](guards.md) tutorial covers this in depth.

```python
from urauth import Permission

can_read_tasks = Permission("task", "read")

# Decorator style
@app.get("/tasks")
@auth.require(can_read_tasks)
async def list_tasks(ctx: AuthContext = Depends(auth.context)):
    return get_all_tasks()

# Dependency style
@app.get("/tasks", dependencies=[Depends(auth.require(can_read_tasks))])
async def list_tasks():
    return get_all_tasks()
```

## Policy Guards

For authorization rules that do not fit neatly into permissions or roles, use `auth.policy()` with a custom check function:

```python
@app.get("/premium-features")
@auth.policy(lambda ctx: getattr(ctx.user, "is_premium", False))
async def premium_features(ctx: AuthContext = Depends(auth.context)):
    return {"features": get_premium_features()}
```

The check function receives the `AuthContext` and must return a truthy value. It can be sync or async:

```python
async def check_quota(ctx: AuthContext) -> bool:
    usage = await get_user_usage(ctx.user.id)
    return usage.api_calls < usage.limit

@app.post("/api/generate")
@auth.policy(check_quota)
async def generate(ctx: AuthContext = Depends(auth.context)):
    return await run_generation(ctx.user.id)
```

## Error Responses

| Condition | Status | Detail |
|-----------|--------|--------|
| No token provided | `401` | "Not authenticated" |
| Malformed or invalid token | `401` | "Invalid token" |
| Expired token | `401` | "Token has expired" |
| Revoked token | `401` | "Token has been revoked" |
| Inactive user (`is_active=False`) | `401` | "Inactive user" |
| User not found | `401` | "User not found" |
| Missing required permission or role | `403` | "Forbidden" |
| Policy check failed | `403` | "Forbidden" |

urauth's exception handlers (registered by `auth.init_app(app)`) convert these to JSON responses automatically:

```json
{"detail": "Not authenticated"}
```

## Recap

- `Depends(auth.current_user)` -- require an authenticated user, get back the user object.
- `Depends(auth.context)` -- get the full `AuthContext` with user, roles, permissions, relations.
- `@auth.optional` -- allow unauthenticated requests; `auth.context` returns an anonymous context.
- `ctx.is_authenticated()`, `ctx.has_permission()`, `ctx.has_role()`, `ctx.has_relation()`, `ctx.satisfies()` -- introspect the context without guards.
- `@auth.require()` and `@auth.policy()` -- declarative guards (covered in depth next).

**Next:** [Guards & Requirements](guards.md)
