# Architecture

## Single Auth Instance

Create one `Auth` and one `FastAuth` instance per application. Share them across your routers via dependency injection or module-level singletons:

```python title="app/auth.py"
from urauth import Auth, AuthConfig
from urauth.backends.memory import MemoryTokenStore
from urauth.fastapi import FastAuth

class MyAuth(Auth):
    ...

core = MyAuth(
    config=AuthConfig(),
    token_store=MemoryTokenStore(),
)
auth = FastAuth(core)
```

```python title="app/routers/tasks.py"
from app.auth import auth

@router.get("/tasks")
@auth.require(can_read_tasks)
async def list_tasks(ctx: AuthContext = Depends(auth.context)):
    ...
```

## Define Permissions as Constants

Declare your permissions once in a shared module. Use `PermissionEnum` for type safety and auto-completion:

```python title="app/permissions.py"
from urauth import PermissionEnum

class Perms(PermissionEnum):
    TASK_READ = ("task", "read")
    TASK_WRITE = ("task", "write")
    TASK_DELETE = ("task", "delete")
    USER_READ = ("user", "read")
    USER_ADMIN = ("user", "admin")
    ORG_ADMIN = ("org", "admin")
```

Then reference them across your codebase:

```python
from app.permissions import Perms

@access.guard(Perms.TASK_READ)
async def list_tasks(request: Request):
    ...
```

## Use RoleRegistry for Role Hierarchies

Define roles with inheritance in a single place. This keeps your authorization model explicit and auditable:

```python title="app/roles.py"
from urauth import RoleRegistry

registry = RoleRegistry()
registry.role("viewer", permissions=["task:read", "user:read"])
registry.role("editor", permissions=["task:write"], inherits=["viewer"])
registry.role("admin", permissions=["*"], inherits=["editor"])
```


> **`tip`** — See source code for full API.

Use `registry.include(other_registry)` to compose role registries from different modules in large applications.

:::
## Prefer Guards over Manual Checks

Guards are declarative, composable, and visible in your route definitions. Prefer them over manual `if` checks in your endpoint body:

```python
# Good -- declarative, visible, reusable
@auth.require(can_read_tasks & Role("member"))
async def list_tasks(ctx: AuthContext = Depends(auth.context)):
    return get_tasks()

# Avoid -- hidden logic, not reusable
async def list_tasks(ctx: AuthContext = Depends(auth.context)):
    if not ctx.has_permission(can_read_tasks) or not ctx.has_role("member"):
        raise ForbiddenError()
    return get_tasks()
```

## Use Pipeline for Feature-Rich Applications

If your application needs multiple login methods, MFA, or password reset, use `Pipeline` instead of wiring individual components:

```python
from urauth import Pipeline, JWTStrategy, PasswordLogin, OAuthLogin, MFAMethod

pipeline = Pipeline(
    strategy=JWTStrategy(refresh=True, transport="hybrid"),
    password=PasswordLogin(),
    oauth=OAuthLogin([Google(...), GitHub(...)]),
    mfa=[MFAMethod(method="otp", required=False)],
)

core = MyAuth(config=config, token_store=store, pipeline=pipeline)
auth = FastAuth(core)
app.include_router(auth.auto_router())  # All routes generated
```
