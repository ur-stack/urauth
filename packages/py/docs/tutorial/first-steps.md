# First Steps

In this tutorial you will set up password-based JWT authentication from scratch using urauth and FastAPI.

## Install

```bash
pip install "urauth[fastapi]"
```

You also need an ASGI server:

```bash
pip install uvicorn
```

## Create a User Model

Your user model can be anything -- a dataclass, a Pydantic model, an SQLAlchemy object, a Django model. The only requirement is that it has `id` and `is_active` attributes.

```python
from dataclasses import dataclass, field

from urauth import PasswordHasher

hasher = PasswordHasher()


@dataclass
class User:
    id: str
    username: str
    hashed_password: str
    is_active: bool = True
    roles: list[str] = field(default_factory=list)
```

!!! info "Protocol, not base class"
    urauth uses `UserProtocol` -- a runtime-checkable protocol that only requires `id` and `is_active`. You never inherit from a base class. Any object with those two attributes works.

    ```python
    from urauth.types import UserProtocol

    # Your User dataclass satisfies this automatically
    assert isinstance(User(id="1", username="a", hashed_password="x"), UserProtocol)
    ```

## Subclass Auth

The core of urauth is the `Auth` class. Subclass it and override three methods to connect your user storage:

```python
from urauth import Auth

# In-memory store for this example
USERS: dict[str, User] = {
    "alice": User(
        id="1",
        username="alice",
        hashed_password=hasher.hash("secret"),
        roles=["admin"],
    ),
}


class MyAuth(Auth):
    async def get_user(self, user_id):                        # (1)!
        return next((u for u in USERS.values() if u.id == str(user_id)), None)

    async def get_user_by_username(self, username):            # (2)!
        return USERS.get(username)

    async def verify_password(self, user, password):           # (3)!
        return hasher.verify(password, user.hashed_password)
```

1. Called when resolving a user from a JWT `sub` claim. Receives the user ID as stored in the token.
2. Called during login to find the user by username or email.
3. Called during login to verify the plaintext password against the stored hash.

!!! tip "Sync or async -- your choice"
    All overridable methods on `Auth` accept both sync and async implementations. urauth handles both transparently:

    ```python
    # Sync works too -- no async/await needed
    class SyncAuth(Auth):
        def get_user(self, user_id):
            return db.users.get(user_id)

        def get_user_by_username(self, username):
            return db.users.find_one(username=username)

        def verify_password(self, user, password):
            return hasher.verify(password, user.hashed_password)
    ```

## Wire Up FastAuth

`FastAuth` is the FastAPI adapter. It wraps your `Auth` subclass and provides FastAPI-specific features: dependencies, guards, routers, and transports.

```python
from fastapi import Depends, FastAPI

from urauth import AuthConfig
from urauth.backends.memory import MemoryTokenStore
from urauth.fastapi import FastAuth

core = MyAuth(
    config=AuthConfig(secret_key="super-secret-key"),  # (1)!
    token_store=MemoryTokenStore(),                     # (2)!
)
auth = FastAuth(core)
```

1. Never use the default `"CHANGE-ME-IN-PRODUCTION"` in production. Set `AUTH_SECRET_KEY` as an environment variable instead -- `AuthConfig` reads it automatically via pydantic-settings.
2. `MemoryTokenStore` is for development. In production, use a Redis-backed store: `pip install "urauth[redis]"`.

## Create the App

```python
app = FastAPI(lifespan=auth.lifespan())  # (1)!
auth.init_app(app)                        # (2)!
app.include_router(auth.password_auth_router())  # (3)!
```

1. `auth.lifespan()` returns an ASGI lifespan context manager. Wire it into FastAPI so startup/shutdown hooks work.
2. `init_app()` registers urauth's exception handlers on the app. These convert `AuthError` subclasses into proper HTTP responses.
3. `password_auth_router()` gives you login, refresh, logout, and logout-all endpoints under `/auth`.

## Add a Protected Route

Use `Depends(auth.current_user)` to require authentication. Note that `current_user` is a **property**, not a method call -- no parentheses.

```python
@app.get("/me")
async def me(user=Depends(auth.current_user)):  # (1)!
    return {"id": user.id, "username": user.username}
```

1. `auth.current_user` returns a FastAPI dependency function. FastAPI calls it automatically, extracts the JWT from the `Authorization: Bearer` header, validates it, loads the user, and injects it as `user`.

## Full Example

Here is the complete application in a single file:

```python title="app.py"
from dataclasses import dataclass, field

from fastapi import Depends, FastAPI

from urauth import Auth, AuthConfig, PasswordHasher
from urauth.backends.memory import MemoryTokenStore
from urauth.fastapi import FastAuth

# Password hashing
hasher = PasswordHasher()


# User model
@dataclass
class User:
    id: str
    username: str
    hashed_password: str
    is_active: bool = True
    roles: list[str] = field(default_factory=list)


# In-memory user store
USERS: dict[str, User] = {
    "alice": User(
        id="1",
        username="alice",
        hashed_password=hasher.hash("secret"),
        roles=["admin"],
    ),
}


# Auth subclass
class MyAuth(Auth):
    async def get_user(self, user_id):
        return next((u for u in USERS.values() if u.id == str(user_id)), None)

    async def get_user_by_username(self, username):
        return USERS.get(username)

    async def verify_password(self, user, password):
        return hasher.verify(password, user.hashed_password)


# Wire up
core = MyAuth(
    config=AuthConfig(secret_key="super-secret-key"),
    token_store=MemoryTokenStore(),
)
auth = FastAuth(core)

app = FastAPI(lifespan=auth.lifespan())
auth.init_app(app)
app.include_router(auth.password_auth_router())


@app.get("/me")
async def me(user=Depends(auth.current_user)):
    return {"id": user.id, "username": user.username}
```

## Test It

Start the server:

```bash
uvicorn app:app --reload
```

### Login

```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "secret"}'
```

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer"
}
```

### Access a Protected Route

Copy the `access_token` from the response and use it:

```bash
curl http://localhost:8000/me \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
```

```json
{
  "id": "1",
  "username": "alice"
}
```

### Without a Token

```bash
curl http://localhost:8000/me
```

```json
{
  "detail": "Not authenticated"
}
```

Status code: `401 Unauthorized`.

You also get interactive documentation at `http://localhost:8000/docs` with a working "Authorize" button -- urauth automatically configures the OpenAPI security scheme.

## What You Now Have

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/login` | POST | Username + password login, returns access + refresh tokens |
| `/auth/refresh` | POST | Refresh token rotation, returns new token pair |
| `/auth/logout` | POST | Revoke the current session (access + refresh tokens) |
| `/auth/logout-all` | POST | Revoke all sessions for the user |
| `/me` | GET | Protected route returning the current user |

## Recap

- Your user model just needs `id` and `is_active` -- no base class, just a protocol.
- Subclass `Auth` and override three methods: `get_user`, `get_user_by_username`, `verify_password`. Sync and async both work.
- Create `FastAuth(core)` to get the FastAPI adapter. Call `password_auth_router()` for login/refresh/logout endpoints.
- `auth.current_user` is a **property** that returns a FastAPI dependency. Use it with `Depends(auth.current_user)`.

**Next:** [Protecting Routes](protecting-routes.md)
