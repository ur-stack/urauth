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

::: info Required packages
```bash
pip install "urauth[fastapi]" sqlmodel aiosqlite
```
:::

```python
from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    email: str = Field(unique=True, index=True)
    hashed_password: str
    is_active: bool = True
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
```

::: info Protocol, not base class
urauth uses `UserProtocol` -- a runtime-checkable protocol that only requires `id` and `is_active`. You never inherit from a base class. Any object with those two attributes works.

```python
from urauth.types import UserProtocol

# Your SQLModel table satisfies this automatically
assert isinstance(
    User(email="alice@example.com", hashed_password="x"),
    UserProtocol,
)
```

:::
## Wire Up User Data

The recommended production approach is the **mixin composition pattern** via `SQLModelUserStore`. Mix it into your `Auth` subclass and pass a `session_factory` and `user_model` -- no method overrides needed for the standard three hooks.

```python
from urauth import Auth, JWT, Password, PasswordHasher
from urauth.backends.memory import MemoryTokenStore
from urauth.contrib.sqlmodel import SQLModelUserStore

hasher = PasswordHasher()


class MyAuth(Auth, SQLModelUserStore):                         # (1)
    async def verify_password(self, user, password):           # (2)
        return hasher.verify(password, user.hashed_password)
```

1. `SQLModelUserStore` provides `get_user` and `get_user_by_username` automatically -- it queries by `id` and `email` respectively using the `session_factory` and `user_model` you pass to the constructor.
2. You only need to override `verify_password`, since password hashing is app-specific.

::: tip Overriding methods manually
If you need custom query logic, skip the mixin and override all three methods yourself:

```python
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

class MyAuth(Auth):
    async def get_user(self, user_id):                        # (1)
        async with async_session() as session:
            return await session.get(User, user_id)

    async def get_user_by_username(self, username):            # (2)
        async with async_session() as session:
            result = await session.exec(select(User).where(User.email == username))
            return result.first()

    async def verify_password(self, user, password):           # (3)
        return hasher.verify(password, user.hashed_password)
```

1. Called when resolving a user from a JWT `sub` claim.
2. Called during login to find the user by email (or username).
3. Called during login to verify the plaintext password against the stored hash.
:::

::: tip Callable kwargs for quick setups
For smaller apps or scripts you can also pass callables directly to `Auth()` without subclassing:

```python
core = Auth(
    get_user=lambda uid: ...,
    get_user_by_username=lambda u: ...,
    verify_password=lambda user, pw: hasher.verify(pw, user.hashed_password),
    method=JWT(...), secret_key="...", password=Password(),
)
```

:::

## Create the Auth Instance

First, set up an async engine and session factory for your database. Then create the auth instance with flat parameters on the `MyAuth` subclass:

```python
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel.ext.asyncio.session import AsyncSession

DATABASE_URL = "sqlite+aiosqlite:///./app.db"  # (1)

engine = create_async_engine(DATABASE_URL, echo=False)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)  # (2)

core = MyAuth(
    session_factory=async_session,                                        # (3)
    user_model=User,                                                      # (4)
    method=JWT(ttl=900, refresh_ttl=604800, store=MemoryTokenStore()),   # (5)
    secret_key="super-secret-key",                                        # (6)
    password=Password(),                                                  # (7)
)
```

1. `sqlite+aiosqlite` uses async SQLite, which is great for local development. In production, swap in your real database URL (e.g. `postgresql+asyncpg://user:pass@host/db`).
2. `async_session` is a factory (not a session instance). urauth calls it to open a new session per request.
3. `session_factory` is passed to `SQLModelUserStore` via the constructor -- it is used by `get_user` and `get_user_by_username`.
4. `user_model` tells the mixin which SQLModel table to query.
5. `JWT(...)` configures JWT-based authentication with access token TTL (15 min), refresh token TTL (7 days), and an in-memory token store. For production, use a Redis-backed store: `pip install "urauth[redis]"`.
6. For development only. In production, set `AUTH_SECRET_KEY` via environment variable with a 32+ byte random key: `openssl rand -hex 32`.
7. `Password()` enables username/password login.

::: danger Production Requirements
Before deploying to production:

- Set `AUTH_SECRET_KEY` to a random 32+ byte key: `openssl rand -hex 32`
- Replace `MemoryTokenStore` with a persistent store (Redis, database)
- Set `token_issuer` and `token_audience` on `Auth()`
- Enable CSRF if using cookie-based auth

:::
## Wire Up FastAuth

`FastAuth` is the FastAPI adapter. It wraps your `Auth` instance and provides FastAPI-specific features: dependencies, guards, routers, and transports.

```python
from fastapi import Depends, FastAPI
from urauth.fastapi import FastAuth

auth = FastAuth(core)
```

## Create the App

```python
app = FastAPI(lifespan=auth.lifespan())  # (1)
auth.init_app(app)                        # (2)
app.include_router(auth.auto_router())    # (3)
```

1. `auth.lifespan()` returns an ASGI lifespan context manager. Wire it into FastAPI so startup/shutdown hooks work.
2. `init_app()` registers urauth's exception handlers on the app. These convert `AuthError` subclasses into proper HTTP responses.
3. `auto_router()` generates login, refresh, logout, and logout-all endpoints under `/auth` based on the configured auth method and login methods.

## Add a Protected Route

Use `Depends(auth.current_user)` to require authentication. Note that `current_user` is a **property**, not a method call -- no parentheses.

```python
@app.get("/me")
async def me(user=Depends(auth.current_user)):  # (1)
    return {"id": user.id, "username": user.username}
```

1. `auth.current_user` returns a FastAPI dependency function. FastAPI calls it automatically, extracts the JWT from the `Authorization: Bearer` header, validates it, loads the user, and injects it as `user`.

## Full Example

Here is the complete application in a single file. It uses SQLModel with async SQLite so you can run it locally with no external services.

```python title="app.py"
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import Field, SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession

from urauth import Auth, JWT, Password, PasswordHasher
from urauth.backends.memory import MemoryTokenStore
from urauth.contrib.sqlmodel import SQLModelUserStore
from urauth.fastapi import FastAuth

# ── Database ─────────────────────────────────────────────────

DATABASE_URL = "sqlite+aiosqlite:///./app.db"

engine = create_async_engine(DATABASE_URL, echo=False)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

# ── User model ────────────────────────────────────────────────

hasher = PasswordHasher()


class User(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    email: str = Field(unique=True, index=True)
    hashed_password: str
    is_active: bool = True
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


# ── Auth subclass ─────────────────────────────────────────────

class MyAuth(Auth, SQLModelUserStore):
    async def verify_password(self, user, password):
        return hasher.verify(password, user.hashed_password)


# ── Auth instance ─────────────────────────────────────────────

core = MyAuth(
    session_factory=async_session,
    user_model=User,
    method=JWT(ttl=900, refresh_ttl=604800, store=MemoryTokenStore()),
    secret_key="super-secret-key",
    password=Password(),
)
auth = FastAuth(core)

# ── App ───────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)  # (1)
    yield


app = FastAPI(lifespan=lifespan)
auth.init_app(app)
app.include_router(auth.auto_router())


@app.get("/me")
async def me(user=Depends(auth.current_user)):
    return {"id": str(user.id), "email": user.email}


# ── Seed data (optional, dev only) ───────────────────────────

@app.on_event("startup")
async def seed():
    async with async_session() as session:
        result = await session.exec(select(User).where(User.email == "alice@example.com"))
        if result.first() is None:
            session.add(User(
                email="alice@example.com",
                hashed_password=hasher.hash("secret"),
            ))
            await session.commit()
```

1. `create_all` runs once at startup, creating any missing tables. Safe to call repeatedly -- it skips tables that already exist.

## Test It

Start the server:

```bash
uvicorn app:app --reload
```

### Login

```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice@example.com", "password": "secret"}'
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
  "id": "a1b2c3d4-...",
  "email": "alice@example.com"
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

- Your user model just needs `id` and `is_active` -- no base class, just a protocol. A `SQLModel` table with a UUID primary key works out of the box.
- Use the `SQLModelUserStore` mixin for production: `class MyAuth(Auth, SQLModelUserStore)`. Only `verify_password` needs overriding -- `get_user` and `get_user_by_username` are provided by the mixin.
- Pass `session_factory` and `user_model` to the constructor alongside your auth configuration.
- Create `MyAuth(session_factory=..., user_model=User, method=JWT(...), secret_key="...", password=Password())`.
- Wrap in `FastAuth(core)` to get the FastAPI adapter. Call `auto_router()` for login/refresh/logout endpoints.
- `auth.current_user` is a **property** that returns a FastAPI dependency. Use it with `Depends(auth.current_user)`.

**Next:** [Protecting Routes](protecting-routes.md)
