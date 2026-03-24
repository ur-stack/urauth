# Sessions

Server-side session management as an alternative or complement to JWT tokens.

## Pipeline Approach (Recommended)

Use `SessionStrategy` with a `Pipeline` for automatic session handling:

```python
from urauth import Auth, AuthConfig, Pipeline, SessionStrategy
from urauth.backends.memory import MemorySessionStore

core = MyAuth(
    config=AuthConfig(
        secret_key="your-secret",
        session_cookie_name="session_id",  # default
        session_ttl=86400,                 # 24 hours (default)
        session_cookie_secure=True,        # default
        session_cookie_httponly=True,       # default
        session_cookie_samesite="lax",     # default
    ),
    session_store=MemorySessionStore(),
    pipeline=Pipeline(
        strategy=SessionStrategy(cookie_name="session_id"),
        password=True,
    ),
)
```

Then wire it into FastAPI:

```python
from urauth.fastapi import FastAuth

auth = FastAuth(core)
router = auth.auto_router()
app.include_router(router)
```

The pipeline generates login/logout endpoints that create and destroy sessions automatically.

## Manual Session Management

For finer control, use `SessionManager` directly:

```python
from urauth import AuthConfig
from urauth.backends.memory import MemorySessionStore
from urauth.fastapi.sessions import SessionManager

config = AuthConfig(
    secret_key="your-secret",
    session_cookie_name="session_id",
    session_ttl=86400,
)

store = MemorySessionStore()
session_manager = SessionManager(store, config)
```

### Creating Sessions

```python
from fastapi import Response

@app.post("/login")
async def login(response: Response):
    user = ...  # authenticate user
    session_id = await session_manager.create_session(
        user_id=user.id,
        response=response,
        data={"role": "admin"},  # optional extra data
    )
    return {"message": "Logged in"}
```

The session ID is set as an HTTP-only cookie on the response.

### Reading Sessions

```python
from fastapi import Request

@app.get("/me")
async def me(request: Request):
    session = await session_manager.get_session(request)
    if session is None:
        raise HTTPException(401)
    return {"user_id": session["user_id"]}
```

### Destroying Sessions

```python
from fastapi import Request, Response

@app.post("/logout")
async def logout(request: Request, response: Response):
    await session_manager.destroy_session(request, response)
    return {"message": "Logged out"}
```

### Destroy All Sessions for a User

```python
await session_manager.destroy_all_for_user(user_id="123")
```

## Session Dependency

Use the built-in dependency for cleaner code:

```python
from fastapi import Depends
from urauth.fastapi.authn.session import session_dependency

get_user = session_dependency(session_manager, user_fns)

@app.get("/me")
async def me(user=Depends(get_user)):
    return {"id": user.id}
```

This extracts the session, loads the user via the provided `UserFunctions`, and checks that the user is active.

## Redis Session Store (Production)

```python
from redis.asyncio import Redis
from urauth.sessions.redis import RedisSessionStore

redis = Redis.from_url("redis://localhost:6379")
store = RedisSessionStore(redis, prefix="session:")
session_manager = SessionManager(store, config)
```

!!! warning
    `MemorySessionStore` does not persist across restarts. Use `RedisSessionStore` in production.

## Session Config Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `session_cookie_name` | `str` | `"session_id"` | Cookie name for the session ID |
| `session_ttl` | `int` | `86400` | Session lifetime in seconds |
| `session_cookie_secure` | `bool` | `True` | Require HTTPS |
| `session_cookie_httponly` | `bool` | `True` | Block JavaScript access |
| `session_cookie_samesite` | `"lax" \| "strict" \| "none"` | `"lax"` | SameSite policy |
