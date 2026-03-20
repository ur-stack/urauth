# Sessions

Server-side session management as an alternative or complement to JWT tokens.

## Setup

```python
from fastapi_auth.sessions.base import SessionManager
from fastapi_auth.backends.memory import MemorySessionStore
from fastapi_auth import AuthConfig

config = AuthConfig(
    secret_key="your-secret",
    session_cookie_name="session_id",  # default
    session_ttl=86400,                 # 24 hours (default)
    session_cookie_secure=True,        # default
    session_cookie_httponly=True,       # default
    session_cookie_samesite="lax",     # default
)

store = MemorySessionStore()
session_manager = SessionManager(store, config)
```

## Creating Sessions

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

## Reading Sessions

```python
from fastapi import Request

@app.get("/me")
async def me(request: Request):
    session = await session_manager.get_session(request)
    if session is None:
        raise HTTPException(401)
    return {"user_id": session["user_id"]}
```

## Session Dependency

Use the built-in dependency for cleaner code:

```python
from fastapi import Depends
from fastapi_auth.authn.session import session_dependency

get_user = session_dependency(session_manager, backend)

@app.get("/me")
async def me(user=Depends(get_user)):
    return {"id": user.id}
```

This extracts the session, loads the user from the backend, and checks that the user is active.

## Destroying Sessions

```python
from fastapi import Request, Response

@app.post("/logout")
async def logout(request: Request, response: Response):
    await session_manager.destroy_session(request, response)
    return {"message": "Logged out"}
```

## Destroy All Sessions for a User

```python
await session_manager.destroy_all_for_user(user_id="123")
```

## Redis Session Store (Production)

```python
from redis.asyncio import Redis
from fastapi_auth.sessions.redis import RedisSessionStore

redis = Redis.from_url("redis://localhost:6379")
store = RedisSessionStore(redis, prefix="session:")
session_manager = SessionManager(store, config)
```

!!! warning
    `MemorySessionStore` doesn't persist across restarts. Use `RedisSessionStore` in production.

## Session Config Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `session_cookie_name` | `str` | `"session_id"` | Cookie name for the session ID |
| `session_ttl` | `int` | `86400` | Session lifetime in seconds |
| `session_cookie_secure` | `bool` | `True` | Require HTTPS |
| `session_cookie_httponly` | `bool` | `True` | Block JavaScript access |
| `session_cookie_samesite` | `"lax" \| "strict" \| "none"` | `"lax"` | SameSite policy |
