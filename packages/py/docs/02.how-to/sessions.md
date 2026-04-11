# Sessions

Server-side session management as an alternative or complement to JWT tokens.

## Auth Method Approach (Recommended)

Use `Session` as the auth method for automatic session handling:

```python
from urauth import Auth, Password, Session
from urauth.backends.memory import MemorySessionStore

core = Auth(
    method=Session(
        cookie_name="sid",       # default
        ttl=86400,               # 24 hours (default)
        store=MemorySessionStore(),
    ),
    secret_key="your-secret",
    password=Password(),
)
```

Then wire it into FastAPI:

```python
from urauth.fastapi import FastAuth

auth = FastAuth(core)
router = auth.auto_router()
app.include_router(router)
```

The auto router generates login/logout endpoints that create and destroy sessions automatically.

## Manual Session Management

For finer control, use `SessionManager` directly:

```python
from urauth.backends.memory import MemorySessionStore
from urauth.fastapi.sessions import SessionManager

store = MemorySessionStore()
session_manager = SessionManager(store, cookie_name="sid", ttl=86400)
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

core = Auth(
    method=Session(cookie_name="sid", ttl=86400, store=store),
    secret_key="your-secret",
    password=Password(),
)
```


> **`warning`** -- See source code for full API.

`MemorySessionStore` does not persist across restarts. Use `RedisSessionStore` in production.

:::
## Session Config Fields

Session settings are configured on the `Session` auth method:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `cookie_name` | `str` | `"sid"` | Cookie name for the session ID |
| `ttl` | `int` | `86400` | Session lifetime in seconds |
| `store` | `SessionStore` | Required | Session data store (memory or Redis) |
