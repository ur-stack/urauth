# Security

## Always Set a Strong Secret Key

The default `"CHANGE-ME-IN-PRODUCTION"` key will trigger a warning at startup. In production, use a cryptographically random secret of at least 32 bytes:

```bash title=".env"
AUTH_SECRET_KEY=$(openssl rand -hex 32)
```


> **`danger`** — See source code for full API.

Never commit secret keys to version control. Use environment variables or a secrets manager.

:::
## Use Short-Lived Access Tokens

Keep access token TTL short (5-15 minutes) and rely on refresh tokens for session continuity. This limits the window of exposure if a token is leaked:

```python
core = MyAuth(
    method=JWT(
        ttl=300,            # 5 minutes
        refresh_ttl=604800, # 7 days
        refresh=True,       # Revoke old refresh token on rotation (default)
        store=token_store,
    ),
    secret_key="...",
    password=Password(),
)
```

## Enable CSRF Protection for Cookie Transport

If you use cookie-based transport (common for browser SPAs), always enable CSRF protection:

```bash
# .env
AUTH_CSRF_ENABLED=true
AUTH_COOKIE_HTTPONLY=true
AUTH_COOKIE_SECURE=true
AUTH_COOKIE_SAMESITE=lax
```

## Rate-Limit Authentication Endpoints

Login and token refresh endpoints are prime targets for brute-force attacks. Always rate-limit them:

```python
from urauth.ratelimit import RateLimiter

limiter = RateLimiter(max_requests=5, window_seconds=60)

@app.post("/auth/login")
@limiter
async def login(request: Request):
    ...
```

## Validate at System Boundaries

urauth validates tokens and checks permissions internally. You do not need to re-validate in your business logic. Trust `AuthContext` -- it was built from a verified token:

```python
# Good -- trust the context
@app.get("/me")
async def get_me(ctx: AuthContext = Depends(auth.context)):
    return {"id": ctx.user.id}

# Unnecessary -- context is already validated
@app.get("/me")
async def get_me(ctx: AuthContext = Depends(auth.context)):
    if not ctx.is_authenticated():  # Already guaranteed by non-optional context
        raise HTTPException(401)
    return {"id": ctx.user.id}
```
