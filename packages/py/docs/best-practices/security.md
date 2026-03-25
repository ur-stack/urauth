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
config = AuthConfig(
    access_token_ttl=300,       # 5 minutes
    refresh_token_ttl=604800,   # 7 days
    rotate_refresh_tokens=True, # Revoke old refresh token on rotation
)
```

## Enable CSRF Protection for Cookie Transport

If you use cookie-based transport (common for browser SPAs), always enable CSRF protection:

```python
config = AuthConfig(
    csrf_enabled=True,
    cookie_httponly=True,
    cookie_secure=True,
    cookie_samesite="lax",
)
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
