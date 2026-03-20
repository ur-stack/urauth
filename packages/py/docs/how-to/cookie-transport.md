# Cookie Transport

Use cookies instead of (or in addition to) bearer tokens.

## Cookie-Only Transport

```python
from fastapi_auth import FastAPIAuth, AuthConfig, CookieTransport

config = AuthConfig(
    secret_key="your-secret",
    cookie_name="access_token",   # default
    cookie_secure=True,           # default — requires HTTPS
    cookie_httponly=True,          # default — not accessible to JS
    cookie_samesite="lax",        # default
    cookie_domain=None,           # default — current domain
    cookie_path="/",              # default
)

auth = FastAPIAuth(
    MyBackend(),
    config,
    transport=CookieTransport(config),
)
```

With this setup, `POST /auth/login` sets a cookie instead of returning a bearer token.

!!! warning
    Set `cookie_secure=False` only during local development over HTTP.

## Hybrid Transport

Use bearer tokens as the primary method, with cookies as a fallback:

```python
from fastapi_auth import HybridTransport, CookieTransport
from fastapi_auth.transport import BearerTransport

transport = HybridTransport(
    BearerTransport(),           # (1)!
    CookieTransport(config),     # (2)!
)

auth = FastAPIAuth(MyBackend(), config, transport=transport)
```

1. Tried first — checks the `Authorization: Bearer` header.
2. Fallback — checks the cookie.

This is useful when you have both API clients (using bearer tokens) and a browser frontend (using cookies).

## Cookie Configuration Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `cookie_name` | `str` | `"access_token"` | Cookie name |
| `cookie_secure` | `bool` | `True` | Require HTTPS |
| `cookie_httponly` | `bool` | `True` | Block JavaScript access |
| `cookie_samesite` | `"lax" \| "strict" \| "none"` | `"lax"` | SameSite policy |
| `cookie_domain` | `str \| None` | `None` | Cookie domain |
| `cookie_path` | `str` | `"/"` | Cookie path |
| `cookie_max_age` | `int \| None` | `None` | Max age in seconds |

## Auto-Refresh with Middleware

`TokenRefreshMiddleware` automatically refreshes near-expiry access tokens in cookies:

```python
from fastapi_auth.middleware import TokenRefreshMiddleware

app.add_middleware(
    TokenRefreshMiddleware,
    token_service=auth.token_service,
    transport=auth.config,  # or your CookieTransport instance
    threshold=300,  # refresh when less than 5 minutes remain (default)
)
```

!!! tip
    This only works with cookie transport — bearer tokens are returned in the response body and can't be silently refreshed.
