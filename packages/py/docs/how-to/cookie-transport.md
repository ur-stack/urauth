# Cookie Transport

Use cookies instead of (or in addition to) bearer tokens.

## Cookie-Only Transport

```python
from urauth import AuthConfig
from urauth.fastapi import FastAuth, CookieTransport

config = AuthConfig(
    secret_key="your-secret",
    cookie_name="access_token",   # default
    cookie_secure=True,           # default — requires HTTPS
    cookie_httponly=True,          # default — not accessible to JS
    cookie_samesite="lax",        # default
    cookie_domain=None,           # default — current domain
    cookie_path="/",              # default
)

auth = FastAuth(core, transport=CookieTransport(config))
```

With this setup, `POST /auth/login` sets a cookie instead of returning a bearer token.


> **`warning`** — See source code for full API.

Set `cookie_secure=False` only during local development over HTTP.

:::
## Pipeline Approach

When using a `Pipeline`, set `transport="cookie"` on the strategy and the transport is configured automatically:

```python
from urauth import Auth, AuthConfig, Pipeline, JWTStrategy

core = MyAuth(
    config=AuthConfig(secret_key="your-secret"),
    pipeline=Pipeline(
        strategy=JWTStrategy(transport="cookie"),
        password=True,
    ),
)

auth = FastAuth(core)  # CookieTransport is auto-selected
```

## Hybrid Transport

Use bearer tokens as the primary method, with cookies as a fallback:

```python
from urauth.fastapi import FastAuth, HybridTransport, BearerTransport, CookieTransport

transport = HybridTransport(
    BearerTransport(),           // (1)
    CookieTransport(config),     // (2)
)

auth = FastAuth(core, transport=transport)
```

1. Tried first — checks the `Authorization: Bearer` header.
2. Fallback — checks the cookie.

This is useful when you have both API clients (using bearer tokens) and a browser frontend (using cookies).

## Pipeline Hybrid

With `Pipeline`, set `transport="hybrid"` for the same behavior:

```python
core = MyAuth(
    config=AuthConfig(secret_key="your-secret"),
    pipeline=Pipeline(
        strategy=JWTStrategy(transport="hybrid"),
        password=True,
    ),
)

auth = FastAuth(core)  # HybridTransport is auto-selected
```

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
from urauth.fastapi.middleware import TokenRefreshMiddleware

app.add_middleware(
    TokenRefreshMiddleware,
    lifecycle=auth.lifecycle,
    transport=CookieTransport(auth.config),
    threshold=300,  # refresh when less than 5 minutes remain (default)
)
```


> **`tip`** — See source code for full API.

This only works with cookie transport — bearer tokens are returned in the response body and cannot be silently refreshed.

:::