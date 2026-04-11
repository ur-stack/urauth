# CSRF Protection

Protect cookie-based authentication from Cross-Site Request Forgery attacks.

## Enable CSRF Middleware

```python
from urauth.fastapi.middleware import CSRFMiddleware

# CSRF settings can be set via environment variables:
# AUTH_CSRF_ENABLED=true
# AUTH_CSRF_COOKIE_NAME=csrf_token
# AUTH_CSRF_HEADER_NAME=X-CSRF-Token

# Or pass them when creating the auth instance:
core = Auth(
    method=JWT(ttl=900, store=token_store),
    secret_key="your-secret",
    password=Password(),
)

# Add the middleware with the auth instance's internal config
app.add_middleware(CSRFMiddleware, config=core._config)
```

## How It Works (Double-Submit Cookie)

1. On safe requests (`GET`, `HEAD`, `OPTIONS`), the middleware sets a `csrf_token` cookie if one does not exist.
2. On unsafe requests (`POST`, `PUT`, `DELETE`, `PATCH`), the middleware checks that the `X-CSRF-Token` header matches the `csrf_token` cookie.
3. If they do not match (or the header is missing), the request is rejected with `403 Forbidden`.


> **`info`** — See source code for full API.

The double-submit pattern works because an attacker can trigger a request with the cookie (browsers send cookies automatically), but cannot read the cookie value to set the header.

:::
## Frontend Integration

Your JavaScript frontend needs to read the CSRF cookie and include it as a header:

```javascript
// Read the CSRF token from the cookie
function getCsrfToken() {
  const match = document.cookie.match(/csrf_token=([^;]+)/);
  return match ? match[1] : null;
}

// Include it in every mutating request
fetch("/api/posts", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-CSRF-Token": getCsrfToken(),  // (1)!
  },
  credentials: "include",  // (2)!
  body: JSON.stringify({ title: "Hello" }),
});
```

1. The header value must match the cookie value.
2. `credentials: "include"` ensures the cookie is sent with the request.

## CSRF Config Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `csrf_enabled` | `bool` | `False` | Enable CSRF protection |
| `csrf_cookie_name` | `str` | `"csrf_token"` | Name of the CSRF cookie |
| `csrf_header_name` | `str` | `"X-CSRF-Token"` | Header to check against the cookie |


> **`tip`** — See source code for full API.

CSRF protection is only needed when using cookie-based authentication. Bearer token authentication is inherently immune to CSRF because the token must be explicitly included in the request header.

:::