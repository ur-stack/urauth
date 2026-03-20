# CSRF Protection

Protect cookie-based authentication from Cross-Site Request Forgery attacks.

## Enable CSRF Middleware

```python
from fastapi_auth import AuthConfig
from fastapi_auth.middleware import CSRFMiddleware

config = AuthConfig(
    secret_key="your-secret",
    csrf_enabled=True,
    csrf_cookie_name="csrf_token",   # default
    csrf_header_name="X-CSRF-Token", # default
)

app.add_middleware(CSRFMiddleware, config=config)
```

## How It Works (Double-Submit Cookie)

1. On safe requests (`GET`, `HEAD`, `OPTIONS`), the middleware sets a `csrf_token` cookie if one doesn't exist.
2. On unsafe requests (`POST`, `PUT`, `DELETE`, `PATCH`), the middleware checks that the `X-CSRF-Token` header matches the `csrf_token` cookie.
3. If they don't match (or the header is missing), the request is rejected with `403 Forbidden`.

!!! info
    The double-submit pattern works because an attacker can trigger a request with the cookie (browsers send cookies automatically), but cannot read the cookie value to set the header.

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

!!! tip
    CSRF protection is only needed when using cookie-based authentication. Bearer token authentication is inherently immune to CSRF because the token must be explicitly included in the request header.
