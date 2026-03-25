# Safe Usage Guide

Concrete DO and DON'T patterns for running urauth safely in production.

## Secret Key Management

### DO: Set `AUTH_SECRET_KEY` via environment variable

Generate a strong key and inject it through the environment:

```bash
# Generate a 256-bit key
openssl rand -hex 32
```

```python
# .env
AUTH_SECRET_KEY=a1b2c3d4e5f6...  # 64 hex characters

# settings are loaded automatically from environment
from urauth import AuthConfig

config = AuthConfig()  # reads AUTH_SECRET_KEY from env
```

### DON'T: Hardcode secrets or use weak keys

```python
# BAD -- hardcoded secret, will end up in version control
config = AuthConfig(secret_key="my-secret-key")

# BAD -- too short, easily brute-forced
config = AuthConfig(secret_key="abc123")
```


> **`danger`** — See source code for full API.

If your secret key is compromised, an attacker can forge valid tokens for any user. Rotate immediately if this happens.

:::

## Token Store

### DO: Use a persistent TokenStore in production

```python
from urauth import AuthConfig

# Redis-backed store -- survives restarts, supports horizontal scaling
config = AuthConfig(
    secret_key_from_env=True,
    token_store_backend="redis",
    token_store_url="redis://localhost:6379/0",
)
```

### DON'T: Use `MemoryTokenStore` in production

```python
# BAD -- tokens lost on restart, no sharing across workers/processes
config = AuthConfig(
    secret_key_from_env=True,
    token_store_backend="memory",  # default -- fine for development only
)
```


> **`warning`** — See source code for full API.

`MemoryTokenStore` is the default for convenience during development. It stores tokens in a Python dictionary. On restart, all refresh tokens are lost and users must re-authenticate. It also cannot be shared across multiple worker processes or instances.

:::

## CSRF Protection

### DO: Enable CSRF for cookie-based authentication

```python
from urauth import AuthConfig

config = AuthConfig(
    secret_key_from_env=True,
    cookie_csrf_protect=True,  # enables double-submit cookie pattern
)
```

### DON'T: Rely on cookies alone without CSRF

```python
# BAD -- cookie auth without CSRF leaves you open to cross-site request forgery
config = AuthConfig(
    secret_key_from_env=True,
    use_cookies=True,
    cookie_csrf_protect=False,
)
```


> **`info`** — See source code for full API.

If you use Bearer tokens in the `Authorization` header (not cookies), CSRF protection is not needed because browsers do not attach custom headers to cross-site requests automatically.

:::

## Token Issuer and Audience

### DO: Set `token_issuer` and `token_audience`

```python
from urauth import AuthConfig

config = AuthConfig(
    secret_key_from_env=True,
    token_issuer="https://auth.example.com",
    token_audience="https://api.example.com",
)
```

This ensures tokens minted by one service are not accepted by another. PyJWT validates both claims on decode.

### DON'T: Leave issuer and audience unset

```python
# BAD -- any token signed with the same key will be accepted,
# regardless of which service issued it or who it was intended for
config = AuthConfig(
    secret_key_from_env=True,
    # token_issuer not set
    # token_audience not set
)
```

## Access Token Lifetime

### DO: Use short-lived access tokens

```python
from urauth import AuthConfig

# Default is 900 seconds (15 minutes) -- this is a good baseline
config = AuthConfig(
    secret_key_from_env=True,
    access_token_ttl=900,
)
```

Short-lived access tokens limit the damage window if a token is leaked. Pair with refresh token rotation so users don't need to re-authenticate frequently.

### DON'T: Set long access token TTLs without understanding the risk

```python
# BAD -- 24-hour access tokens mean a leaked token is valid for a full day
config = AuthConfig(
    secret_key_from_env=True,
    access_token_ttl=86400,
)
```


> **`tip`** — See source code for full API.

If you need longer sessions, keep access tokens short (15 min) and use refresh tokens with rotation. This way, a leaked access token expires quickly and a leaked refresh token can only be used once.

:::

## Extra Claims

### DO: Use a controlled allowlist for extra claims

```python
from urauth.tokens.jwt import create_access_token

# GOOD -- claims come from your application logic, not user input
token = create_access_token(
    subject=user.id,
    extra_claims={"role": user.role, "org_id": user.org_id},
)
```

### DON'T: Pass user-controlled input as extra claims

```python
from urauth.tokens.jwt import create_access_token

# BAD -- user can inject arbitrary claims into their own token
token = create_access_token(
    subject=user.id,
    extra_claims=request.json(),  # never do this
)
```


> **`danger`** — See source code for full API.

urauth protects reserved claims (`sub`, `exp`, `iat`, `jti`, `iss`, `aud`) from being overwritten via `extra_claims`. However, an attacker could still inject application-level claims like `role` or `is_admin` if you pass unvalidated user input.

:::

## Insecure Key Flag

### DO: Keep `allow_insecure_key` at its default (`False`)

```python
from urauth import AuthConfig

# GOOD -- urauth will reject keys shorter than 32 bytes
config = AuthConfig(secret_key_from_env=True)
```

### DON'T: Set `allow_insecure_key=True` in production

```python
# BAD -- disables key length validation, allows weak keys
config = AuthConfig(
    secret_key="short",
    allow_insecure_key=True,  # only for tests
)
```


> **`warning`** — See source code for full API.

The `allow_insecure_key` flag exists solely for test fixtures where a full-strength key is unnecessary overhead. It should never appear in production configuration.

:::

## Token Storage on the Client

### DO: Use `httpOnly` cookies (urauth default)

```python
from urauth import AuthConfig

# GOOD -- tokens stored in httpOnly cookies, inaccessible to JavaScript
config = AuthConfig(
    secret_key_from_env=True,
    use_cookies=True,
    cookie_httponly=True,   # default
    cookie_secure=True,     # default
    cookie_samesite="lax",  # default
)
```

### DON'T: Store tokens in localStorage

```javascript
// BAD -- any XSS vulnerability can steal the token
localStorage.setItem("access_token", response.data.token);
```


> **`info`** — See source code for full API.

urauth's cookie defaults (`httponly=True`, `secure=True`, `samesite="lax"`) protect against the most common client-side token theft vectors. If you must use Bearer tokens in a SPA, store them in memory (a JavaScript variable) rather than `localStorage` or `sessionStorage`.

:::