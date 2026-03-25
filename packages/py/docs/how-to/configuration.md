# Configuration

All configuration is managed through `AuthConfig`, a Pydantic Settings class that reads from environment variables with the `AUTH_` prefix.

## Production Required Settings

::: danger Set these before deploying
These settings are **required** for production deployments. urauth will raise `ValueError` at startup if `AUTH_ENVIRONMENT=production` and key validation fails.

:::
```bash title=".env (production)"
AUTH_ENVIRONMENT=production
AUTH_SECRET_KEY=<output of: openssl rand -hex 32>
AUTH_TOKEN_ISSUER=your-app-name
AUTH_TOKEN_AUDIENCE=your-app-audience
AUTH_CSRF_ENABLED=true  # if using cookie-based auth
```

| Setting | Why |
|---------|-----|
| `AUTH_SECRET_KEY` | Must be 32+ bytes for HMAC. Default key raises `ValueError`. |
| `AUTH_ENVIRONMENT` | Set to `production` to enforce key validation and reject `allow_insecure_key`. |
| `AUTH_TOKEN_ISSUER` | Prevents cross-app token confusion. |
| `AUTH_TOKEN_AUDIENCE` | Limits token acceptance to intended consumers. |

## Environment Variables

Every field can be set via environment variable:

```bash
export AUTH_SECRET_KEY="your-production-secret"
export AUTH_ACCESS_TOKEN_TTL=1800
export AUTH_COOKIE_SECURE=true
```

Or use a `.env` file (Pydantic Settings loads it automatically):

```bash title=".env"
AUTH_SECRET_KEY=your-production-secret
AUTH_ALGORITHM=HS256
AUTH_ACCESS_TOKEN_TTL=1800
AUTH_REFRESH_TOKEN_TTL=604800
AUTH_COOKIE_SECURE=true
AUTH_CSRF_ENABLED=true
AUTH_TENANT_ENABLED=false
```

::: danger Default secret key
The default `secret_key` is `"CHANGE-ME-IN-PRODUCTION"`. **Never use this in production.** Always set `AUTH_SECRET_KEY` via environment variable.

:::
## All Configuration Fields

### JWT

| Field | Type | Default | Env Var | Description |
|-------|------|---------|---------|-------------|
| `secret_key` | `str` | `"CHANGE-ME-IN-PRODUCTION"` | `AUTH_SECRET_KEY` | Signing key for JWTs |
| `algorithm` | `str` | `"HS256"` | `AUTH_ALGORITHM` | JWT algorithm (HS256, RS256, ES256, etc.) |
| `access_token_ttl` | `int` | `900` | `AUTH_ACCESS_TOKEN_TTL` | Access token lifetime in seconds (15 min) |
| `refresh_token_ttl` | `int` | `604800` | `AUTH_REFRESH_TOKEN_TTL` | Refresh token lifetime in seconds (7 days) |
| `token_issuer` | `str \| None` | `None` | `AUTH_TOKEN_ISSUER` | JWT `iss` claim |
| `token_audience` | `str \| None` | `None` | `AUTH_TOKEN_AUDIENCE` | JWT `aud` claim |
| `rotate_refresh_tokens` | `bool` | `True` | `AUTH_ROTATE_REFRESH_TOKENS` | Revoke old refresh token on rotation |

### Password

| Field | Type | Default | Env Var | Description |
|-------|------|---------|---------|-------------|
| `password_hash_scheme` | `str` | `"bcrypt"` | `AUTH_PASSWORD_HASH_SCHEME` | Password hashing scheme |

### Cookie Transport

| Field | Type | Default | Env Var | Description |
|-------|------|---------|---------|-------------|
| `cookie_name` | `str` | `"access_token"` | `AUTH_COOKIE_NAME` | Cookie name for access token |
| `cookie_secure` | `bool` | `True` | `AUTH_COOKIE_SECURE` | Require HTTPS |
| `cookie_httponly` | `bool` | `True` | `AUTH_COOKIE_HTTPONLY` | Block JavaScript access |
| `cookie_samesite` | `"lax" \| "strict" \| "none"` | `"lax"` | `AUTH_COOKIE_SAMESITE` | SameSite policy |
| `cookie_domain` | `str \| None` | `None` | `AUTH_COOKIE_DOMAIN` | Cookie domain |
| `cookie_path` | `str` | `"/"` | `AUTH_COOKIE_PATH` | Cookie path |
| `cookie_max_age` | `int \| None` | `None` | `AUTH_COOKIE_MAX_AGE` | Max age in seconds |

### Sessions

| Field | Type | Default | Env Var | Description |
|-------|------|---------|---------|-------------|
| `session_cookie_name` | `str` | `"session_id"` | `AUTH_SESSION_COOKIE_NAME` | Session cookie name |
| `session_ttl` | `int` | `86400` | `AUTH_SESSION_TTL` | Session lifetime in seconds (24 hours) |
| `session_cookie_secure` | `bool` | `True` | `AUTH_SESSION_COOKIE_SECURE` | Require HTTPS |
| `session_cookie_httponly` | `bool` | `True` | `AUTH_SESSION_COOKIE_HTTPONLY` | Block JavaScript access |
| `session_cookie_samesite` | `"lax" \| "strict" \| "none"` | `"lax"` | `AUTH_SESSION_COOKIE_SAMESITE` | SameSite policy |

### CSRF

| Field | Type | Default | Env Var | Description |
|-------|------|---------|---------|-------------|
| `csrf_enabled` | `bool` | `False` | `AUTH_CSRF_ENABLED` | Enable CSRF protection |
| `csrf_cookie_name` | `str` | `"csrf_token"` | `AUTH_CSRF_COOKIE_NAME` | CSRF cookie name |
| `csrf_header_name` | `str` | `"X-CSRF-Token"` | `AUTH_CSRF_HEADER_NAME` | CSRF header name |

### Multi-Tenant

| Field | Type | Default | Env Var | Description |
|-------|------|---------|---------|-------------|
| `tenant_enabled` | `bool` | `False` | `AUTH_TENANT_ENABLED` | Enable multi-tenant mode |
| `tenant_header` | `str` | `"X-Tenant-ID"` | `AUTH_TENANT_HEADER` | Tenant header name |
| `tenant_claim` | `str` | `"tenant_id"` | `AUTH_TENANT_CLAIM` | JWT claim for tenant ID |

### Multi-Tenant Hierarchy

| Field | Type | Default | Env Var | Description |
|-------|------|---------|---------|-------------|
| `tenant_hierarchy_enabled` | `bool` | `False` | `AUTH_TENANT_HIERARCHY_ENABLED` | Enable hierarchical tenants |
| `tenant_hierarchy_levels` | `list[str] \| None` | `None` | `AUTH_TENANT_HIERARCHY_LEVELS` | Ordered level names (e.g., `["organization", "department", "team"]`) |
| `tenant_path_claim` | `str` | `"tenant_path"` | `AUTH_TENANT_PATH_CLAIM` | JWT claim name for the hierarchy path |
| `tenant_default_level` | `str` | `"tenant"` | `AUTH_TENANT_DEFAULT_LEVEL` | Level name used when wrapping a flat `tenant_id` into a path |

### Router

| Field | Type | Default | Env Var | Description |
|-------|------|---------|---------|-------------|
| `auth_prefix` | `str` | `"/auth"` | `AUTH_AUTH_PREFIX` | URL prefix for auth endpoints |

## Usage

```python
from urauth import AuthConfig

# From code
config = AuthConfig(
    secret_key="my-secret",
    access_token_ttl=1800,
    csrf_enabled=True,
)

# From environment variables (just instantiate — Pydantic reads env vars)
config = AuthConfig()  # reads AUTH_* env vars
```
