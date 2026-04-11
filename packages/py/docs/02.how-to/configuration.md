# Configuration

Configuration is done via flat parameters on the `Auth` instance. Settings like `secret_key`, `algorithm`, `tenant_enabled`, etc. are passed directly. Internal details are managed by `AuthConfig` (a Pydantic Settings class that reads from environment variables with the `AUTH_` prefix), but you do not need to create an `AuthConfig` yourself.

## Production Required Settings

::: danger Set these before deploying
These settings are **required** for production deployments. urauth will raise `ValueError` at startup if key validation fails.

:::
```bash title=".env (production)"
AUTH_SECRET_KEY=<output of: openssl rand -hex 32>
AUTH_TOKEN_ISSUER=your-app-name
AUTH_TOKEN_AUDIENCE=your-app-audience
```

| Setting | Why |
|---------|-----|
| `AUTH_SECRET_KEY` | Must be 32+ bytes for HMAC. Default key raises `ValueError`. |
| `AUTH_TOKEN_ISSUER` | Prevents cross-app token confusion. |
| `AUTH_TOKEN_AUDIENCE` | Limits token acceptance to intended consumers. |

## Environment Variables

Every field can be set via environment variable with the `AUTH_` prefix:

```bash
export AUTH_SECRET_KEY="your-production-secret"
export AUTH_COOKIE_SECURE=true
```

Or use a `.env` file (Pydantic Settings loads it automatically):

```bash title=".env"
AUTH_SECRET_KEY=your-production-secret
AUTH_ALGORITHM=HS256
AUTH_COOKIE_SECURE=true
AUTH_CSRF_ENABLED=true
AUTH_TENANT_ENABLED=false
```

::: danger Default secret key
The default `secret_key` is `"CHANGE-ME-IN-PRODUCTION"`. **Never use this in production.** Always set `AUTH_SECRET_KEY` via environment variable.

:::
## Auth() Constructor Parameters

The primary way to configure urauth is through the `Auth()` constructor:

```python
from urauth import Auth, JWT, Password
from urauth.backends.memory import MemoryTokenStore

class MyAuth(Auth):
    async def get_user(self, user_id): ...
    async def get_user_by_username(self, username): ...
    async def verify_password(self, user, password): ...

core = MyAuth(
    method=JWT(                        # Auth method (required)
        ttl=900,                       # Access token TTL
        refresh_ttl=604800,            # Refresh token TTL
        refresh=True,                  # Enable refresh token rotation
        revocable=True,                # Check token blocklist
        store=MemoryTokenStore(),      # Token store
    ),
    secret_key="...",                  # JWT signing key
    algorithm="HS256",                 # JWT algorithm
    token_issuer="my-app",            # JWT iss claim
    token_audience="my-api",          # JWT aud claim
    password=Password(),               # Enable password login
    namespace="project_a",            # Multi-project auth separation
    tenant_enabled=False,              # Enable multi-tenant mode
)
```

## JWT Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `secret_key` | `str` | `"CHANGE-ME-IN-PRODUCTION"` | Signing key for JWTs |
| `algorithm` | `str` | `"HS256"` | JWT algorithm (HS256, RS256, ES256, etc.) |
| `token_issuer` | `str \| None` | `None` | JWT `iss` claim |
| `token_audience` | `str \| None` | `None` | JWT `aud` claim |

JWT method-specific settings are on `JWT(...)`:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ttl` | `int` | `900` | Access token lifetime in seconds (15 min) |
| `refresh_ttl` | `int` | `604800` | Refresh token lifetime in seconds (7 days) |
| `refresh` | `bool` | `True` | Enable refresh token rotation |
| `revocable` | `bool` | `True` | Check token blocklist on each request |
| `store` | `TokenStore` | Required | Token store for revocation tracking |

### Password

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `password_hash_scheme` | `str` | `"bcrypt"` | Password hashing scheme |

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

Session settings are configured on the `Session` auth method:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `cookie_name` | `str` | `"sid"` | Session cookie name |
| `ttl` | `int` | `86400` | Session lifetime in seconds (24 hours) |
| `store` | `SessionStore` | Required | Session data store |

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

### Namespace

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `namespace` | `str \| None` | `None` | Multi-project auth separation. Isolates token families and user contexts per project. |

### Router

| Field | Type | Default | Env Var | Description |
|-------|------|---------|---------|-------------|
| `auth_prefix` | `str` | `"/auth"` | `AUTH_AUTH_PREFIX` | URL prefix for auth endpoints |

## Usage

```python
from urauth import Auth, JWT, Password

class MyAuth(Auth):
    async def get_user(self, user_id): ...
    async def get_user_by_username(self, username): ...
    async def verify_password(self, user, password): ...

# From code -- flat params on the Auth subclass
core = MyAuth(
    method=JWT(ttl=1800, store=my_store),
    secret_key="my-secret",
    password=Password(),
)

# Environment variables are read automatically for AUTH_* settings
# (secret_key, algorithm, cookie settings, etc.)
```
