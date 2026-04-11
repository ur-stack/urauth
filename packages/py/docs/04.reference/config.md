# Configuration

`AuthConfig` is an internal configuration class used by `TokenLifecycle` and other core components. It is based on pydantic-settings and reads environment variables with the `AUTH_` prefix (e.g., `AUTH_SECRET_KEY`, `AUTH_ALGORITHM`).

You do not need to create an `AuthConfig` directly. Configuration is done via flat parameters on `Auth()`:

```python
from urauth import Auth, JWT, Password

class MyAuth(Auth):
    async def get_user(self, user_id): ...
    async def get_user_by_username(self, username): ...
    async def verify_password(self, user, password): ...

core = MyAuth(
    method=JWT(ttl=900, store=my_store),
    secret_key="...",           # maps to AUTH_SECRET_KEY
    algorithm="HS256",          # maps to AUTH_ALGORITHM
    token_issuer="my-app",     # maps to AUTH_TOKEN_ISSUER
    token_audience="my-api",   # maps to AUTH_TOKEN_AUDIENCE
    namespace="project_a",    # multi-project separation
    tenant_enabled=True,       # maps to AUTH_TENANT_ENABLED
    password=Password(),
)
```

See [Configuration How-To](../how-to/configuration.md) for the full list of parameters and their environment variable equivalents.

## AuthConfig (Internal)


> **`urauth.config.AuthConfig`** -- See source code for full API.

## UserDataMixin


> **`urauth.users.UserDataMixin`** -- See source code for full API.

Base mixin for user data access hooks. Subclass `Auth` and override the methods you need, or pass callables directly to `Auth(get_user=..., ...)`. Both sync and async implementations are supported.

Three methods must be implemented: `get_user`, `get_user_by_username`, `verify_password`. All others (`get_user_roles`, `get_user_permissions`, `get_user_relations`, `check_relation`, identifier lookups, OAuth) have sensible defaults.
