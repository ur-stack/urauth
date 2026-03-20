# Refresh Tokens

Access tokens are short-lived (15 minutes by default). Refresh tokens let users get new access tokens without logging in again.

## How It Works

When a user logs in, they receive a **token pair**:

- **Access token** — short-lived, used for API requests
- **Refresh token** — long-lived (7 days by default), used only to get a new access token

```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "bearer"
}
```

## Configuring TTLs

```python
from fastapi_auth import AuthConfig

config = AuthConfig(
    secret_key="your-secret",
    access_token_ttl=900,     # 15 minutes (default)
    refresh_token_ttl=604800, # 7 days (default)
)
```

## Refreshing Tokens

Call `POST /auth/refresh` with the refresh token:

```bash
curl -X POST http://localhost:8000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "eyJ..."}'
```

You get a new token pair:

```json
{
  "access_token": "eyJ...(new)",
  "refresh_token": "eyJ...(new)",
  "token_type": "bearer"
}
```

!!! info
    The new access token is **not** fresh. Only tokens from `POST /auth/login` are fresh.

## Token Rotation

By default, `rotate_refresh_tokens` is `True`. Every time a refresh token is used, the old one is revoked and a new one is issued. This limits the window of exposure if a refresh token is leaked.

```python
config = AuthConfig(
    secret_key="your-secret",
    rotate_refresh_tokens=True,  # default
)
```

## Reuse Detection

!!! danger "Replay attack protection"
    If a revoked refresh token is used again, fastapi-auth revokes **all tokens in that family** — logging the user out of every session. This protects against token theft.

Refresh tokens belong to a **family** (tracked by `family_id`). When rotation creates a new token, it inherits the family. If someone replays an old (revoked) refresh token, the entire family is invalidated.

This requires a `TokenStore`. The built-in `MemoryTokenStore` is used by default, but you should use a persistent store in production (see [Custom Backends](../how-to/custom-backends.md)).

## Logout

Revoke the current token:

```bash
curl -X POST http://localhost:8000/auth/logout \
  -H "Authorization: Bearer eyJ..."
```

Returns `204 No Content`.

## Logout All Sessions

Revoke all tokens for the user:

```bash
curl -X POST http://localhost:8000/auth/logout-all \
  -H "Authorization: Bearer eyJ..."
```

This calls `token_store.revoke_all_for_user()`, invalidating every access and refresh token the user has.

## Token Store

The `TokenStore` protocol tracks issued and revoked tokens. The default `MemoryTokenStore` works for development but doesn't persist across restarts.

```python
from fastapi_auth import FastAPIAuth, AuthConfig

# Default: MemoryTokenStore (fine for development)
auth = FastAPIAuth(MyBackend(), config)

# Production: pass your own store
auth = FastAPIAuth(MyBackend(), config, token_store=my_redis_store)
```

See [Custom Backends](../how-to/custom-backends.md) for implementing a Redis-backed token store.

## Recap

- Login returns an access + refresh token pair.
- `POST /auth/refresh` exchanges a refresh token for a new pair.
- Token rotation (on by default) revokes old refresh tokens on use.
- Reuse detection invalidates the entire token family if a revoked token is replayed.
- `POST /auth/logout` revokes the current token; `POST /auth/logout-all` revokes all user tokens.
- Use a persistent `TokenStore` in production.

**Next:** [OAuth2 & Social Login →](oauth2-social-login.md)
