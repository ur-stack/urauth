# API Key Auth

Authenticate requests using API keys instead of (or alongside) JWT tokens.

## Auth Method Approach (Recommended)

Use `APIKey` as the auth method and override `get_user_by_api_key()` on your `Auth` subclass:

```python
from urauth import Auth, APIKey

class MyAuth(Auth):
    async def get_user_by_api_key(self, key: str):
        """Return a user for a valid key, or None."""
        return await db.get_user_by_api_key(key)

    async def get_user(self, user_id: str):
        return await db.get_user(user_id)

    # ... other overrides

core = MyAuth(
    method=APIKey(header_name="X-API-Key"),
    secret_key="your-secret",
)
```

Then wire it into FastAPI:

```python
from urauth.fastapi import FastAuth

auth = FastAuth(core)
router = auth.auto_router()
app.include_router(router)
```

The client sends the key in the `X-API-Key` header:

```bash
curl http://localhost:8000/api/data \
  -H "X-API-Key: sk-abc123..."
```

## Standalone APIKeyAuth

For cases where you want API key auth outside of the main auth configuration, use `APIKeyAuth` directly with a custom lookup function:

```python
from fastapi import Depends
from urauth.fastapi.authn.api_key import APIKeyAuth

async def lookup_api_key(key: str):
    """Return a user/entity for a valid key, or None."""
    return await db.get_user_by_api_key(key)

api_key_auth = APIKeyAuth(lookup_api_key)


@app.get("/api/data")
async def get_data(user=Depends(api_key_auth.dependency())):
    return {"user": user.id}
```

Your lookup function can be synchronous -- `APIKeyAuth` detects whether it is async and handles both:

```python
def lookup_api_key(key: str):
    return KEYS.get(key)

api_key_auth = APIKeyAuth(lookup_api_key)
```

## Custom Header Name

Change the header with `header_name` on either approach:

```python
# Auth method
Auth(method=APIKey(header_name="Authorization"), secret_key="...")

# Standalone
api_key_auth = APIKeyAuth(lookup_api_key, header_name="Authorization")
```

`APIKey` also supports a `query_param` option for extracting keys from query strings:

```python
Auth(method=APIKey(query_param="api_key"), secret_key="...")
```

## Fallback: JWT + API Key

Use `Fallback` to support both JWT and API key authentication:

```python
from urauth import Auth, Fallback, JWT, APIKey
from urauth.backends.memory import MemoryTokenStore

core = MyAuth(
    method=Fallback(methods=[
        JWT(ttl=900, store=MemoryTokenStore()),
        APIKey(header_name="X-API-Key"),
    ]),
    secret_key="your-secret",
)
```

## OpenAPI Integration

Add the API key scheme to your OpenAPI docs so the "Authorize" button in Swagger UI works with API keys:

```python
from urauth.fastapi.openapi import register_security_schemes

# Call after including all routers
register_security_schemes(app, api_key_header="X-API-Key")
```

This adds both `BearerAuth` (JWT) and `ApiKeyAuth` security schemes to the OpenAPI spec.
