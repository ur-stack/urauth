# API Key Auth

Authenticate requests using API keys instead of (or alongside) JWT tokens.

## Basic Setup

```python
from fastapi import Depends
from fastapi_auth.authn.api_key import APIKeyAuth

# Define your key lookup — sync or async
async def lookup_api_key(key: str):
    """Return a user/entity for a valid key, or None."""
    return await db.get_user_by_api_key(key)

api_key_auth = APIKeyAuth(lookup_api_key)


@app.get("/api/data")
async def get_data(user=Depends(api_key_auth.dependency())):
    return {"user": user.id}
```

The client sends the key in the `X-API-Key` header:

```bash
curl http://localhost:8000/api/data \
  -H "X-API-Key: sk-abc123..."
```

## Custom Header Name

```python
api_key_auth = APIKeyAuth(lookup_api_key, header_name="Authorization")
```

## Sync Lookup

Your lookup function can be synchronous:

```python
def lookup_api_key(key: str):
    return KEYS.get(key)

api_key_auth = APIKeyAuth(lookup_api_key)
```

`APIKeyAuth` detects whether your function is async and handles both.

## OpenAPI Integration

Add the API key scheme to your OpenAPI docs:

```python
from fastapi_auth.openapi import register_security_schemes

# Call after including all routers
register_security_schemes(app, api_key_header="X-API-Key")
```

This adds both `BearerAuth` (JWT) and `ApiKeyAuth` security schemes to the OpenAPI spec, making the "Authorize" button in Swagger UI work with API keys.
