# Testing

fastapi-auth provides test utilities to simplify authentication in your test suite.

## `create_test_token()`

Generate a token pair without setting up a full auth system:

```python
from fastapi_auth.testing import create_test_token

pair = create_test_token(
    user_id="user-1",
    secret_key="test-secret",   # default
    roles=["admin"],
    scopes=["posts:read"],
    fresh=True,
    access_ttl=3600,            # 1 hour (default)
)

# Use the access token in requests
headers = {"Authorization": f"Bearer {pair.access_token}"}
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `user_id` | `str` | `"test-user"` | Subject claim |
| `secret_key` | `str` | `"test-secret"` | Signing key |
| `algorithm` | `str` | `"HS256"` | JWT algorithm |
| `scopes` | `list[str] \| None` | `None` | Token scopes |
| `roles` | `list[str] \| None` | `None` | Token roles |
| `tenant_id` | `str \| None` | `None` | Tenant claim |
| `fresh` | `bool` | `False` | Fresh token flag |
| `extra_claims` | `dict \| None` | `None` | Additional JWT claims |
| `access_ttl` | `int` | `3600` | Access token lifetime |
| `refresh_ttl` | `int` | `86400` | Refresh token lifetime |

## `AuthOverride`

Override `auth.current_user()` in your tests without real tokens:

```python
from fastapi_auth.testing import AuthOverride

override = AuthOverride(auth, app)

with override.as_user(user, roles=["admin"]):
    # All current_user() calls return this user
    response = client.get("/admin")
    assert response.status_code == 200
```

If you don't have a user object, `AuthOverride` creates a mock:

```python
with override.as_user(user_id="test-123", roles=["editor"], scopes=["posts:read"]):
    response = client.get("/editor/drafts")
```

## Full Pytest Example

### `conftest.py`

```python
import pytest
from fastapi.testclient import TestClient

from app import app, auth
from fastapi_auth.testing import AuthOverride


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def auth_override():
    return AuthOverride(auth, app)
```

### `test_routes.py`

```python
def test_public_route(client):
    response = client.get("/health")
    assert response.status_code == 200


def test_protected_route_unauthenticated(client):
    response = client.get("/me")
    assert response.status_code == 401


def test_protected_route_authenticated(client, auth_override):
    with auth_override.as_user(user_id="alice", roles=["viewer"]):
        response = client.get("/me")
        assert response.status_code == 200
        assert response.json()["id"] == "alice"


def test_admin_route_forbidden(client, auth_override):
    with auth_override.as_user(roles=["viewer"]):
        response = client.get("/admin")
        assert response.status_code == 403


def test_admin_route_allowed(client, auth_override):
    with auth_override.as_user(roles=["admin"]):
        response = client.get("/admin")
        assert response.status_code == 200
```

## Async Tests with httpx

```python
import pytest
from httpx import ASGITransport, AsyncClient

from app import app, auth
from fastapi_auth.testing import AuthOverride


@pytest.fixture
def auth_override():
    return AuthOverride(auth, app)


@pytest.mark.asyncio
async def test_async_protected(auth_override):
    with auth_override.as_user(user_id="bob", roles=["admin"]):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.get("/admin")
            assert response.status_code == 200
```
