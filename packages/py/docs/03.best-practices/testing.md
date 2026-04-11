# Testing

## Use create_test_token() for Unit Tests

Do not hit the real login endpoint in unit tests. Create test tokens directly:

```python
from urauth.testing import create_test_token

def test_protected_endpoint(client):
    token = create_test_token(
        user_id="test-user",
        roles=["admin"],
        secret_key="test-secret",
    )
    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
```

## Use AuthOverride for Integration Tests

Override the auth context entirely to test authorization logic without token mechanics:

```python
from urauth.testing import AuthOverride

def test_admin_access(client, auth):
    with AuthOverride(auth, user_id="admin-1", roles=["admin"]):
        response = client.get("/admin/dashboard")
        assert response.status_code == 200

def test_viewer_denied(client, auth):
    with AuthOverride(auth, user_id="viewer-1", roles=["viewer"]):
        response = client.delete("/admin/users/1")
        assert response.status_code == 403
```

## Test Tenant Isolation

For multi-tenant applications, always verify that users cannot access data from other tenants:

```python
def test_tenant_isolation(client, auth):
    # User in tenant A
    token_a = create_test_token(
        user_id="user-1",
        tenant_id="tenant-a",
        secret_key="test-secret",
    )
    # User in tenant B
    token_b = create_test_token(
        user_id="user-2",
        tenant_id="tenant-b",
        secret_key="test-secret",
    )

    # Each user should only see their own tenant's data
    resp_a = client.get("/data", headers={"Authorization": f"Bearer {token_a}"})
    resp_b = client.get("/data", headers={"Authorization": f"Bearer {token_b}"})
    assert resp_a.json()["tenant"] ** "tenant-a"
    assert resp_b.json()["tenant"] ** "tenant-b"
```

## Test Permission Boundaries

Test both the happy path (authorized) and the sad path (forbidden) for every guarded endpoint:

```python
def test_editor_can_write(client, auth):
    with AuthOverride(auth, user_id="editor-1", roles=["editor"]):
        assert client.post("/tasks", json={"title": "New"}).status_code == 201

def test_viewer_cannot_write(client, auth):
    with AuthOverride(auth, user_id="viewer-1", roles=["viewer"]):
        assert client.post("/tasks", json={"title": "New"}).status_code == 403
```
