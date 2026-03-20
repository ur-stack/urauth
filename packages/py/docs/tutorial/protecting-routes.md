# Protecting Routes

Now that you have authentication working, let's explore the different ways to protect your routes.

## Basic Protection

The simplest form — require an authenticated user:

```python
from fastapi import Depends

@app.get("/me")
async def me(user=Depends(auth.current_user())):
    return {"id": user.id}
```

If no valid token is provided, the endpoint returns `401 Unauthorized`.

## Optional Authentication

Sometimes you want to show different content for logged-in vs anonymous users:

```python
@app.get("/feed")
async def feed(user=Depends(auth.current_user(optional=True))):
    if user:
        return {"message": f"Welcome back, {user.username}!"}
    return {"message": "Welcome, guest!"}
```

When `optional=True`, the dependency returns `None` instead of raising `401`.

## Require Verified Users

```python
@app.get("/settings")
async def settings(user=Depends(auth.current_user(verified=True))):
    return {"email": user.email}
```

This checks that `user.is_verified` is `True`. Returns `403 Forbidden` otherwise.

## Fresh Tokens

Some actions (changing password, deleting account) should require a "fresh" login — not just a valid token, but one obtained from a recent password entry:

```python
@app.post("/change-password")
async def change_password(user=Depends(auth.current_user(fresh=True))):
    ...  # user recently entered their password
```

!!! info
    Tokens created by `POST /auth/login` are marked `fresh=True`. Tokens obtained via `POST /auth/refresh` are not fresh.

## Scope-Based Access

Scopes let you limit what a token can do:

```python
@app.get("/read-posts")
async def read_posts(user=Depends(auth.current_user(scopes=["posts:read"]))):
    ...

@app.post("/write-post")
async def write_post(user=Depends(auth.current_user(scopes=["posts:write"]))):
    ...
```

If the token doesn't include the required scopes, a `403 Forbidden` is returned.

## Role-Based Access

Require specific roles:

```python
@app.get("/admin/dashboard")
async def admin_dashboard(user=Depends(auth.current_user(roles=["admin"]))):
    ...

@app.get("/editor/drafts")
async def editor_drafts(user=Depends(auth.current_user(roles=["editor"]))):
    ...
```

!!! tip
    Roles are checked against the `roles` claim in the JWT. To enable role hierarchies (e.g., admin inherits editor), see [RBAC & Permissions](rbac-permissions.md).

## The `requires()` Shorthand

If you only need authorization checks (no user object), use `requires()`:

```python
@app.delete("/posts/{post_id}", dependencies=[Depends(auth.requires(roles=["admin"]))])
async def delete_post(post_id: str):
    ...  # user is guaranteed to be an admin
```

This is equivalent to `current_user(roles=["admin"])` but discards the user object.

## Error Responses

| Condition | Status | Detail |
|-----------|--------|--------|
| No token / invalid token | `401` | "Not authenticated" or "Invalid token" |
| Expired token | `401` | "Token has expired" |
| Revoked token | `401` | "Token has been revoked" |
| Inactive user | `401` | "User is not active" |
| Missing scope / role | `403` | "Forbidden" |
| Not verified | `403` | "Forbidden" |
| Not fresh | `401` | "Fresh token required" |

## Recap

- `current_user()` — require authenticated user
- `current_user(optional=True)` — return `None` for anonymous
- `current_user(verified=True)` — require verified user
- `current_user(fresh=True)` — require recently-entered password
- `current_user(scopes=[...])` — require specific token scopes
- `current_user(roles=[...])` — require specific roles
- `requires()` — authorization-only shorthand

**Next:** [Refresh Tokens →](refresh-tokens.md)
