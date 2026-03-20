# RBAC & Permissions

Role-Based Access Control (RBAC) lets you define a role hierarchy and fine-grained permissions.

## Role Hierarchy

Define which roles inherit from which:

```python
auth.set_rbac({
    "admin": ["editor", "viewer"],  # (1)!
    "editor": ["viewer"],           # (2)!
})
```

1. Admin inherits all of editor's and viewer's roles.
2. Editor inherits viewer's role.

The hierarchy is **transitively expanded** — if admin inherits editor and editor inherits viewer, then admin also has the viewer role.

## Role Checks

```python
@app.get("/admin")
async def admin_only(user=Depends(auth.current_user(roles=["admin"]))):
    return {"role": "admin"}

@app.get("/editor")
async def editor_area(user=Depends(auth.current_user(roles=["editor"]))):
    return {"role": "editor or above"}
```

With the hierarchy above, an admin can access both endpoints. An editor can access `/editor` but not `/admin`.

!!! tip
    Role checks use the user's JWT `roles` claim. Make sure your backend includes roles when creating tokens. The `password_auth_router()` reads roles from users that implement the `UserWithRoles` protocol.

## Permissions

For finer-grained control, map roles to permissions:

```python
auth.set_permissions({
    "admin": {"*"},                          # (1)!
    "editor": {"posts:read", "posts:write"},
    "viewer": {"posts:read"},
})
```

1. The wildcard `*` grants all permissions.

Then require specific permissions on your routes:

```python
@app.get("/posts")
async def list_posts(user=Depends(auth.current_user(permissions=["posts:read"]))):
    ...

@app.post("/posts")
async def create_post(user=Depends(auth.current_user(permissions=["posts:write"]))):
    ...

@app.delete("/system/cache")
async def clear_cache(user=Depends(auth.current_user(permissions=["system:admin"]))):
    ...  # only admin (via wildcard) can access this
```

## Combining Roles and Permissions

You can use both in the same dependency:

```python
@app.put("/posts/{id}")
async def edit_post(
    id: str,
    user=Depends(auth.current_user(roles=["editor"], permissions=["posts:write"])),
):
    ...
```

Both checks must pass — the user needs the `editor` role (or higher) **and** the `posts:write` permission.

## How Permission Resolution Works

1. The user's JWT contains a `roles` claim (e.g., `["editor"]`)
2. `RBACManager.effective_roles()` expands the roles using the hierarchy (e.g., `{"editor", "viewer"}`)
3. `PermissionManager.permissions_for_roles()` collects all permissions for those roles
4. The required permission is checked against the collected set
5. A wildcard `*` in any role's permissions matches everything

## Recap

- `auth.set_rbac(hierarchy)` defines role inheritance with transitive expansion.
- `current_user(roles=[...])` checks against the expanded role set.
- `auth.set_permissions(mapping)` maps roles to fine-grained permissions.
- `current_user(permissions=[...])` checks against the collected permission set.
- The wildcard `*` grants all permissions.

**Next:** [Multi-Tenant →](multi-tenant.md)
