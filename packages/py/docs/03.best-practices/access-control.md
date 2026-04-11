# Access Control

## Follow the Principle of Least Privilege

Start with minimal permissions and add more as needed. Use wildcards sparingly -- only for true super-admin roles:

```python
# Good -- explicit permissions
registry.role("editor", permissions=["task:read", "task:write", "comment:read", "comment:write"])

# Use wildcards only for admin
registry.role("admin", permissions=["*"])
```

## Use Scoped Permissions for Resource-Level Access

When users need different access levels in different contexts (e.g., admin in one team, viewer in another), use scoped permissions via `scope_from`:

```python
@access.guard("task", "write", scope_from="team_id")
async def update_task(team_id: str, request: Request):
    ...
```

## Compose Requirements for Complex Rules

Use `&` (AND) and `|` (OR) to build complex authorization rules from simple primitives:

```python
from urauth import Permission, Role, Relation

# Must be a member AND have write permission
member_writer = Role("member") & Permission("task", "write")

# Owner OR admin can delete
can_delete = Relation("task", "owner") | Role("admin")

@auth.require(member_writer)
async def update_task(ctx: AuthContext = Depends(auth.context)):
    ...
```

## Load Roles from the Database in Production

For dynamic role management (admin UI for creating roles), use `RoleRegistry.with_loader()`:

```python
async def load_roles():
    rows = await db.execute("SELECT name, permissions FROM roles")
    return [{"name": r.name, "permissions": r.permissions.split(",")} for r in rows]

registry = RoleRegistry()
registry.with_loader(load_roles, cache_ttl=300)  # Cache for 5 minutes
```
