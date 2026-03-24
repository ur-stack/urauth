# Relations

Relation-based access control (ReBAC) answers the question: "Does user X have relation Y to resource Z?" This is the model behind Google Zanzibar and systems like SpiceDB and OpenFGA. urauth provides lightweight relation primitives that integrate with the same `AuthContext` and guard system used for roles and permissions.

## Concept

Traditional RBAC says "user is an admin." Relations say "user is the **owner** of **post 42**." This lets you model ownership, team membership, organization hierarchy, and other resource-specific access patterns.

```
user:alice  is  owner  of  post:42
user:bob    is  member of  team:engineering
user:carol  is  admin  of  org:acme
```

## Defining Relations

Create a `Relation` with a relation name and a resource type:

```python
from urauth.authz.primitives import Relation

owns_post = Relation("owner", "post")
member_of_team = Relation("member", "team")
admin_of_org = Relation("admin", "org")
```

A `Relation` has two parts:

- **name** -- the type of relationship (e.g., `"owner"`, `"member"`, `"admin"`)
- **resource** -- the resource type (e.g., `"post"`, `"team"`, `"org"`)

Its string form is `"resource#name"`: `Relation("owner", "post")` equals `"post#owner"`.

## Loading Relations: get_user_relations

Override `get_user_relations(user)` in your `Auth` subclass to return the user's relations. Each relation is a tuple of `(Relation, resource_id)`:

```python
from urauth.auth import Auth
from urauth.authz.primitives import Relation

class MyAuth(Auth):
    async def get_user_relations(self, user):
        # Query your database for the user's relations
        rows = await db.execute(
            "SELECT relation_name, resource_type, resource_id "
            "FROM user_relations WHERE user_id = :uid",
            {"uid": user.id},
        )
        return [
            (Relation(row.relation_name, row.resource_type), row.resource_id)
            for row in rows
        ]
```

For example, if Alice owns posts 42 and 99 and is a member of team "engineering":

```python
async def get_user_relations(self, user):
    return [
        (Relation("owner", "post"), "42"),
        (Relation("owner", "post"), "99"),
        (Relation("member", "team"), "engineering"),
    ]
```

These relations are loaded into the `AuthContext` when the context is built, alongside roles and permissions.

## Custom Relation Checking: check_relation

For cases where you do not want to pre-load all relations (e.g., the set is too large, or you need a database lookup per check), override `check_relation`:

```python
class MyAuth(Auth):
    async def check_relation(self, user, relation, resource_id):
        """Check if user has a specific relation to a resource."""
        exists = await db.execute(
            "SELECT 1 FROM user_relations "
            "WHERE user_id = :uid AND relation_name = :rel AND "
            "resource_type = :rtype AND resource_id = :rid",
            {
                "uid": user.id,
                "rel": relation.name,
                "rtype": str(relation.resource),
                "rid": resource_id,
            },
        )
        return exists is not None
```

The `check_relation` method is called by `RelationGuard` and provides a per-request check against a specific resource ID. The default implementation falls back to searching `get_user_relations()`.

## Guarding Endpoints with require_relation

Use `auth.require_relation()` to protect endpoints based on a relation. The `resource_id_from` parameter tells the guard which path parameter contains the resource ID:

```python
from fastapi import Depends, FastAPI
from starlette.requests import Request

from urauth.authz.primitives import Relation
from urauth.fastapi.auth import FastAuth

owns_post = Relation("owner", "post")

app = FastAPI()

@app.get("/posts/{post_id}")
@auth.require_relation(owns_post, resource_id_from="post_id")
async def get_post(request: Request, post_id: str):
    return {"post_id": post_id}

@app.put("/posts/{post_id}")
@auth.require_relation(owns_post, resource_id_from="post_id")
async def update_post(request: Request, post_id: str):
    return {"updated": post_id}
```

When a request comes in for `PUT /posts/42`:

1. The guard resolves the `AuthContext` from the request
2. It extracts `"42"` from the `post_id` path parameter
3. It calls `auth.check_relation(user, owns_post, "42")`
4. If the check returns `False`, a `403 Forbidden` is raised

The guard also works as a dependency:

```python
@app.put(
    "/posts/{post_id}",
    dependencies=[Depends(auth.require_relation(owns_post, resource_id_from="post_id"))],
)
async def update_post(post_id: str):
    return {"updated": post_id}
```

## AuthContext has_relation

For inline checks within an endpoint, use `ctx.has_relation()`:

```python
@app.get("/posts/{post_id}")
async def get_post(
    post_id: str,
    ctx=Depends(auth.context),
):
    if ctx.has_relation(Relation("owner", "post"), post_id):
        return {"post_id": post_id, "can_edit": True}
    return {"post_id": post_id, "can_edit": False}
```

`has_relation()` checks the pre-loaded relations in the context. It does not call `check_relation` -- it only searches the list returned by `get_user_relations()`.

## Combining Relations with Permissions

Relations are `Requirement` objects, just like `Permission` and `Role`. They support `&` (AND) and `|` (OR) composition:

```python
from urauth.authz.primitives import Permission, Role, Relation

is_admin = Role("admin")
owns_post = Relation("owner", "post")
can_write = Permission("post", "write")

# Admin OR the owner can delete
@app.delete("/posts/{post_id}")
@auth.require(is_admin | owns_post)
async def delete_post(request: Request, post_id: str):
    ...

# Must be an editor AND have write permission
@app.put("/posts/{post_id}")
@auth.require(can_write & Role("editor"))
async def update_post(request: Request, post_id: str):
    ...
```

!!! note
    When a `Relation` is used in a composite requirement via `auth.require()` (not `require_relation`), its `evaluate()` method checks if the relation exists for **any** resource ID in the context. For resource-specific checks, use `auth.require_relation()` with `resource_id_from`.

## Real-World Examples

### Document Ownership

```python
owns_document = Relation("owner", "document")
can_view_document = Relation("viewer", "document")

class MyAuth(Auth):
    async def get_user_relations(self, user):
        rows = await db.execute(
            "SELECT relation, document_id FROM document_access WHERE user_id = :uid",
            {"uid": user.id},
        )
        return [
            (Relation(row.relation, "document"), row.document_id)
            for row in rows
        ]

@app.get("/documents/{doc_id}")
@auth.require_relation(can_view_document, resource_id_from="doc_id")
async def get_document(request: Request, doc_id: str):
    ...

@app.delete("/documents/{doc_id}")
@auth.require_relation(owns_document, resource_id_from="doc_id")
async def delete_document(request: Request, doc_id: str):
    ...
```

### Team Membership

```python
member_of_team = Relation("member", "team")
admin_of_team = Relation("admin", "team")

@app.get("/teams/{team_id}/members")
@auth.require_relation(member_of_team, resource_id_from="team_id")
async def list_members(request: Request, team_id: str):
    ...

@app.post("/teams/{team_id}/invite")
@auth.require_relation(admin_of_team, resource_id_from="team_id")
async def invite_member(request: Request, team_id: str):
    ...
```

### Organization Hierarchy

Combine relations with roles for organization-level access:

```python
org_admin = Relation("admin", "org")
org_member = Relation("member", "org")
is_superadmin = Role("superadmin")

# Superadmins can access any org; org admins can access their own
@app.get("/orgs/{org_id}/settings")
@auth.require(is_superadmin | org_admin)
async def org_settings(request: Request, org_id: str):
    ...

# Any org member can view the dashboard
@app.get("/orgs/{org_id}/dashboard")
@auth.require_relation(org_member, resource_id_from="org_id")
async def org_dashboard(request: Request, org_id: str):
    ...
```

## Recap

- `Relation("name", "resource")` defines a typed relation between a user and a resource.
- Override `get_user_relations(user)` to return `[(Relation, resource_id), ...]` from your database.
- Override `check_relation(user, relation, resource_id)` for per-request database lookups instead of pre-loading.
- `auth.require_relation(relation, resource_id_from="param")` guards endpoints based on path parameter resource IDs.
- `ctx.has_relation(relation, resource_id)` checks pre-loaded relations inline.
- Relations compose with permissions and roles using `&` and `|`: `admin | owns_post`.
- Use relations for ownership, team membership, organization hierarchy, and other resource-specific access patterns.

**Next:** [Multi-Tenant](multi-tenant.md)
