# Core Concepts

## Permissions {#permissions}

Permissions use a `resource:action` format. The separator is auto-detected and interchangeable — `"user:read"`, `"user.read"`, and `"user|read"` are all semantically equal.

### Wildcards

- `"*"` — grants all permissions
- `"user:*"` — grants all actions on the `user` resource
- `"user:read"` — grants a specific action

### Composition

Permissions (and all requirements) support boolean composition:

::: code-group

```python [Python]
from urauth import Permission, Role

can_read = Permission("post", "read")
can_write = Permission("post", "write")
admin = Role("admin")

# Composite requirements
requirement = (can_read & can_write) | admin
ctx.satisfies(requirement)  # True if user can read AND write, OR is admin
```

```typescript [TypeScript]
import { Permission, Role } from "@urauth/ts";

const canRead = new Permission("post", "read");
const canWrite = new Permission("post", "write");
const admin = new Role("admin");

const requirement = canRead.and(canWrite).or(admin);
ctx.satisfies(requirement); // true if user can read AND write, OR is admin
```

:::

### definePermissions / PermissionEnum

Define all permissions in one place for type safety:

::: code-group

```python [Python]
from urauth import PermissionEnum

class Perms(PermissionEnum):
    USER_READ = "user:read"
    USER_WRITE = "user:write"
    ADMIN_ALL = ("admin", "*")
```

```typescript [TypeScript]
import { definePermissions } from "@urauth/ts";

const Perms = definePermissions({
  USER_READ: "user:read",
  USER_WRITE: "user:write",
  ADMIN_ALL: ["admin", "*"],
});
```

:::

## Roles {#roles}

Roles are named collections of permissions with optional hierarchy (inheritance).

```typescript
import { RoleRegistry } from "@urauth/ts";

const registry = new RoleRegistry();
registry.role("viewer", ["post:read"]);
registry.role("editor", ["post:read", "post:write"], { inherits: ["viewer"] });
registry.role("admin", ["user:*", "post:*"], { inherits: ["editor"] });

const checker = registry.buildChecker();
// admin inherits editor's permissions, which inherits viewer's
checker.effectiveRoles(["admin"]); // Set { "admin", "editor", "viewer" }
```

## Relations {#relations}

urauth supports [Google Zanzibar](https://research.google/pubs/pub48190/)-style relation tuples for fine-grained, object-level authorization.

A relation is defined as `resource#relation_name`, and tuples bind a relation to a specific object and subject:

::: code-group

```python [Python]
from urauth import Relation, RelationTuple

doc_owner = Relation("doc", "owner")

# Create a tuple: "user:alice is the owner of doc:readme"
tuple = doc_owner.tuple("readme", "user:alice")

# Check in context
ctx.has_relation(doc_owner, "readme")  # True if user owns doc "readme"
```

```typescript [TypeScript]
import { Relation, RelationTuple, defineRelations } from "@urauth/ts";

const Rels = defineRelations({
  DOC_OWNER: "doc#owner",
  DOC_VIEWER: ["doc", "viewer"],
});

const tuple = Rels.DOC_OWNER.tuple("readme", "user:alice");
// Or parse from string:
const parsed = RelationTuple.parse("doc:readme#owner@user:alice");

ctx.hasRelation(Rels.DOC_OWNER, "readme");
```

:::

## Multi-Tenancy {#multi-tenancy}

### Flat Tenancy

The simplest model — a single `tenant_id` in the JWT:

```typescript
const ctx = new AuthContext({
  user: { id: "1" },
  token: { /* ... */ tenant_id: "acme" },
});
ctx.tenantId; // "acme"
```

### Hierarchical Tenancy

For complex organizations, use `TenantPath` to carry full hierarchy context:

```
organization: "acme"  →  region: "us-west"  →  team: "alpha"
```

::: code-group

```python [Python]
from urauth import TenantPath, TenantNode, TenantHierarchy

hierarchy = TenantHierarchy(["organization", "region", "team"])

path = TenantPath([
    TenantNode("acme", "organization"),
    TenantNode("us-west", "region"),
    TenantNode("alpha", "team"),
])

path.leaf_id              # "alpha"
path.id_at("organization") # "acme"
path.is_descendant_of("acme")  # True
path.to_claim()  # {"organization": "acme", "region": "us-west", "team": "alpha"}
```

```typescript [TypeScript]
import { TenantPath, TenantNode, TenantHierarchy } from "@urauth/ts";

const hierarchy = new TenantHierarchy(["organization", "region", "team"]);

const path = new TenantPath([
  new TenantNode("acme", "organization"),
  new TenantNode("us-west", "region"),
  new TenantNode("alpha", "team"),
]);

path.leafId;              // "alpha"
path.idAt("organization"); // "acme"
path.isDescendantOf("acme");  // true
path.toClaim(); // { organization: "acme", region: "us-west", team: "alpha" }
```

:::

The `TenantPath` is embedded in the JWT as `tenant_path` and automatically deserialized into `AuthContext`:

```typescript
const ctx = new AuthContext({
  user: { id: "1" },
  tenant: TenantPath.fromClaim({
    organization: "acme",
    region: "us-west",
  }),
});

ctx.tenantId;              // "us-west" (leaf)
ctx.inTenant("acme");      // true (any level)
ctx.atLevel("organization"); // "acme"
```

## AuthContext {#auth-context}

`AuthContext` is the central object that holds all auth data for the current request. It's built from a JWT or user object and provides introspection methods:

| Method | Description |
|--------|-------------|
| `isAuthenticated()` | User is non-null and authenticated |
| `hasPermission(perm)` | Semantic, separator-agnostic permission check |
| `hasRole(role)` | Check for a specific role |
| `hasAnyRole(...roles)` | Check for any of the given roles |
| `hasRelation(rel, id)` | Check a Zanzibar relation to a resource |
| `satisfies(req)` | Evaluate a composite requirement |
| `tenantId` | Leaf tenant ID (backward compat) |
| `inTenant(id)` | Check if in a specific tenant at any level |
| `atLevel(level)` | Get tenant ID at a hierarchy level |
