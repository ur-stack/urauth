# AuthContext

`AuthContext` is the central object holding all auth data for the current user session. It provides introspection methods for checking permissions, roles, relations, and tenant membership.

## Construction

```typescript
import { AuthContext, Permission, Role, Relation, TenantPath, TenantNode } from "@urauth/ts";

const ctx = new AuthContext({
  user: { id: "1", name: "Alice" },
  roles: [new Role("editor")],
  permissions: [new Permission("post", "read"), new Permission("post", "write")],
  relations: [new Relation("doc", "owner").tuple("readme")],
  scopes: new Map([
    ["tenant-a", [new Permission("billing", "read")]],
  ]),
  tenant: new TenantPath([
    new TenantNode("acme", "organization"),
    new TenantNode("us-west", "region"),
  ]),
  token: decodedJwt,  // optional TokenPayload
  request: req,       // optional request object
});
```

### Anonymous Context

```typescript
const anonymous = AuthContext.anonymous();
anonymous.isAuthenticated(); // false
anonymous.user;              // null
```

## Permission Checks

All permission checks are **semantic** (separator-agnostic):

```typescript
// Exact match
ctx.hasPermission("post:read");   // true
ctx.hasPermission("post.read");   // true (same thing)
ctx.hasPermission("post:delete"); // false

// Wildcard in context
const admin = new AuthContext({
  user: { id: "1" },
  permissions: [new Permission("*")],
});
admin.hasPermission("anything:here"); // true

// Resource wildcard
const userAdmin = new AuthContext({
  user: { id: "1" },
  permissions: [new Permission("user", "*")],
});
userAdmin.hasPermission("user:read");   // true
userAdmin.hasPermission("user:delete"); // true
userAdmin.hasPermission("post:read");   // false
```

## Role Checks

```typescript
ctx.hasRole("editor");           // true
ctx.hasRole(new Role("editor")); // true
ctx.hasRole("admin");            // false

ctx.hasAnyRole("admin", "editor"); // true
ctx.hasAnyRole("admin", "viewer"); // false
```

## Relation Checks

```typescript
const docOwner = new Relation("doc", "owner");

ctx.hasRelation(docOwner, "readme");  // true (if in relations)
ctx.hasRelation(docOwner, "other");   // false
```

## Composite Requirements

```typescript
const canRead = new Permission("post", "read");
const canWrite = new Permission("post", "write");
const admin = new Role("admin");

ctx.satisfies(canRead);                    // true
ctx.satisfies(canRead.and(canWrite));      // true
ctx.satisfies(admin.or(canRead));          // true
ctx.satisfies(admin.and(canWrite));        // false (not admin)
```

## Tenant Methods

```typescript
// Leaf tenant ID (backward compat with flat tenant_id)
ctx.tenantId;  // "us-west"

// Check membership at any hierarchy level
ctx.inTenant("acme");     // true
ctx.inTenant("us-west");  // true
ctx.inTenant("other");    // false

// Get ID at a specific level
ctx.atLevel("organization"); // "acme"
ctx.atLevel("region");       // "us-west"
ctx.atLevel("team");         // undefined
```

## AuthContextOptions

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `user` | `unknown` | `null` | The authenticated user object |
| `roles` | `Role[]` | `[]` | User's roles |
| `permissions` | `Permission[]` | `[]` | Direct permissions |
| `relations` | `RelationTuple[]` | `[]` | Zanzibar relation tuples |
| `scopes` | `Map<string, Permission[]>` | `new Map()` | Scoped permissions (e.g., per-tenant) |
| `token` | `TokenPayload` | `undefined` | Decoded JWT claims |
| `request` | `unknown` | `undefined` | Original request object |
| `tenant` | `TenantPath` | `undefined` | Hierarchical tenant context |
| `authenticated` | `boolean` | `true` | Whether the user is authenticated |
