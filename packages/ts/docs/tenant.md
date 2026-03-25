# Multi-Tenant

Support for flat and hierarchical multi-tenancy through JWT claims and runtime context.

## TenantPath

Ordered path from root to leaf in the tenant hierarchy. Replaces the flat `tenant_id` string with full hierarchy context.

### Construction

```typescript
import { TenantPath, TenantNode } from "@urauth/ts";

const path = new TenantPath([
  new TenantNode("acme", "organization"),
  new TenantNode("us-west", "region"),
  new TenantNode("alpha", "team"),
]);
```

### Properties

```typescript
path.leafId;     // "alpha" (most specific)
path.leafLevel;  // "team"
path.length;     // 3
```

### Lookup

```typescript
path.idAt("organization"); // "acme"
path.idAt("region");       // "us-west"
path.idAt("unknown");      // undefined
```

### Hierarchy Checks

```typescript
// Is any segment this ID?
path.isDescendantOf("acme");    // true
path.isDescendantOf("alpha");   // true
path.isDescendantOf("other");   // false

// Ancestor relationship
const ancestor = new TenantPath([new TenantNode("acme", "organization")]);
ancestor.contains(path);  // true (ancestor contains descendant)
path.contains(ancestor);  // false
```

### JWT Serialization

```typescript
// To JWT claim
path.toClaim();
// { organization: "acme", region: "us-west", team: "alpha" }

// From JWT claim
const restored = TenantPath.fromClaim({
  organization: "acme",
  region: "us-west",
});

// Backward compat: wrap flat tenant_id
const flat = TenantPath.fromFlat("tenant-123");
flat.leafId;    // "tenant-123"
flat.leafLevel; // "tenant" (default level name)
```

## TenantHierarchy

Schema definition for the tenant hierarchy, configured at startup:

```typescript
import { TenantHierarchy, TenantLevel } from "@urauth/ts";

// From strings (auto-numbered by depth)
const hierarchy = new TenantHierarchy(["organization", "region", "team"]);

// Or from explicit levels
const hierarchy2 = new TenantHierarchy([
  new TenantLevel("organization", 0),
  new TenantLevel("region", 1),
  new TenantLevel("team", 2),
]);
```

### Navigation

```typescript
hierarchy.root;    // TenantLevel { name: "organization", depth: 0 }
hierarchy.leaf;    // TenantLevel { name: "team", depth: 2 }
hierarchy.length;  // 3

hierarchy.depthOf("region");        // 1
hierarchy.parentOf("region");       // "organization"
hierarchy.parentOf("organization"); // undefined
hierarchy.childrenOf("organization"); // ["region"]
hierarchy.childrenOf("team");         // []

hierarchy.has("region");  // true
hierarchy.get("region");  // TenantLevel { name: "region", depth: 1 }
```

## TenantDefaults

Registry for provisioning default roles when a new tenant is created:

```typescript
import { TenantDefaults, RoleTemplate } from "@urauth/ts";

const defaults = new TenantDefaults();

defaults.register("organization", [
  new RoleTemplate("org_admin", ["org:*"], "Full organization access"),
  new RoleTemplate("org_member", ["org:read"], "Read-only member"),
]);

defaults.register("team", [
  new RoleTemplate("team_lead", ["team:*"]),
  new RoleTemplate("team_member", ["team:read", "team:write"]),
]);

// Get templates for a level
defaults.templatesFor("organization");
// [RoleTemplate { name: "org_admin", ... }, RoleTemplate { name: "org_member", ... }]

defaults.levels; // ["organization", "team"]

// Provision roles via your custom provisioner
await defaults.provision("org-123", "organization", myProvisioner);
```

## Store Interfaces

Implement these to back tenant hierarchy with your database:

```typescript
import type { TenantStore, TenantRoleProvisioner } from "@urauth/ts";

// Tenant hierarchy persistence
const store: TenantStore = {
  async getTenant(tenantId) { /* ... */ },
  async getAncestors(tenantId) { /* ... */ },
  async getChildren(tenantId) { /* ... */ },
  async resolvePath(tenantId) { /* ... */ },
};

// Role provisioning when creating tenants
const provisioner: TenantRoleProvisioner = {
  async provision(tenantId, level, templates) {
    for (const tmpl of templates) {
      await db.roles.create({
        tenantId,
        name: tmpl.name,
        permissions: tmpl.permissions,
      });
    }
  },
};
```
