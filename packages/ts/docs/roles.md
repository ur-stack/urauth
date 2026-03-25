# Roles

## RoleRegistry

Define roles with permissions and inheritance hierarchy:

```typescript
import { RoleRegistry } from "@urauth/ts";

const registry = new RoleRegistry();

// Simple roles
registry.role("viewer", ["post:read"]);
registry.role("editor", ["post:read", "post:write"]);

// Role with inheritance
registry.role("admin", ["user:*", "post:*"], { inherits: ["editor"] });
```

### Merging Registries

Combine multiple registries (e.g., from different modules):

```typescript
const coreRoles = new RoleRegistry();
coreRoles.role("viewer", ["post:read"]);

const adminRoles = new RoleRegistry();
adminRoles.role("admin", ["user:*"]);

coreRoles.include(adminRoles);
```

## RoleExpandingChecker

Build a checker that expands role hierarchies and checks permissions:

```typescript
const checker = registry.buildChecker();

// See all effective roles (including inherited)
checker.effectiveRoles(["admin"]);
// Set { "admin", "editor" }

// Check permissions (async)
await checker.hasPermission(ctx, "post", "read");  // true
await checker.hasPermission(ctx, "user", "write");  // depends on roles
```

You can also construct a checker directly:

```typescript
import { RoleExpandingChecker } from "@urauth/ts";

const checker = new RoleExpandingChecker({
  rolePermissions: new Map([
    ["admin", new Set(["user:*", "post:*"])],
    ["editor", new Set(["post:read", "post:write"])],
  ]),
  hierarchy: new Map([
    ["admin", ["editor"]],
  ]),
});
```

## Dynamic Role Loading

Load roles from a database at runtime:

```typescript
registry.withLoader(
  {
    async loadRoles() {
      // Return Map<roleName, Set<permissionStrings>>
      const roles = await db.roles.findAll();
      return new Map(roles.map(r => [r.name, new Set(r.permissions)]));
    },
    async loadHierarchy() {
      // Return Map<parentRole, childRoles[]>
      return new Map([["admin", ["editor", "viewer"]]]);
    },
  },
  { cache: new MemoryRoleCache(), cacheTtl: 300 },
);

// Initial load
await registry.load();

// Reload after changes
await registry.reload();
```

## StringChecker

A simpler checker that matches `resource:action` strings against context permissions without role expansion:

```typescript
import { StringChecker } from "@urauth/ts";

const checker = new StringChecker();
await checker.hasPermission(ctx, "post", "read");
```

Matching is semantic (separator-agnostic) and supports wildcards.
