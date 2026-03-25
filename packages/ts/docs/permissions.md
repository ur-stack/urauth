# Permissions

## Permission Format

Permissions use a `resource:action` format. The separator is auto-detected from a set of allowed characters (`@ # . : | \ / $ &`), making `"user:read"` and `"user.read"` semantically equal.

### Construction

```typescript
import { Permission } from "@urauth/ts";

// Two-arg form
new Permission("user", "read");

// Single-string form (auto-detects separator)
new Permission("user:read");
new Permission("user.read");
new Permission("user|read");

// Global wildcard
new Permission("*");

// Custom parser for edge cases
new Permission("urn:service:task:read", undefined, {
  parser: (s) => {
    const parts = s.split(":");
    return [parts.at(-2)!, parts.at(-1)!];
  },
});
```

### Wildcards

| Pattern | Matches |
|---------|---------|
| `"*"` | Everything |
| `"user:*"` | All actions on `user` resource |
| `"user:read"` | Only `user:read` |

### Semantic Equality

Comparison ignores the separator character:

```typescript
const p1 = new Permission("user:read");
const p2 = new Permission("user.read");

p1.equals(p2);         // true
p1.equals("user.read"); // true
```

## matchPermission

Standalone utility for separator-agnostic matching with wildcard support:

```typescript
import { matchPermission } from "@urauth/ts";

matchPermission("user:read", "user.read");  // true (cross-separator)
matchPermission("user:*", "user:write");    // true (resource wildcard)
matchPermission("*", "anything:here");      // true (global wildcard)
matchPermission("user:read", "post:read");  // false
```

## definePermissions

Create a frozen map of named `Permission` instances for type-safe access:

```typescript
import { definePermissions } from "@urauth/ts";

const Perms = definePermissions({
  USER_READ: "user:read",           // string form
  USER_WRITE: ["user", "write"],    // tuple form
  ADMIN_ALL: new Permission("admin", "*"),  // Permission object
});

Perms.USER_READ;             // Permission instance
Perms.USER_READ.toString();  // "user:read"
Perms.USER_READ.resource;    // "user"
Perms.USER_READ.action;      // "read"
Object.isFrozen(Perms);      // true
```

### Custom Parser

For non-standard formats, pass a parser:

```typescript
const Perms = definePermissions(
  { TASK_READ: "urn:service:task:read" },
  {
    parser: (s) => {
      const parts = s.split(":");
      return [parts.at(-2)!, parts.at(-1)!];
    },
  },
);
Perms.TASK_READ.resource; // "task"
Perms.TASK_READ.action;   // "read"
```

## Composition

Permissions extend `Requirement` and support boolean composition:

```typescript
const canRead = new Permission("post", "read");
const canWrite = new Permission("post", "write");
const admin = new Role("admin");

// AND — all must be satisfied
const readAndWrite = canRead.and(canWrite);

// OR — any must be satisfied
const editorOrAdmin = canRead.and(canWrite).or(admin);

// Evaluate against context
ctx.satisfies(editorOrAdmin);
```

See also: [AuthContext](./context) for how permissions are checked.
