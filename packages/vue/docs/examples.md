# Examples

## Setup

Provide auth context in a root or layout component. All child components can then use the composables.

```vue
<script setup lang="ts">
import { provideAccess } from "@urauth/vue";
import { AuthContext, Permission, Role } from "@urauth/ts";

// Build context from your auth data (JWT payload, API response, etc.)
const ctx = new AuthContext({
  user: currentUser,
  roles: [new Role("editor")],
  permissions: [
    new Permission("post", "read"),
    new Permission("post", "write"),
    new Permission("comment", "*"),
  ],
});

provideAccess({ ctx });
</script>
```

You can also pass a custom `PermissionChecker` for advanced scenarios:

```typescript
import { canAccess, type PermissionChecker } from "@urauth/ts";

const checker: PermissionChecker = (subject, resource, action) => {
  // Custom logic — check external service, feature flags, etc.
  return subject.permissions.includes(`${resource}:${action}`);
};

provideAccess({ ctx, checker });
```

## useAccess

General-purpose permission check. Returns an object with a `can()` function.

```vue
<script setup lang="ts">
import { useAccess } from "@urauth/vue";

const { can } = useAccess();
</script>

<template>
  <button v-if="can('post', 'write')">New Post</button>
  <button v-if="can('post', 'delete')">Delete</button>
</template>
```

### Scoped permissions

```typescript
const { can } = useAccess();

// Check within a specific scope
can("post", "write", { scope: "team-alpha" });
```

## usePermission

Returns a reactive `ComputedRef<boolean>` for a specific resource/action pair. Ideal for template bindings.

```vue
<script setup lang="ts">
import { usePermission } from "@urauth/vue";

const canWrite = usePermission("post", "write");
const canDelete = usePermission("post", "delete");
const canManageUsers = usePermission("user", "*");
</script>

<template>
  <div>
    <button v-if="canWrite">Edit</button>
    <button v-if="canDelete" class="danger">Delete</button>
    <UserManager v-if="canManageUsers" />
  </div>
</template>
```

## useRole

Reactive check for a single role.

```vue
<script setup lang="ts">
import { useRole } from "@urauth/vue";

const isAdmin = useRole("admin");
const isEditor = useRole("editor");
</script>

<template>
  <AdminPanel v-if="isAdmin" />
  <EditorToolbar v-if="isEditor" />
</template>
```

## useAnyRole

Reactive check for whether the user holds *any* of the given roles.

```vue
<script setup lang="ts">
import { useAnyRole } from "@urauth/vue";

const canModerate = useAnyRole("admin", "moderator");
</script>

<template>
  <ModerationQueue v-if="canModerate" />
</template>
```

## useAuthState

Reactive auth introspection. Exposes computed refs for auth status, user, roles, permissions, and tenant.

```vue
<script setup lang="ts">
import { useAuthState } from "@urauth/vue";

const { isAuthenticated, user, roles, permissions, tenantId } = useAuthState();
</script>

<template>
  <div v-if="isAuthenticated">
    <p>User: {{ user.name }}</p>
    <p>Roles: {{ roles.join(", ") }}</p>
    <p>Tenant: {{ tenantId }}</p>
  </div>
  <LoginButton v-else />
</template>
```

## useRequirement

Evaluate composite requirements (AllOf / AnyOf) reactively.

```vue
<script setup lang="ts">
import { useRequirement } from "@urauth/vue";
import { Permission, Role, allOf, anyOf } from "@urauth/ts";

// Must be editor AND have post:write permission
const canEditPosts = useRequirement(
  allOf(new Role("editor"), new Permission("post", "write"))
);

// Either admin OR (editor with post:delete)
const canDeletePosts = useRequirement(
  anyOf(
    new Role("admin"),
    allOf(new Role("editor"), new Permission("post", "delete"))
  )
);
</script>

<template>
  <PostEditor v-if="canEditPosts" />
  <DeleteButton v-if="canDeletePosts" />
</template>
```

## useTenant

Reactive tenant context for multi-tenant applications.

```vue
<script setup lang="ts">
import { useTenant } from "@urauth/vue";

const { tenantId, inTenant, atLevel } = useTenant();
const orgId = atLevel("organization");
</script>

<template>
  <div>
    <p>Current tenant: {{ tenantId }}</p>
    <OrgSettings v-if="inTenant('org-acme')" />
  </div>
</template>
```

## Full Application Example

```vue
<!-- App.vue -->
<script setup lang="ts">
import { ref, watch } from "vue";
import { provideAccess } from "@urauth/vue";
import { AuthContext, Permission, Role, RoleRegistry } from "@urauth/ts";

const registry = new RoleRegistry();
registry.role("viewer", ["post:read"]);
registry.role("editor", ["post:read", "post:write"], { inherits: ["viewer"] });
registry.role("admin", ["*"], { inherits: ["editor"] });

// Simulate fetching user from API
const userContext = ref<AuthContext | null>(null);

async function onLogin(token: string) {
  const payload = parseJwt(token); // Your JWT decoder
  const ctx = new AuthContext({
    user: payload.user,
    roles: payload.roles.map((r: string) => new Role(r)),
    permissions: payload.permissions.map((p: string) => {
      const [resource, action] = p.split(":");
      return new Permission(resource, action);
    }),
  });
  userContext.value = ctx;
  provideAccess({ ctx });
}
</script>
```
