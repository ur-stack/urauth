# @urauth/vue

Vue 3 composables for urAuth access control. Provides VueUse-inspired reactive composables for permission checking, role management, and auth state introspection.

## Installation

```bash
pnpm add @urauth/vue
```

## Peer Dependencies

- `vue` >= 3.0.0
- `@urauth/ts`

## What's Included

| Composable | Description |
|------------|-------------|
| [`provideAccess`](./examples#setup) | Provide auth context to descendant components |
| [`useAccess`](./examples#useaccess) | General-purpose `can()` permission check |
| [`usePermission`](./examples#usepermission) | Reactive `ComputedRef<boolean>` for a specific permission |
| [`useRole`](./examples#userole) | Reactive role check |
| [`useAnyRole`](./examples#useanyrole) | Reactive check for any of the given roles |
| [`useAuthState`](./examples#useauthstate) | Reactive auth status, user, roles, permissions |
| [`useRequirement`](./examples#userequirement) | Reactive composite requirement evaluation |
| [`useTenant`](./examples#usetenant) | Reactive tenant context |

## Quick Start

```vue
<!-- App.vue -->
<script setup lang="ts">
import { provideAccess } from "@urauth/vue";
import { AuthContext, Permission, Role } from "@urauth/ts";

const ctx = new AuthContext({
  user: { id: "1", name: "Alice" },
  roles: [new Role("editor")],
  permissions: [new Permission("post", "read"), new Permission("post", "write")],
});

provideAccess({ ctx });
</script>

<template>
  <PostEditor />
</template>
```

```vue
<!-- PostEditor.vue -->
<script setup lang="ts">
import { usePermission, useRole, useAuthState } from "@urauth/vue";

const canEdit = usePermission("post", "write");
const isAdmin = useRole("admin");
const { isAuthenticated, user } = useAuthState();
</script>

<template>
  <div v-if="isAuthenticated">
    <p>Welcome, {{ user.name }}</p>
    <button v-if="canEdit">Edit Post</button>
    <AdminPanel v-if="isAdmin" />
  </div>
</template>
```

## Next Steps

- [Examples](./examples) — Detailed usage examples for every composable.
- [API Reference](./reference) — Full API surface listing.
- [@urauth/ts docs](/packages/ts/) — Shared authorization API.
