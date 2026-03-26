# Examples

## Setting Context from a Plugin

Use a Nuxt plugin to set auth context on app initialization:

```typescript
// ~/plugins/auth.ts
import { useAccess } from "@urauth/nuxt";
import { AuthContext, Permission, Role } from "@urauth/ts";

export default defineNuxtPlugin(async () => {
  const { setContext } = useAccess();

  // Fetch user from your API
  const { data } = await useFetch("/api/me");

  if (data.value) {
    const ctx = new AuthContext({
      user: data.value.user,
      roles: data.value.roles.map((r: string) => new Role(r)),
      permissions: data.value.permissions.map((p: string) => {
        const [resource, action] = p.split(":");
        return new Permission(resource, action);
      }),
    });
    setContext(ctx);
  }
});
```

## Permission-Based UI

```vue
<script setup lang="ts">
import { useAccess } from "@urauth/nuxt";

const { can } = useAccess();
</script>

<template>
  <nav>
    <NuxtLink to="/posts">Posts</NuxtLink>
    <NuxtLink v-if="can('post', 'write')" to="/posts/new">New Post</NuxtLink>
    <NuxtLink v-if="can('user', 'read')" to="/admin/users">Users</NuxtLink>
  </nav>
</template>
```

## Route Middleware

Protect pages with Nuxt route middleware:

```typescript
// ~/middleware/auth.ts
export default defineNuxtRouteMiddleware((to) => {
  const { can } = useAccess();

  if (to.meta.permission) {
    const [resource, action] = (to.meta.permission as string).split(":");
    if (!can(resource, action)) {
      return navigateTo("/unauthorized");
    }
  }
});
```

```vue
<!-- ~/pages/admin.vue -->
<script setup lang="ts">
definePageMeta({
  middleware: "auth",
  permission: "admin:access",
});
</script>
```

## Custom Permission Checker

```typescript
import { useAccess } from "@urauth/nuxt";
import type { PermissionChecker } from "@urauth/ts";

const featureFlagChecker: PermissionChecker = (subject, resource, action) => {
  // Override permission checks based on feature flags
  if (resource === "beta-feature" && !featureFlags.betaEnabled) {
    return false;
  }
  return subject.permissions.includes(`${resource}:${action}`);
};

const { can, setContext } = useAccess(featureFlagChecker);
```

## SSR Hydration

The `useAccess()` composable uses Nuxt's `useState` internally, which means:

- State is serialized during SSR and hydrated on the client
- No flash of unauthorized content
- Permission checks work identically on server and client

```vue
<script setup lang="ts">
import { useAccess } from "@urauth/nuxt";

const { can, state } = useAccess();

// Access the raw reactive state if needed
console.log(state.value.ctx?.isAuthenticated());
</script>
```

## Full-Stack Example

```
~/
├── server/
│   ├── middleware/auth.ts          # H3 auth middleware
│   ├── api/posts.get.ts            # Protected API route
│   └── utils/auth.ts               # Auth instance
├── plugins/auth.ts                 # Set client-side context
├── middleware/auth.ts              # Route middleware
└── pages/
    ├── index.vue                   # Public page
    └── admin.vue                   # Protected page
```

```typescript
// ~/server/utils/auth.ts
import { Auth } from "@urauth/node";

export const auth = new Auth({
  secretKey: process.env.AUTH_SECRET!,
  algorithm: "HS256",
  issuer: "my-app",
  accessTokenTtl: 900,
  refreshTokenTtl: 604800,
});
```
