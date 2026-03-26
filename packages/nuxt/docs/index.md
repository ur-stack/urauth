# @urauth/nuxt

Nuxt 3 module for urAuth access control. Provides SSR-safe composables with hydration support via `useState`, plus server-side auth through `@urauth/h3`.

## Installation

```bash
pnpm add @urauth/nuxt
```

## Dependencies

- `@urauth/ts` — shared authorization primitives
- For server-side auth, also install `@urauth/h3`

## What's Included

| Export | Description |
|--------|-------------|
| `useAccess` | SSR-safe composable with `can()`, `setContext()`, and reactive `state` |
| `canAccess` | Re-exported from `@urauth/ts` for direct permission checks |
| `urAuthModule` | Nuxt module entry point |

## Quick Start

### Client-Side (Pages & Components)

```vue
<script setup lang="ts">
import { useAccess } from "@urauth/nuxt";
import { AuthContext, Permission, Role } from "@urauth/ts";

const { can, setContext } = useAccess();

// Set context from your auth source (API call, middleware, etc.)
const ctx = new AuthContext({
  user: { id: "1", name: "Alice" },
  roles: [new Role("editor")],
  permissions: [new Permission("post", "read"), new Permission("post", "write")],
});
setContext(ctx);
</script>

<template>
  <button v-if="can('post', 'write')">Edit Post</button>
</template>
```

### Server-Side (Nuxt Server Routes)

Use `@urauth/h3` for server-side auth in Nuxt API routes:

```typescript
// ~/server/middleware/auth.ts
import { createOnRequest } from "@urauth/h3";
import { auth } from "~/server/utils/auth";

export default createOnRequest(auth, { optional: true });
```

```typescript
// ~/server/api/posts.post.ts
import { requirePermission } from "@urauth/h3";

export default defineEventHandler({
  onRequest: [requirePermission("post", "write")],
  handler: async (event) => {
    const user = event.context.auth.user;
    // Create post...
  },
});
```

## Next Steps

- [Examples](./examples) — Detailed usage patterns for Nuxt apps.
- [API Reference](./reference) — Full API surface listing.
- [@urauth/h3 docs](/packages/h3/) — Server-side auth for Nuxt.
