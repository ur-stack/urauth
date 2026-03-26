# @urauth/next

Next.js utilities for urAuth access control. Provides a client-side provider with `"use client"` directive and `useAccess()` hook with built-in state management.

For server-side authorization in API routes and middleware, use `@urauth/node` or `@urauth/ts` directly.

## Installation

```bash
pnpm add @urauth/next
```

## Peer Dependencies

- `react` >= 18.0.0
- `@urauth/ts`

## What's Included

| Export | Description |
|--------|-------------|
| `UrAuthProvider` | Client component provider with built-in `useState` |
| `useAccess` | Hook with `can()` and `setContext()` for dynamic auth |

## Quick Start

### Client Components

```tsx
// app/providers.tsx
"use client";

import { UrAuthProvider } from "@urauth/next";

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <UrAuthProvider>
      {children}
    </UrAuthProvider>
  );
}
```

```tsx
// app/layout.tsx
import { Providers } from "./providers";

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html>
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
```

```tsx
// app/components/auth-loader.tsx
"use client";

import { useEffect } from "react";
import { useAccess } from "@urauth/next";
import { AuthContext, Permission, Role } from "@urauth/ts";

export function AuthLoader() {
  const { setContext } = useAccess();

  useEffect(() => {
    fetch("/api/me").then(res => res.json()).then(data => {
      const ctx = new AuthContext({
        user: data.user,
        roles: data.roles.map((r: string) => new Role(r)),
        permissions: data.permissions.map((p: string) => {
          const [resource, action] = p.split(":");
          return new Permission(resource, action);
        }),
      });
      setContext(ctx);
    });
  }, [setContext]);

  return null;
}
```

```tsx
// app/components/toolbar.tsx
"use client";

import { useAccess } from "@urauth/next";

export function Toolbar() {
  const { can } = useAccess();

  return (
    <nav>
      <a href="/posts">Posts</a>
      {can("post", "write") && <a href="/posts/new">New Post</a>}
      {can("user", "read") && <a href="/admin">Admin</a>}
    </nav>
  );
}
```

### Server Components & API Routes

Use `@urauth/ts` directly in server components and `@urauth/node` in API routes:

```typescript
// app/api/posts/route.ts
import { Auth } from "@urauth/node";
import { ForbiddenError } from "@urauth/ts";

const auth = new Auth({ secretKey: process.env.AUTH_SECRET!, /* ... */ });

export async function POST(request: Request) {
  const token = request.headers.get("Authorization")?.replace("Bearer ", "");
  const ctx = await auth.buildContext(token);

  if (!ctx.hasPermission("post:write")) {
    throw new ForbiddenError("Cannot create posts");
  }

  // Create post...
}
```

## Next Steps

- [Examples](./examples) — Client/server patterns, route protection, and more.
- [API Reference](./reference) — Full API surface listing.
