# @urauth/react

React hooks for urAuth access control. Provides a context provider and `useAccess()` hook for permission checking in React 18+ components.

## Installation

```bash
pnpm add @urauth/react
```

## Peer Dependencies

- `react` >= 18.0.0
- `@urauth/ts`

## What's Included

| Export | Description |
|--------|-------------|
| `UrAuthProvider` | React context provider for auth state |
| `useAccess` | Hook returning a `can()` permission check function |

## Quick Start

```tsx
import { UrAuthProvider, useAccess } from "@urauth/react";
import { AuthContext, Permission, Role } from "@urauth/ts";

// 1. Create auth context
const ctx = new AuthContext({
  user: { id: "1", name: "Alice" },
  roles: [new Role("editor")],
  permissions: [new Permission("post", "read"), new Permission("post", "write")],
});

// 2. Wrap your app with the provider
function App() {
  return (
    <UrAuthProvider value={{ ctx }}>
      <PostEditor />
    </UrAuthProvider>
  );
}

// 3. Use the hook in any child component
function PostEditor() {
  const { can } = useAccess();

  return (
    <div>
      {can("post", "write") && <button>Edit Post</button>}
      {can("post", "delete") && <button>Delete Post</button>}
    </div>
  );
}
```

## Next Steps

- [Examples](./examples) — Detailed usage patterns.
- [API Reference](./reference) — Full API surface listing.
- [@urauth/ts docs](/packages/ts/) — Shared authorization API.
