# Examples

## Basic Setup

Wrap your application tree with `UrAuthProvider`:

```tsx
import { UrAuthProvider } from "@urauth/react";
import { AuthContext, Permission, Role } from "@urauth/ts";

function App() {
  const ctx = new AuthContext({
    user: currentUser,
    roles: [new Role("editor")],
    permissions: [
      new Permission("post", "read"),
      new Permission("post", "write"),
    ],
  });

  return (
    <UrAuthProvider value={{ ctx }}>
      <AppContent />
    </UrAuthProvider>
  );
}
```

## Permission-Based Rendering

```tsx
import { useAccess } from "@urauth/react";

function Toolbar() {
  const { can } = useAccess();

  return (
    <nav>
      <a href="/posts">Posts</a>
      {can("post", "write") && <a href="/posts/new">New Post</a>}
      {can("user", "read") && <a href="/admin/users">Users</a>}
      {can("settings", "write") && <a href="/settings">Settings</a>}
    </nav>
  );
}
```

## With Custom Checker

Pass a custom `PermissionChecker` for advanced authorization logic:

```tsx
import { UrAuthProvider } from "@urauth/react";
import type { PermissionChecker } from "@urauth/ts";

const checker: PermissionChecker = (subject, resource, action) => {
  // Custom logic — feature flags, A/B tests, etc.
  return subject.permissions.includes(`${resource}:${action}`);
};

function App() {
  return (
    <UrAuthProvider value={{ ctx: authContext, checker }}>
      <AppContent />
    </UrAuthProvider>
  );
}
```

## Scoped Permissions

```tsx
function TeamContent() {
  const { can } = useAccess();

  // Check permissions within a specific scope
  if (can("post", "write", { scope: "team-alpha" })) {
    return <PostEditor team="alpha" />;
  }

  return <p>You don't have write access to this team.</p>;
}
```

## Dynamic Context from API

```tsx
import { useState, useEffect } from "react";
import { UrAuthProvider } from "@urauth/react";
import { AuthContext, Permission, Role } from "@urauth/ts";

function AuthProvider({ children }: { children: React.ReactNode }) {
  const [ctx, setCtx] = useState<AuthContext | null>(null);

  useEffect(() => {
    fetch("/api/me")
      .then((res) => res.json())
      .then((data) => {
        const authCtx = new AuthContext({
          user: data.user,
          roles: data.roles.map((r: string) => new Role(r)),
          permissions: data.permissions.map((p: string) => {
            const [resource, action] = p.split(":");
            return new Permission(resource, action);
          }),
        });
        setCtx(authCtx);
      });
  }, []);

  if (!ctx) return <div>Loading...</div>;

  return (
    <UrAuthProvider value={{ ctx }}>
      {children}
    </UrAuthProvider>
  );
}
```

## Guard Component Pattern

Build reusable guard components on top of `useAccess`:

```tsx
import { useAccess } from "@urauth/react";

function RequirePermission({
  resource,
  action,
  fallback = null,
  children,
}: {
  resource: string;
  action: string;
  fallback?: React.ReactNode;
  children: React.ReactNode;
}) {
  const { can } = useAccess();

  if (!can(resource, action)) {
    return <>{fallback}</>;
  }

  return <>{children}</>;
}

// Usage
function Dashboard() {
  return (
    <div>
      <RequirePermission resource="analytics" action="read" fallback={<UpgradeBanner />}>
        <AnalyticsPanel />
      </RequirePermission>
    </div>
  );
}
```
