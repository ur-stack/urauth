# Examples

## Dynamic Auth Context

The `UrAuthProvider` manages state internally via `useState`. Use `setContext()` to update it dynamically:

```tsx
"use client";

import { useAccess } from "@urauth/next";
import { AuthContext, Permission, Role } from "@urauth/ts";

function LoginForm() {
  const { setContext } = useAccess();

  async function handleLogin(formData: FormData) {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        username: formData.get("username"),
        password: formData.get("password"),
      }),
    });
    const { accessToken } = await res.json();

    // Decode token and set context
    const payload = parseJwt(accessToken);
    setContext(new AuthContext({
      user: payload.user,
      roles: payload.roles.map((r: string) => new Role(r)),
      permissions: payload.permissions.map((p: string) => {
        const [resource, action] = p.split(":");
        return new Permission(resource, action);
      }),
    }));
  }

  return (
    <form action={handleLogin}>
      <input name="username" />
      <input name="password" type="password" />
      <button type="submit">Log In</button>
    </form>
  );
}
```

## Permission-Based UI

```tsx
"use client";

import { useAccess } from "@urauth/next";

function Dashboard() {
  const { can } = useAccess();

  return (
    <div>
      <h1>Dashboard</h1>

      {can("analytics", "read") && <AnalyticsPanel />}
      {can("post", "write") && <QuickPostForm />}
      {can("user", "read") && <UserList />}

      {!can("analytics", "read") && (
        <p>Upgrade your plan to see analytics.</p>
      )}
    </div>
  );
}
```

## Guard Component Pattern

```tsx
"use client";

import { useAccess } from "@urauth/next";

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
  return can(resource, action) ? <>{children}</> : <>{fallback}</>;
}

// Usage
function Page() {
  return (
    <RequirePermission resource="admin" action="access" fallback={<p>Access denied</p>}>
      <AdminPanel />
    </RequirePermission>
  );
}
```

## With Custom Checker

```tsx
"use client";

import { useAccess } from "@urauth/next";
import type { PermissionChecker } from "@urauth/ts";

function FeatureFlaggedContent() {
  const { setContext } = useAccess();

  // Pass a custom checker when setting context
  const checker: PermissionChecker = (subject, resource, action) => {
    if (resource === "beta" && !featureFlags.betaEnabled) return false;
    return subject.permissions.includes(`${resource}:${action}`);
  };

  // setContext accepts an optional second argument for the checker
  setContext(authContext, checker);
}
```

## Server-Side Route Protection (App Router)

Protect Next.js API routes using `@urauth/node`:

```typescript
// app/api/admin/route.ts
import { Auth } from "@urauth/node";
import { UnauthorizedError, ForbiddenError } from "@urauth/ts";
import { NextResponse } from "next/server";

const auth = new Auth({ secretKey: process.env.AUTH_SECRET!, /* ... */ });

export async function GET(request: Request) {
  try {
    const token = request.headers.get("Authorization")?.replace("Bearer ", "");
    const ctx = await auth.buildContext(token);

    if (!ctx.hasRole("admin")) {
      return NextResponse.json({ error: "Forbidden" }, { status: 403 });
    }

    return NextResponse.json({ users: await getUsers() });
  } catch (err) {
    if (err instanceof UnauthorizedError) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    throw err;
  }
}
```

## Next.js Middleware

Protect routes at the edge with Next.js middleware:

```typescript
// middleware.ts
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

export function middleware(request: NextRequest) {
  const token = request.cookies.get("access_token")?.value;

  if (!token && request.nextUrl.pathname.startsWith("/dashboard")) {
    return NextResponse.redirect(new URL("/login", request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/dashboard/:path*", "/admin/:path*"],
};
```
