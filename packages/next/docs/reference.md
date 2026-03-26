# API Reference

## UrAuthProvider

Client component that provides auth state to the component tree. Marked with `"use client"` directive.

```typescript
function UrAuthProvider({ children }: { children: ReactNode }): ReactElement
```

| Prop | Type | Description |
|------|------|-------------|
| `children` | `ReactNode` | Child components |

Manages state internally via `useState`. Use `useAccess().setContext()` to update the auth context.

---

## useAccess

Hook for checking permissions and managing auth context in client components.

```typescript
function useAccess(): {
  can: (resource: string, action: string, options?: { scope?: string }) => boolean
  setContext: (ctx: AuthContext, checker?: PermissionChecker) => void
}
```

**Returns:**

| Property | Type | Description |
|----------|------|-------------|
| `can` | `(resource, action, options?) => boolean` | Check if the current user has a permission. Returns `false` if no context has been set. |
| `setContext` | `(ctx, checker?) => void` | Set the auth context and optional custom checker. Triggers a re-render for all consumers. |

**Throws:** `Error` if `<UrAuthProvider>` is not found in the component tree.

### can()

| Parameter | Type | Description |
|-----------|------|-------------|
| `resource` | `string` | Resource name (e.g., `"post"`) |
| `action` | `string` | Action name (e.g., `"write"`) |
| `options.scope` | `string` | Optional scope for scoped checks |

### setContext()

| Parameter | Type | Description |
|-----------|------|-------------|
| `ctx` | `AuthContext` | Auth context from `@urauth/ts` |
| `checker` | `PermissionChecker` | Optional custom permission checker |

---

## Key Differences from @urauth/react

| Feature | `@urauth/react` | `@urauth/next` |
|---------|-----------------|----------------|
| Provider | Pass `value` prop directly | Built-in `useState`, use `setContext()` |
| `"use client"` | Not included (you add it) | Included in the module |
| `setContext` | Not available (provide new value) | Available via `useAccess()` |
| SSR | No built-in SSR support | Designed for Next.js App Router |
| Context updates | Replace provider value | Call `setContext()` anywhere |
