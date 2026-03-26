# API Reference

## UrAuthProvider

React context provider component. Wraps `React.createContext` with the urAuth access context.

```typescript
const UrAuthProvider: React.Provider<{
  ctx: AuthContext
  checker?: PermissionChecker
} | null>
```

**Props:**

| Prop | Type | Description |
|------|------|-------------|
| `value` | `{ ctx: AuthContext; checker?: PermissionChecker }` | Auth context and optional checker |
| `children` | `React.ReactNode` | Child components |

**Usage:**

```tsx
<UrAuthProvider value={{ ctx: authContext, checker }}>
  <App />
</UrAuthProvider>
```

---

## useAccess

Hook for checking permissions in components.

```typescript
function useAccess(): {
  can: (resource: string, action: string, options?: { scope?: string }) => boolean
}
```

**Returns:**

| Property | Type | Description |
|----------|------|-------------|
| `can` | `(resource, action, options?) => boolean` | Check if the current user has a permission |

**Throws:** `Error` if `<UrAuthProvider>` is not found in the component tree.

**Parameters for `can()`:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `resource` | `string` | Resource name (e.g., `"post"`) |
| `action` | `string` | Action name (e.g., `"write"`) |
| `options.scope` | `string` | Optional scope for scoped checks |
