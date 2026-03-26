# API Reference

## useAccess

SSR-safe composable for access control. Uses Nuxt's `useState` for hydration safety.

```typescript
function useAccess(checker?: PermissionChecker): {
  can: (resource: string, action: string, options?: { scope?: string }) => boolean
  setContext: (ctx: AuthContext) => void
  state: Ref<AccessState>
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checker` | `PermissionChecker` | Optional custom permission checker |

**Returns:**

| Property | Type | Description |
|----------|------|-------------|
| `can` | `(resource, action, options?) => boolean` | Check if the current user has a permission. Returns `false` if no context is set. |
| `setContext` | `(ctx: AuthContext) => void` | Set the auth context. Triggers reactivity for all consumers. |
| `state` | `Ref<AccessState>` | Raw reactive state. `state.value.ctx` is the `AuthContext` (or `null`). |

**Throws:** Nothing — returns `false` for all `can()` calls when no context is set.

---

## canAccess

Re-exported from `@urauth/ts`. Performs a synchronous permission check.

```typescript
function canAccess(
  ctx: AuthContext,
  resource: string,
  action: string,
  options?: { scope?: string; checker?: PermissionChecker }
): boolean
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `ctx` | `AuthContext` | Auth context to check against |
| `resource` | `string` | Resource name |
| `action` | `string` | Action name |
| `options.scope` | `string` | Optional scope |
| `options.checker` | `PermissionChecker` | Optional custom checker |

---

## urAuthModule

Nuxt module entry point. Used in `nuxt.config.ts` module registration.

```typescript
export default function urAuthModule(): void
```

---

## AccessState

Internal state interface used by `useAccess`.

```typescript
interface AccessState {
  ctx: AuthContext | null
  checker?: PermissionChecker
}
```
