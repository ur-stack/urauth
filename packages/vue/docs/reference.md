# API Reference

## provideAccess

Provide auth context to all descendant components via Vue's dependency injection.

```typescript
function provideAccess(access: { ctx: AuthContext; checker?: PermissionChecker }): void
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `access.ctx` | `AuthContext` | The auth context from `@urauth/ts` |
| `access.checker` | `PermissionChecker` | Optional custom permission checker |

Must be called in a component's `setup()`. All composables below require this to be called in an ancestor component.

---

## useAccess

General-purpose permission check composable.

```typescript
function useAccess(): {
  can: (resource: string, action: string, options?: { scope?: string }) => boolean
}
```

**Returns:**

| Property | Type | Description |
|----------|------|-------------|
| `can` | `(resource, action, options?) => boolean` | Check if the current user has a permission |

**Throws:** `Error` if `provideAccess()` was not called in an ancestor.

---

## usePermission

Reactive permission check that returns a computed ref.

```typescript
function usePermission(
  resource: string,
  action: string,
  options?: { scope?: string }
): ComputedRef<boolean>
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `resource` | `string` | Resource name (e.g., `"post"`) |
| `action` | `string` | Action name (e.g., `"write"`) |
| `options.scope` | `string` | Optional scope for scoped checks |

**Returns:** `ComputedRef<boolean>` — reactive boolean ref.

---

## useRole

Reactive check for a single role.

```typescript
function useRole(role: string): ComputedRef<boolean>
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `role` | `string` | Role name to check |

**Returns:** `ComputedRef<boolean>`

---

## useAnyRole

Reactive check for any of the given roles.

```typescript
function useAnyRole(...roles: string[]): ComputedRef<boolean>
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `...roles` | `string[]` | Role names to check (variadic) |

**Returns:** `ComputedRef<boolean>` — `true` if the user holds at least one of the given roles.

---

## useAuthState

Reactive auth state introspection.

```typescript
function useAuthState(): {
  isAuthenticated: ComputedRef<boolean>
  user: ComputedRef<unknown>
  roles: ComputedRef<string[]>
  permissions: ComputedRef<string[]>
  tenantId: ComputedRef<string | undefined>
}
```

All returned properties are computed refs that react to auth context changes.

---

## useRequirement

Evaluate a composite requirement reactively.

```typescript
function useRequirement(requirement: Requirement): ComputedRef<boolean>
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `requirement` | `Requirement` | A `Permission`, `Role`, `Relation`, `AllOf`, or `AnyOf` |

**Returns:** `ComputedRef<boolean>`

---

## useTenant

Reactive tenant context.

```typescript
function useTenant(): {
  tenantId: ComputedRef<string | undefined>
  inTenant: (tenantId: string) => boolean
  atLevel: (level: string) => string | undefined
}
```

| Property | Type | Description |
|----------|------|-------------|
| `tenantId` | `ComputedRef<string \| undefined>` | Current leaf tenant ID |
| `inTenant` | `(tenantId: string) => boolean` | Check membership in a tenant |
| `atLevel` | `(level: string) => string \| undefined` | Get tenant ID at a hierarchy level |
