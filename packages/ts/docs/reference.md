# API Reference

Complete listing of all exports from `@urauth/ts`.

## Types

### TokenPayload

```typescript
interface TokenPayload {
  sub: string;
  jti: string;
  iat: number;
  exp: number;
  type: "access" | "refresh";
  scopes?: string[];
  roles?: string[];
  permissions?: string[];
  tenant_id?: string;
  tenant_path?: Record<string, string>;
  fresh?: boolean;
  family_id?: string;
  [key: string]: unknown;
}
```

### TokenPair

```typescript
interface TokenPair {
  accessToken: string;
  refreshToken: string;
  tokenType: string;
}
```

### Action / Resource

Branded string types for compile-time safety:

```typescript
type Action = string & { readonly __brand?: "Action" };
type Resource = string & { readonly __brand?: "Resource" };
```

## Exceptions

All extend `AuthError` which has `statusCode` and `detail` properties.

| Class | Status | Description |
|-------|--------|-------------|
| `AuthError` | — | Base error class |
| `InvalidTokenError` | 401 | Token is malformed or invalid |
| `TokenExpiredError` | 401 | Token has expired |
| `TokenRevokedError` | 401 | Token has been revoked |
| `UnauthorizedError` | 401 | Authentication required |
| `ForbiddenError` | 403 | Insufficient permissions |

## Authorization Primitives

### Permission

```typescript
class Permission extends Requirement {
  readonly resource: Resource;
  readonly action: Action;

  constructor(resource: string, action?: string, options?: {
    separator?: string;
    parser?: (s: string) => [string, string];
  });

  evaluate(ctx: AuthContext): boolean;
  toString(): string;
  equals(other: Permission | string): boolean;
}
```

### Role

```typescript
class Role extends Requirement {
  readonly name: string;
  readonly permissions: Permission[];

  constructor(name: string, permissions?: Permission[]);

  evaluate(ctx: AuthContext): boolean;
  toString(): string;
  equals(other: Role | string): boolean;
}
```

### Relation

```typescript
class Relation extends Requirement {
  readonly resource: Resource;
  readonly name: string;

  constructor(resource: string, name?: string, options?: {
    separator?: string;
    parser?: (s: string) => [string, string];
  });

  get separator(): string;
  tuple(objectId: string, subject?: string): RelationTuple;
  evaluate(ctx: AuthContext): boolean;
  toString(): string;
  equals(other: Relation | string): boolean;
}
```

### RelationTuple

```typescript
class RelationTuple {
  readonly relation: Relation;
  readonly objectId: string;
  readonly subject: string | undefined;

  constructor(relation: Relation, objectId: string, subject?: string);
  static parse(s: string): RelationTuple;
  toString(): string;
  equals(other: RelationTuple | string): boolean;
}
```

### Requirement / AllOf / AnyOf

```typescript
abstract class Requirement {
  abstract evaluate(ctx: AuthContext): boolean;
  and(other: Requirement): AllOf;
  or(other: Requirement): AnyOf;
}

function allOf(...requirements: Requirement[]): AllOf;
function anyOf(...requirements: Requirement[]): AnyOf;
```

## Functions

### matchPermission

```typescript
function matchPermission(
  pattern: Permission | string,
  target: Permission | string,
): boolean;
```

### definePermissions

```typescript
function definePermissions<T extends Record<string, string | [string, string] | Permission>>(
  defs: T,
  options?: { parser?: (s: string) => [string, string] },
): Readonly<{ [K in keyof T]: Permission }>;
```

### defineRelations

```typescript
function defineRelations<T extends Record<string, string | [string, string] | Relation>>(
  defs: T,
  options?: { parser?: (s: string) => [string, string] },
): Readonly<{ [K in keyof T]: Relation }>;
```

### canAccess

```typescript
function canAccess(
  ctx: AuthContext,
  resourceOrPermission: string | Permission,
  action?: string,
  options?: { scope?: string; checker?: PermissionChecker },
): boolean;
```

## Checkers

### AsyncPermissionChecker (interface)

```typescript
interface AsyncPermissionChecker {
  hasPermission(
    ctx: AuthContext,
    resource: string,
    action: string,
    options?: { scope?: string },
  ): Promise<boolean>;
}
```

### PermissionChecker (interface, sync)

```typescript
interface PermissionChecker {
  hasPermission(
    ctx: AuthContext,
    resource: string,
    action: string,
    options?: { scope?: string },
  ): boolean;
}
```

### StringChecker

Implements `AsyncPermissionChecker`. Matches permission strings using `matchPermission`.

### RoleExpandingChecker

Implements `AsyncPermissionChecker`. Expands role hierarchy before checking.

```typescript
class RoleExpandingChecker {
  constructor(options: {
    rolePermissions: Map<string, Set<string>>;
    hierarchy?: Map<string, string[]>;
  });
  effectiveRoles(userRoles: string[]): Set<string>;
}
```

## Role Management

### RoleRegistry

```typescript
class RoleRegistry {
  role(name: string, permissions: string[], options?: { inherits?: string[] }): void;
  include(other: RoleRegistry): void;
  withLoader(loader: RoleLoader, options?: { cache?: RoleCache; cacheTtl?: number }): void;
  load(): Promise<void>;
  reload(): Promise<void>;
  buildChecker(): RoleExpandingChecker;
}
```

## Tenant

### TenantLevel / TenantNode / TenantPath / TenantHierarchy

See [Tenant documentation](./tenant).

### RoleTemplate / TenantDefaults

See [Tenant documentation](./tenant#tenantdefaults).

### TenantStore / TenantRoleProvisioner (interfaces)

See [Tenant documentation](./tenant#store-interfaces).

## Context

### AuthContext

See [AuthContext documentation](./context).

## Actions

### CommonAction

```typescript
const CommonAction = {
  CREATE: "create",
  READ: "read",
  UPDATE: "update",
  DELETE: "delete",
  LIST: "list",
  ARCHIVE: "archive",
} as const;
```
