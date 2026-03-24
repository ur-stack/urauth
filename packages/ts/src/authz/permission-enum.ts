/**
 * definePermissions — declarative permission definitions.
 *
 * TypeScript-idiomatic alternative to Python's PermissionEnum.
 *
 * Usage:
 *   const Perms = definePermissions({
 *     USER_READ: ["user", "read"],
 *     TASK_WRITE: ["task", "write"],
 *   });
 *   Perms.USER_READ          // Permission instance
 *   Perms.USER_READ.toString() // "user:read"
 */

import { Permission } from "./primitives";

type PermissionDefs = Record<string, [string, string]>;

type PermissionMap<T extends PermissionDefs> = {
  readonly [K in keyof T]: Permission;
};

/** Create a frozen map of named Permission instances from [resource, action] tuples. */
export function definePermissions<T extends PermissionDefs>(defs: T): PermissionMap<T> {
  const result = {} as Record<string, Permission>;
  for (const [key, [resource, action]] of Object.entries(defs)) {
    result[key] = new Permission(resource, action);
  }
  return Object.freeze(result) as PermissionMap<T>;
}
