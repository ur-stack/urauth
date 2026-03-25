/**
 * definePermissions — declarative permission definitions.
 *
 * TypeScript-idiomatic alternative to Python's PermissionEnum.
 *
 * Usage:
 *   const Perms = definePermissions({
 *     USER_READ: ["user", "read"],
 *     TASK_WRITE: "task:write",
 *     ADMIN_ALL: new Permission("admin", "*"),
 *   });
 *   Perms.USER_READ            // Permission instance
 *   Perms.USER_READ.toString() // "user:read"
 */

import { Permission, type PermissionParser } from "./primitives";

type PermissionDef = string | [string, string] | Permission;
type PermissionDefs = Record<string, PermissionDef>;

type PermissionMap<T extends PermissionDefs> = {
  readonly [K in keyof T]: Permission;
};

/** Create a frozen map of named Permission instances. */
export function definePermissions<T extends PermissionDefs>(
  defs: T,
  options?: { parser?: PermissionParser },
): PermissionMap<T> {
  const result = {} as Record<string, Permission>;
  for (const [key, def] of Object.entries(defs)) {
    if (def instanceof Permission) {
      result[key] = def;
    } else if (Array.isArray(def)) {
      result[key] = new Permission(def[0], def[1]);
    } else {
      result[key] = new Permission(def, undefined, { parser: options?.parser });
    }
  }
  return Object.freeze(result) as PermissionMap<T>;
}
