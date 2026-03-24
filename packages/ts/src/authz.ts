/**
 * Backward-compatibility shim — re-exports from ./authz/ submodules.
 *
 * Downstream packages (@urauth/vue, @urauth/nuxt) import from "@urauth/ts"
 * which resolves through this file. All existing imports continue to work.
 */

export { Permission, Role, Relation } from "./authz/primitives";
export type { AsyncPermissionChecker } from "./authz/checker";
export { StringChecker, RoleExpandingChecker } from "./authz/checker";
export { canAccess, type PermissionChecker } from "./authz/compat";
export { Requirement, AllOf, AnyOf, allOf, anyOf } from "./authz/requirement";
export { RoleRegistry, type RoleLoader, type RoleCache, MemoryRoleCache } from "./authz/roles";
export { definePermissions } from "./authz/permission-enum";
