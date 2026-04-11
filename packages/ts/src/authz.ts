/**
 * Backward-compatibility shim — re-exports from ./authz/ submodules.
 *
 * Downstream packages (@urauth/vue, @urauth/nuxt) import from "@urauth/ts"
 * which resolves through this file. All existing imports continue to work.
 */

export { Permission, Role, Relation, RelationTuple, matchPermission } from "./authz/primitives.js";
export type { AsyncPermissionChecker } from "./authz/checker.js";
export { StringChecker, RoleExpandingChecker } from "./authz/checker.js";
export { canAccess, type PermissionChecker } from "./authz/compat.js";
export { Requirement, AllOf, AnyOf, allOf, anyOf } from "./authz/requirement.js";
export { RoleRegistry, type RoleLoader, type RoleCache, MemoryRoleCache } from "./authz/roles.js";
export { definePermissions } from "./authz/permission-enum.js";
export { defineRelations } from "./authz/relation-enum.js";
