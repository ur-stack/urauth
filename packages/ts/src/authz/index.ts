export { Requirement, AllOf, AnyOf, allOf, anyOf } from "./requirement.js";
export { Permission, Role, Relation, RelationTuple, matchPermission } from "./primitives.js";
export type { Action, Resource, PermissionParser, RelationParser } from "./primitives.js";
export { type AsyncPermissionChecker, StringChecker, RoleExpandingChecker } from "./checker.js";
export {
  RoleRegistry,
  type RoleLoader,
  type RoleCache,
  MemoryRoleCache,
} from "./roles.js";
export { definePermissions } from "./permission-enum.js";
export { defineRelations } from "./relation-enum.js";
export { canAccess, type PermissionChecker } from "./compat.js";
