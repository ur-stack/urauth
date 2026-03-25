export { Requirement, AllOf, AnyOf, allOf, anyOf } from "./requirement";
export { Permission, Role, Relation, RelationTuple, matchPermission } from "./primitives";
export type { Action, Resource, PermissionParser, RelationParser } from "./primitives";
export { type AsyncPermissionChecker, StringChecker, RoleExpandingChecker } from "./checker";
export {
  RoleRegistry,
  type RoleLoader,
  type RoleCache,
  MemoryRoleCache,
} from "./roles";
export { definePermissions } from "./permission-enum";
export { defineRelations } from "./relation-enum";
export { canAccess, type PermissionChecker } from "./compat";
