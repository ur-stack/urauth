// Types
export { type TokenPayload, type TokenPair } from "./types";

// Exceptions
export {
  AuthError,
  InvalidTokenError,
  TokenExpiredError,
  TokenRevokedError,
  UnauthorizedError,
  ForbiddenError,
} from "./exceptions";

// Authorization
export { Requirement, AllOf, AnyOf, allOf, anyOf } from "./authz/requirement";
export { Permission, Role, Relation, RelationTuple, matchPermission } from "./authz/primitives";
export type { Action, Resource, PermissionParser, RelationParser } from "./authz/primitives";
export { type AsyncPermissionChecker, StringChecker, RoleExpandingChecker } from "./authz/checker";
export {
  RoleRegistry,
  type RoleLoader,
  type RoleCache,
  MemoryRoleCache,
} from "./authz/roles";
export { definePermissions } from "./authz/permission-enum";
export { defineRelations } from "./authz/relation-enum";
export { canAccess, type PermissionChecker } from "./authz/compat";
export { CommonAction } from "./actions";

// Context
export { AuthContext, type AuthContextOptions } from "./context";

// Tenant
export {
  TenantLevel,
  TenantNode,
  TenantPath,
  TenantHierarchy,
  RoleTemplate,
  TenantDefaults,
  type TenantStore,
  type TenantRoleProvisioner,
} from "./tenant/index";
