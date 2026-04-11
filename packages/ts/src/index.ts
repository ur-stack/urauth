// Types
export { type TokenPayload, type TokenPair } from "./types.js";

// Exceptions
export {
  AuthError,
  InvalidTokenError,
  TokenExpiredError,
  TokenRevokedError,
  UnauthorizedError,
  ForbiddenError,
} from "./exceptions.js";

// Authorization
export { Requirement, AllOf, AnyOf, allOf, anyOf } from "./authz/requirement.js";
export { Permission, Role, Relation, RelationTuple, matchPermission } from "./authz/primitives.js";
export type { Action, Resource, PermissionParser, RelationParser } from "./authz/primitives.js";
export { type AsyncPermissionChecker, StringChecker, RoleExpandingChecker } from "./authz/checker.js";
export {
  RoleRegistry,
  type RoleLoader,
  type RoleCache,
  MemoryRoleCache,
} from "./authz/roles.js";
export { definePermissions } from "./authz/permission-enum.js";
export { defineRelations } from "./authz/relation-enum.js";
export { canAccess, type PermissionChecker } from "./authz/compat.js";
export { CommonAction } from "./actions.js";

// Context
export { AuthContext, type AuthContextOptions } from "./context.js";

// Client
export {
  type HttpClient,
  type RequestConfig,
  type HttpResponse,
  HttpError,
  createAxiosClient,
  type TokenStorage,
  memoryStorage,
  localStorageTokens,
  decodeJWT,
  UrAuthClient,
  type UrAuthClientConfig,
  type LoginRequest,
  type IdentifierLoginRequest,
  type LoginCredentials,
  urAuthKeys,
  authQueryOptions,
  authMutationOptions,
  type EndpointDef,
  type EndpointRegistry,
  defaultAuthEndpoints,
  defineEndpoints,
  createQueryKeys,
  createEndpointFunctions,
} from "./client/index.js";

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
} from "./tenant/index.js";
