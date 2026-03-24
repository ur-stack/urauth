// Types
export { type TokenPayload, type TokenPair } from "./types";

// Config
export { type AuthConfig, defaultConfig } from "./config";

// Exceptions
export {
  AuthError,
  InvalidTokenError,
  TokenExpiredError,
  TokenRevokedError,
  UnauthorizedError,
  ForbiddenError,
} from "./exceptions";

// Tokens
export {
  verifyToken,
  TokenService,
  type CreateAccessTokenOptions,
  type CreateRefreshTokenOptions,
  type CreateTokenPairOptions,
} from "./tokens/index";
export { RevocationService } from "./tokens/revocation";
export { RefreshService } from "./tokens/refresh";

// Stores
export { type TokenStore, type SessionStore, type SessionData } from "./stores/types";
export { MemoryTokenStore, MemorySessionStore } from "./stores/memory";

// Authorization
export { Requirement, AllOf, AnyOf, allOf, anyOf } from "./authz/requirement";
export { Permission, Role, Relation } from "./authz/primitives";
export type { Action, Resource } from "./authz/primitives";
export { type AsyncPermissionChecker, StringChecker, RoleExpandingChecker } from "./authz/checker";
export {
  RoleRegistry,
  type RoleLoader,
  type RoleCache,
  MemoryRoleCache,
} from "./authz/roles";
export { definePermissions } from "./authz/permission-enum";
export { canAccess, type PermissionChecker } from "./authz/compat";
export { CommonAction } from "./actions";

// Context
export { AuthContext, type AuthContextOptions } from "./context";
