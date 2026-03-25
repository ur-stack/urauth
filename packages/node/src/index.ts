// ── Auth Engine ──────────────────────────────────────────────────
export { Auth, type AuthOptions, type AuthCallbacks } from "./auth";
export { TokenLifecycle, type IssueRequest, type IssuedTokenPair } from "./lifecycle";

// ── Config ───────────────────────────────────────────────────────
export { type AuthConfig, defaultConfig, validateConfig } from "./config";

// ── Tokens ───────────────────────────────────────────────────────
export {
  verifyToken,
  TokenService,
  type CreateAccessTokenOptions,
  type CreateRefreshTokenOptions,
  type CreateTokenPairOptions,
} from "./tokens/index";
export { RevocationService } from "./tokens/revocation";
export { RefreshService } from "./tokens/refresh";

// ── Stores ───────────────────────────────────────────────────────
export { type TokenStore, type SessionStore, type SessionData } from "./stores/types";
export { MemoryTokenStore, MemorySessionStore } from "./stores/memory";

// ── Guards ───────────────────────────────────────────────────────
export {
  type GuardCheck,
  requirePermission,
  requireRole,
  requireAny,
  requireAll,
  guard,
  requireTenant,
  requireAuth,
  policy,
} from "./guards";

// ── Password ─────────────────────────────────────────────────────
export { PasswordHasher, type PasswordHasherOptions } from "./password";

// ── Rate Limiting ────────────────────────────────────────────────
export { RateLimiter, KeyStrategy, type RateLimiterOptions } from "./ratelimit";

// ── Pipeline ─────────────────────────────────────────────────────
export {
  type PipelineConfig,
  type StrategyConfig,
  type OAuthProviderConfig,
  type MfaMethodConfig,
  defaultPipeline,
} from "./pipeline";

// ── Transport ────────────────────────────────────────────────────
export { type Transport, extractBearerToken } from "./transport";

// ── Testing ──────────────────────────────────────────────────────
export { mockContext, mockAdminContext, mockAnonymousContext, mockPayload } from "./testing";

// ── Re-exports from @urauth/ts (convenience) ────────────────────
export type { TokenPayload, TokenPair } from "@urauth/ts";
export {
  AuthError,
  InvalidTokenError,
  TokenExpiredError,
  TokenRevokedError,
  UnauthorizedError,
  ForbiddenError,
} from "@urauth/ts";
export { AuthContext, type AuthContextOptions } from "@urauth/ts";
export {
  Permission,
  Role,
  Relation,
  RelationTuple,
  matchPermission,
  Requirement,
  AllOf,
  AnyOf,
  allOf,
  anyOf,
  StringChecker,
  RoleExpandingChecker,
  RoleRegistry,
  MemoryRoleCache,
  definePermissions,
  defineRelations,
  canAccess,
  CommonAction,
  TenantLevel,
  TenantNode,
  TenantPath,
  TenantHierarchy,
  RoleTemplate,
  TenantDefaults,
} from "@urauth/ts";
export type {
  Action,
  Resource,
  PermissionParser,
  RelationParser,
  AsyncPermissionChecker,
  RoleLoader,
  RoleCache,
  PermissionChecker,
  TenantStore,
  TenantRoleProvisioner,
} from "@urauth/ts";
