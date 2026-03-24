/**
 * @urauth/node — Node.js backend SDK for urauth.
 *
 * Provides JWT verification middleware, session management,
 * and auth utilities for Node.js backend frameworks (Express, Fastify, Hono, etc.).
 *
 * This package is a stub. Implementation coming soon.
 */

// Re-export core types from @urauth/ts
export type { TokenPayload } from "@urauth/ts";
export { AuthContext } from "@urauth/ts";
export { AuthError, InvalidTokenError, TokenExpiredError, UnauthorizedError, ForbiddenError } from "@urauth/ts";
export { verifyToken } from "@urauth/ts";
export type { AuthConfig } from "@urauth/ts";
