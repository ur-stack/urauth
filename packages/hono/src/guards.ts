/**
 * Hono guard middleware — wraps @urauth/node guard factories into Hono middleware.
 */

import type { MiddlewareHandler } from "hono";
import type { Auth } from "@urauth/node";
import {
  type GuardCheck,
  requirePermission as _requirePermission,
  requireRole as _requireRole,
  requireAuth as _requireAuth,
  requireTenant as _requireTenant,
  policy as _policy,
} from "@urauth/node";
import { guard as guardFn } from "@urauth/node";
import type { AuthContext, Requirement } from "@urauth/ts";
import type { UrAuthEnv } from "./types";

type AuthMiddleware = MiddlewareHandler<UrAuthEnv>;

/** Wrap a guard check function into Hono middleware. */
function wrapGuard(check: GuardCheck): AuthMiddleware {
  return async (c, next) => {
    const ctx = c.get("auth");
    check(ctx, c.req.raw);
    await next();
  };
}

/**
 * Guard middleware — require a Requirement to be satisfied.
 *
 * @example
 * ```ts
 * app.get("/users", guard(auth, Permission("user", "read")), handler);
 * app.delete("/posts/:id", guard(auth, Permission("post", "delete").or(Role("admin"))), handler);
 * ```
 */
export function guard(auth: Auth, requirement: Requirement): AuthMiddleware {
  return wrapGuard(guardFn(requirement));
}

/** Require authentication only (no specific permission). */
export function protect(_auth: Auth): AuthMiddleware {
  return wrapGuard(_requireAuth());
}

/** Require a specific permission. */
export function guardPermission(
  auth: Auth,
  resource: string,
  action: string,
): AuthMiddleware {
  return wrapGuard(_requirePermission(resource, action));
}

/** Require a specific role. */
export function guardRole(auth: Auth, roleName: string): AuthMiddleware {
  return wrapGuard(_requireRole(roleName));
}

/** Require tenant membership at a specific level. */
export function guardTenant(
  auth: Auth,
  opts: { level: string },
): AuthMiddleware {
  return wrapGuard(_requireTenant(opts));
}

/** Custom policy guard. */
export function guardPolicy(
  auth: Auth,
  check: (ctx: AuthContext) => boolean,
): AuthMiddleware {
  return wrapGuard(_policy(check));
}
