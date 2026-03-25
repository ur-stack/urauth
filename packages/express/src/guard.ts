/**
 * Express guard middleware — wraps @urauth/node guard factories.
 */

import type { RequestHandler } from "express";
import {
  guard as guardFn,
  requirePermission,
  requireRole,
  requireAuth,
  requireTenant,
  policy as policyFn,
  type GuardCheck,
} from "@urauth/node";
import type { AuthContext, Requirement } from "@urauth/ts";
import "./types";

/** Wrap a guard check into Express middleware. */
function wrapGuard(check: GuardCheck): RequestHandler {
  return (req, _res, next) => {
    try {
      check(req.auth, req);
      next();
    } catch (err) {
      next(err);
    }
  };
}

/**
 * Guard middleware — require a Requirement to be satisfied.
 *
 * @example
 * ```ts
 * app.get("/users", guard(Permission("user", "read")), handler);
 * ```
 */
function guard(requirement: Requirement, options?: { resourceFrom?: string }): RequestHandler {
  return wrapGuard(guardFn(requirement));
}

/** Shorthand: require authentication only. */
function protect(): RequestHandler {
  return wrapGuard(requireAuth());
}

/** Tenant guard. */
function tenantGuard(opts: { level: string }): RequestHandler {
  return wrapGuard(requireTenant(opts));
}

/** Custom policy guard. */
function policyGuard(check: (ctx: AuthContext) => boolean): RequestHandler {
  return wrapGuard(policyFn(check));
}

// Attach sub-methods to guard
guard.tenant = tenantGuard;
guard.policy = policyGuard;

export { guard, protect };
