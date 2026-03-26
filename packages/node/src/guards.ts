/**
 * Guard factories — framework-agnostic check functions.
 *
 * Each factory returns a check function: (ctx: AuthContext) => void
 * Framework adapters wrap these into their middleware format.
 */

import type {
  AuthContext,
  Requirement} from "@urauth/ts";
import {
  Permission,
  Role,
  ForbiddenError,
  UnauthorizedError,
} from "@urauth/ts";

export type GuardCheck = (ctx: AuthContext, request?: unknown) => void;

/** Require the context to have a specific permission. */
export function requirePermission(resource: string, action: string): GuardCheck {
  const perm = new Permission(resource, action);
  return (ctx) => {
    if (!ctx.isAuthenticated()) throw new UnauthorizedError();
    if (!ctx.hasPermission(perm)) {
      throw new ForbiddenError(`Missing permission: ${perm.toString()}`);
    }
  };
}

/** Require the context to have a specific role. */
export function requireRole(roleName: string): GuardCheck {
  const role = new Role(roleName);
  return (ctx) => {
    if (!ctx.isAuthenticated()) throw new UnauthorizedError();
    if (!ctx.hasRole(role)) {
      throw new ForbiddenError(`Missing role: ${roleName}`);
    }
  };
}

/** Require that a composable requirement is satisfied. */
export function requireAny(...requirements: Requirement[]): GuardCheck {
  return (ctx) => {
    if (!ctx.isAuthenticated()) throw new UnauthorizedError();
    const satisfied = requirements.some((r) => r.evaluate(ctx));
    if (!satisfied) {
      throw new ForbiddenError("None of the required conditions are met");
    }
  };
}

/** Require all given requirements to be satisfied. */
export function requireAll(...requirements: Requirement[]): GuardCheck {
  return (ctx) => {
    if (!ctx.isAuthenticated()) throw new UnauthorizedError();
    for (const r of requirements) {
      if (!r.evaluate(ctx)) {
        throw new ForbiddenError("Not all required conditions are met");
      }
    }
  };
}

/** Require that a composite Requirement is satisfied. */
export function guard(requirement: Requirement): GuardCheck {
  return (ctx) => {
    if (!ctx.isAuthenticated()) throw new UnauthorizedError();
    if (!requirement.evaluate(ctx)) {
      throw new ForbiddenError("Requirement not satisfied");
    }
  };
}

/** Require the user to be in a specific tenant level. */
export function requireTenant(opts: { level: string }): GuardCheck {
  return (ctx) => {
    if (!ctx.isAuthenticated()) throw new UnauthorizedError();
    const id = ctx.atLevel(opts.level);
    if (id === undefined || id === "") {
      throw new ForbiddenError(`Not in tenant level: ${opts.level}`);
    }
  };
}

/** Custom policy guard — pass a predicate function. */
export function policy(check: (ctx: AuthContext) => boolean): GuardCheck {
  return (ctx) => {
    if (!ctx.isAuthenticated()) throw new UnauthorizedError();
    if (!check(ctx)) {
      throw new ForbiddenError("Policy check failed");
    }
  };
}

/** Require authentication only (no specific permission). */
export function requireAuth(): GuardCheck {
  return (ctx) => {
    if (!ctx.isAuthenticated()) throw new UnauthorizedError();
  };
}
