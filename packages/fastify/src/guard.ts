/**
 * Fastify guard hooks.
 */

import type { preHandlerHookHandler } from "fastify";
import {
  guard as guardFn,
  requireAuth,
  requireTenant,
  policy as policyFn,
} from "@urauth/node";
import type { AuthContext, Requirement } from "@urauth/ts";
import "./types";

/** Create a preHandler hook that checks a requirement. */
export function createGuard(requirement: Requirement): preHandlerHookHandler {
  const check = guardFn(requirement);
  return (request, _reply, done) => {
    try {
      check(request.auth, request);
      done();
    } catch (err) {
      done(err as Error);
    }
  };
}

/** Create a preHandler hook that requires authentication. */
export function createProtect(): preHandlerHookHandler {
  const check = requireAuth();
  return (request, _reply, done) => {
    try {
      check(request.auth, request);
      done();
    } catch (err) {
      done(err as Error);
    }
  };
}

/** Create a preHandler hook for tenant guard. */
export function createTenantGuard(opts: { level: string }): preHandlerHookHandler {
  const check = requireTenant(opts);
  return (request, _reply, done) => {
    try {
      check(request.auth, request);
      done();
    } catch (err) {
      done(err as Error);
    }
  };
}

/** Create a preHandler hook for a custom policy. */
export function createPolicyGuard(check: (ctx: AuthContext) => boolean): preHandlerHookHandler {
  const guardCheck = policyFn(check);
  return (request, _reply, done) => {
    try {
      guardCheck(request.auth, request);
      done();
    } catch (err) {
      done(err as Error);
    }
  };
}
