/**
 * H3 guard handlers — wrap @urauth/node guards into H3 event handlers.
 */

import type { EventHandler } from "h3";
import {
  guard as guardFn,
  requirePermission as _requirePermission,
  requireRole as _requireRole,
  requireAuth as _requireAuth,
  requireTenant as _requireTenant,
  policy as _policy,
} from "@urauth/node";
import type { AuthContext, Requirement } from "@urauth/ts";
import "./types";

/** Require authentication only. */
export function requireAuth(): EventHandler {
  const check = _requireAuth();
  return (event) => {
    check(event.context.auth);
  };
}

/** Require a specific permission. */
export function requirePermission(resource: string, action: string): EventHandler {
  const check = _requirePermission(resource, action);
  return (event) => {
    check(event.context.auth);
  };
}

/** Require a specific role. */
export function requireRole(roleName: string): EventHandler {
  const check = _requireRole(roleName);
  return (event) => {
    check(event.context.auth);
  };
}

/** Require a Requirement to be satisfied. */
export function requireGuard(requirement: Requirement): EventHandler {
  const check = guardFn(requirement);
  return (event) => {
    check(event.context.auth);
  };
}

/** Require tenant membership at a specific level. */
export function requireTenant(opts: { level: string }): EventHandler {
  const check = _requireTenant(opts);
  return (event) => {
    check(event.context.auth);
  };
}

/** Custom policy guard. */
export function requirePolicy(check: (ctx: AuthContext) => boolean): EventHandler {
  const guardCheck = _policy(check);
  return (event) => {
    guardCheck(event.context.auth);
  };
}
