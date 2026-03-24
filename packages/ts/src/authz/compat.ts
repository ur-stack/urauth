/**
 * canAccess() — convenience function for sync permission checks.
 */

import type { AuthContext } from "../context";
import { Permission } from "./primitives";

/** Sync permission checker interface. */
export interface PermissionChecker {
  hasPermission(
    ctx: AuthContext,
    resource: string,
    action: string,
    options?: { scope?: string },
  ): boolean;
}

/**
 * Check if an AuthContext has permission for a resource+action.
 * Accepts either a Permission object or (resource, action) strings.
 */
export function canAccess(
  ctx: AuthContext,
  resourceOrPermission: string | Permission,
  action?: string,
  options?: { scope?: string; checker?: PermissionChecker },
): boolean {
  let resource: string;
  let actionStr: string;

  if (resourceOrPermission instanceof Permission) {
    resource = resourceOrPermission.resource;
    actionStr = resourceOrPermission.action;
  } else {
    resource = resourceOrPermission;
    actionStr = action!;
  }

  if (options?.checker) {
    return options.checker.hasPermission(ctx, resource, actionStr, options);
  }

  // Handle scope
  if (options?.scope && ctx.scopes.has(options.scope)) {
    const scopePerms = ctx.scopes.get(options.scope)!;
    const required = `${resource}:${actionStr}`;
    for (const p of scopePerms) {
      const pStr = p.toString();
      if (pStr === "*") return true;
      if (pStr === required) return true;
      if (pStr.endsWith(":*") && pStr.slice(0, -2) === resource) return true;
    }
    return false;
  }

  return ctx.hasPermission(new Permission(resource, actionStr));
}
