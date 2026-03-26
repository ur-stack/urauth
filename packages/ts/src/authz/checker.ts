/**
 * Checker-based access control — the single concept for authorization.
 */

import type { AuthContext } from "../context";
import { Permission, matchPermission } from "./primitives";

/** Async permission checker interface (AuthContext-based) for server-side use. */
export interface AsyncPermissionChecker {
  hasPermission(
    ctx: AuthContext,
    resource: string,
    action: string,
    options?: { scope?: string },
  ): Promise<boolean>;
}

/**
 * Default checker — matches "resource:action" against context permissions.
 *
 * Comparison is semantic (separator-agnostic):
 * - Exact match: "user:read" matches "user.read"
 * - Wildcard: "*" grants everything
 * - Resource wildcard: "user:*" grants all actions on "user"
 */
export class StringChecker implements AsyncPermissionChecker {
  hasPermission(
    ctx: AuthContext,
    resource: string,
    action: string,
    options?: { scope?: string },
  ): Promise<boolean> {
    const required = new Permission(resource, action);

    let perms: Permission[];
    if (options?.scope !== undefined && ctx.scopes.has(options.scope)) {
      perms = ctx.scopes.get(options.scope) ?? [];
    } else {
      perms = ctx.permissions;
    }

    return Promise.resolve(perms.some((p) => matchPermission(p, required)));
  }
}

/**
 * Expands roles via hierarchy, maps to permission strings, then checks.
 */
export class RoleExpandingChecker implements AsyncPermissionChecker {
  private rolePermissions: Map<string, Set<string>>;
  private hierarchy: Map<string, string[]>;
  private expanded = new Map<string, Set<string>>();

  constructor(options: {
    rolePermissions: Map<string, Set<string>>;
    hierarchy?: Map<string, string[]>;
  }) {
    this.rolePermissions = options.rolePermissions;
    this.hierarchy = options.hierarchy ?? new Map<string, string[]>();
    this.buildExpansion();
  }

  private buildExpansion(): void {
    for (const role of this.hierarchy.keys()) {
      this.expand(role);
    }
  }

  private expand(role: string, visiting = new Set<string>()): Set<string> {
    const cached = this.expanded.get(role);
    if (cached) return cached;

    if (visiting.has(role)) {
      // Circular dependency detected — break the cycle
      return new Set<string>([role]);
    }
    visiting.add(role);

    const result = new Set<string>([role]);
    for (const child of this.hierarchy.get(role) ?? []) {
      for (const r of this.expand(child, visiting)) {
        result.add(r);
      }
    }
    this.expanded.set(role, result);
    return result;
  }

  /** Return all roles a user effectively holds, including inherited ones. */
  effectiveRoles(userRoles: string[]): Set<string> {
    const result = new Set<string>();
    for (const role of userRoles) {
      const exp = this.expanded.get(role);
      if (exp) {
        for (const r of exp) result.add(r);
      } else {
        result.add(role);
      }
    }
    return result;
  }

  private permissionsForRoles(roles: Set<string>): Set<string> {
    const result = new Set<string>();
    for (const role of roles) {
      for (const p of this.rolePermissions.get(role) ?? []) {
        result.add(p);
      }
    }
    return result;
  }

  hasPermission(
    ctx: AuthContext,
    resource: string,
    action: string,
  ): Promise<boolean> {
    const roleNames = ctx.roles.map((r) => r.name);
    const effective = this.effectiveRoles(roleNames);
    const perms = this.permissionsForRoles(effective);

    // Also include direct permissions from context
    for (const p of ctx.permissions) {
      perms.add(p.toString());
    }

    const required = new Permission(resource, action);
    for (const permStr of perms) {
      if (matchPermission(new Permission(permStr), required)) return Promise.resolve(true);
    }
    return Promise.resolve(false);
  }
}
