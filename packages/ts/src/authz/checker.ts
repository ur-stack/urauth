/**
 * Checker-based access control — the single concept for authorization.
 */

import type { AuthContext } from "../context";

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
 * Supports:
 * - Exact match: "user:read"
 * - Wildcard: "*" grants everything
 * - Resource wildcard: "user:*" grants all actions on "user"
 */
export class StringChecker implements AsyncPermissionChecker {
  private separator: string;

  constructor(options?: { separator?: string }) {
    this.separator = options?.separator ?? ":";
  }

  async hasPermission(
    ctx: AuthContext,
    resource: string,
    action: string,
    options?: { scope?: string },
  ): Promise<boolean> {
    const required = `${resource}${this.separator}${action}`;

    let perms = ctx.permissions.map((p) => p.toString());

    if (options?.scope != null && ctx.scopes.has(options.scope)) {
      perms = ctx.scopes.get(options.scope)!.map((p) => p.toString());
    }

    for (const perm of perms) {
      if (perm === "*") return true;
      if (perm === required) return true;
      if (perm.endsWith(`${this.separator}*`)) {
        const prefix = perm.slice(0, -(this.separator.length + 1));
        if (prefix === resource) return true;
      }
    }
    return false;
  }
}

/**
 * Expands roles via hierarchy, maps to permission strings, then checks.
 */
export class RoleExpandingChecker implements AsyncPermissionChecker {
  private rolePermissions: Map<string, Set<string>>;
  private hierarchy: Map<string, string[]>;
  private separator: string;
  private expanded = new Map<string, Set<string>>();

  constructor(options: {
    rolePermissions: Map<string, Set<string>>;
    hierarchy?: Map<string, string[]>;
    separator?: string;
  }) {
    this.rolePermissions = options.rolePermissions;
    this.hierarchy = options.hierarchy ?? new Map();
    this.separator = options.separator ?? ":";
    this.buildExpansion();
  }

  private buildExpansion(): void {
    for (const role of this.hierarchy.keys()) {
      this.expand(role);
    }
  }

  private expand(role: string): Set<string> {
    const cached = this.expanded.get(role);
    if (cached) return cached;

    const result = new Set<string>([role]);
    for (const child of this.hierarchy.get(role) ?? []) {
      for (const r of this.expand(child)) {
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

  async hasPermission(
    ctx: AuthContext,
    resource: string,
    action: string,
    options?: { scope?: string },
  ): Promise<boolean> {
    const roleNames = ctx.roles.map((r) => r.name);
    const effective = this.effectiveRoles(roleNames);
    const perms = this.permissionsForRoles(effective);

    // Also include direct permissions from context
    for (const p of ctx.permissions) {
      perms.add(p.toString());
    }

    const required = `${resource}${this.separator}${action}`;

    if (perms.has("*")) return true;
    if (perms.has(required)) return true;
    if (perms.has(`${resource}${this.separator}*`)) return true;
    return false;
  }
}
