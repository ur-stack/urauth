/**
 * AuthContext — holds all auth data for the current user session.
 *
 * Built from a JWT or user object. Provides introspection methods for
 * checking permissions, roles, and relations.
 */

import type { TokenPayload } from "./types";
import type { Requirement } from "./authz/requirement";
import { Permission, Role, Relation, RelationTuple, matchPermission } from "./authz/primitives";
import type { TenantPath } from "./tenant/hierarchy";

export interface AuthContextOptions {
  user?: unknown;
  roles?: Role[];
  permissions?: Permission[];
  relations?: RelationTuple[];
  scopes?: Map<string, Permission[]>;
  token?: TokenPayload;
  request?: unknown;
  tenant?: TenantPath;
  authenticated?: boolean;
}

export class AuthContext {
  readonly user: unknown;
  readonly roles: Role[];
  readonly permissions: Permission[];
  readonly relations: RelationTuple[];
  readonly scopes: Map<string, Permission[]>;
  readonly token: TokenPayload | undefined;
  readonly request: unknown;
  readonly tenant: TenantPath | undefined;
  private _authenticated: boolean;

  constructor(opts: AuthContextOptions = {}) {
    this.user = opts.user ?? null;
    this.roles = opts.roles ?? [];
    this.permissions = opts.permissions ?? [];
    this.relations = opts.relations ?? [];
    this.scopes = opts.scopes ?? new Map();
    this.token = opts.token;
    this.request = opts.request;
    this.tenant = opts.tenant;
    this._authenticated = opts.authenticated ?? true;
  }

  /** Create an anonymous (unauthenticated) context. */
  static anonymous(opts?: { request?: unknown }): AuthContext {
    return new AuthContext({
      user: null,
      authenticated: false,
      request: opts?.request,
    });
  }

  isAuthenticated(): boolean {
    return this._authenticated && this.user != null;
  }

  /** Check if the context holds a permission (supports wildcards). Comparison is semantic — separator-agnostic. */
  hasPermission(permission: Permission | string): boolean {
    const target = typeof permission === "string" ? new Permission(permission) : permission;
    return this.permissions.some((p) => matchPermission(p, target));
  }

  /** Check if the context holds a specific role. */
  hasRole(role: Role | string): boolean {
    const name = role instanceof Role ? role.name : String(role);
    return this.roles.some((r) => r.name === name);
  }

  /** Check if the context holds any of the given roles. */
  hasAnyRole(...roles: Array<Role | string>): boolean {
    return roles.some((r) => this.hasRole(r));
  }

  /** Check if the context holds a specific Zanzibar relation to a resource. */
  hasRelation(relation: Relation, resourceId: string): boolean {
    return this.relations.some(
      (rt) => rt.relation.equals(relation) && rt.objectId === resourceId,
    );
  }

  /** Evaluate a (possibly composite) requirement against this context. */
  satisfies(requirement: Requirement): boolean {
    return requirement.evaluate(this);
  }

  /** The leaf tenant ID (backward compat with flat tenant_id). */
  get tenantId(): string | undefined {
    if (this.tenant !== undefined) return this.tenant.leafId;
    return this.token?.tenant_id;
  }

  /** Check if the current context is within a specific tenant (at any level). */
  inTenant(tenantId: string): boolean {
    if (this.tenant === undefined) return false;
    return this.tenant.isDescendantOf(tenantId);
  }

  /** Get the tenant ID at a specific hierarchy level. */
  atLevel(level: string): string | undefined {
    if (this.tenant === undefined) return undefined;
    return this.tenant.idAt(level);
  }
}
