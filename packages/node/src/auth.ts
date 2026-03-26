/**
 * Auth — central orchestration class for urauth Node.js backend.
 *
 * Uses callback-based configuration (idiomatic JS) rather than
 * Python-style class inheritance.
 */

import {
  AuthContext,
  Permission,
  Role,
  TenantPath,
  UnauthorizedError,
} from "@urauth/ts";
import type { TokenPayload ,
  RelationTuple} from "@urauth/ts";
import type { AuthConfig } from "./config";
import { defaultConfig } from "./config";
import type { TokenStore } from "./stores/types";
import { MemoryTokenStore } from "./stores/memory";
import { TokenLifecycle, type IssueRequest, type IssuedTokenPair } from "./lifecycle";
import type { PipelineConfig } from "./pipeline";

export interface AuthCallbacks<TUser = unknown> {
  /** Look up a user by ID. Required. */
  getUser: (userId: string) => Promise<TUser | null | undefined>;

  /** Look up a user by username/email. Required for password auth. */
  getUserByUsername?: (username: string) => Promise<TUser | null | undefined>;

  /** Verify a password against a user. Required for password auth. */
  verifyPassword?: (user: TUser, password: string) => Promise<boolean>;

  /** Get the unique ID from a user object. Defaults to (user as any).id */
  getUserId?: (user: TUser) => string;

  /** Get roles for a user. Returns role name strings. */
  getUserRoles?: (user: TUser) => Promise<string[]> | string[];

  /** Get direct permissions for a user. Returns permission strings. */
  getUserPermissions?: (user: TUser) => Promise<string[]> | string[];

  /** Resolve a Zanzibar relation for a user. */
  resolveRelation?: (
    user: TUser,
    relation: string,
    resource: string,
    resourceId: string,
  ) => Promise<boolean>;

  /** Resolve the tenant path for a user (multi-tenant). */
  resolveTenantPath?: (
    user: TUser,
    payload: TokenPayload,
  ) => Promise<Record<string, string>> | Record<string, string>;

  /** Get tenant-scoped permissions for a user. */
  getTenantPermissions?: (
    user: TUser,
    level: string,
    tenantId: string,
  ) => Promise<string[]> | string[];
}

export interface AuthOptions<TUser = unknown> extends AuthCallbacks<TUser> {
  config: AuthConfig;
  tokenStore?: TokenStore;
  pipeline?: PipelineConfig;
}

export class Auth<TUser = unknown> {
  readonly config: AuthConfig;
  readonly lifecycle: TokenLifecycle;
  readonly pipeline: PipelineConfig | undefined;
  private callbacks: AuthCallbacks<TUser>;
  private tokenStore: TokenStore;

  constructor(options: AuthOptions<TUser>) {
    this.config = { ...defaultConfig, ...options.config } as AuthConfig;
    this.tokenStore = options.tokenStore ?? new MemoryTokenStore();
    this.lifecycle = new TokenLifecycle(this.config, this.tokenStore);
    this.pipeline = options.pipeline;
    this.callbacks = options;
  }

  /** Build an AuthContext from a raw JWT string. */
  async buildContext(
    rawToken: string | null | undefined,
    options?: { optional?: boolean },
  ): Promise<AuthContext> {
    if (rawToken === null || rawToken === undefined || rawToken === "") {
      if (options?.optional === true) return AuthContext.anonymous();
      throw new UnauthorizedError();
    }

    try {
      const payload = await this.lifecycle.validate(rawToken);
      return await this.buildContextFromPayload(payload);
    } catch (err) {
      if (options?.optional === true) return AuthContext.anonymous();
      throw err;
    }
  }

  /** Build an AuthContext directly from a user object (for testing / internal). */
  async buildContextForUser(user: TUser): Promise<AuthContext> {
    const roles = await this.resolveRoles(user);
    const permissions = await this.resolvePermissions(user);

    return new AuthContext({
      user,
      roles: roles.map((r) => new Role(r)),
      permissions: permissions.map((p) => new Permission(p)),
      authenticated: true,
    });
  }

  /** Authenticate with username + password, return issued tokens. */
  async authenticate(username: string, password: string): Promise<IssuedTokenPair> {
    if (!this.callbacks.getUserByUsername) {
      throw new Error("getUserByUsername callback is required for password auth");
    }
    if (!this.callbacks.verifyPassword) {
      throw new Error("verifyPassword callback is required for password auth");
    }

    const user = await this.callbacks.getUserByUsername(username);
    if (!user) throw new UnauthorizedError("Invalid credentials");

    const valid = await this.callbacks.verifyPassword(user, password);
    if (!valid) throw new UnauthorizedError("Invalid credentials");

    const uid = this.getUserId(user);
    const roles = await this.resolveRoles(user);

    const request: IssueRequest = {
      userId: uid,
      roles,
      fresh: true,
    };

    // Resolve tenant path if configured
    if (this.callbacks.resolveTenantPath) {
      // Create a minimal payload for tenant resolution
      const tenantPath = await this.callbacks.resolveTenantPath(user, {} as TokenPayload);
      if (Object.keys(tenantPath).length > 0) {
        request.tenantPath = tenantPath;
      }
    }

    return this.lifecycle.issue(request);
  }

  // ── Private helpers ─────────────────────────────────────────────

  private getUserId(user: TUser): string {
    if (this.callbacks.getUserId) return this.callbacks.getUserId(user);
    return String((user as Record<string, unknown>).id);
  }

  private async resolveRoles(user: TUser): Promise<string[]> {
    if (!this.callbacks.getUserRoles) return [];
    return Promise.resolve(this.callbacks.getUserRoles(user));
  }

  private async resolvePermissions(user: TUser): Promise<string[]> {
    if (!this.callbacks.getUserPermissions) return [];
    return Promise.resolve(this.callbacks.getUserPermissions(user));
  }

  private async buildContextFromPayload(payload: TokenPayload): Promise<AuthContext> {
    const user = await this.callbacks.getUser(payload.sub);
    if (!user) throw new UnauthorizedError("User not found");

    const roleNames = payload.roles ?? (await this.resolveRoles(user));
    const roles = roleNames.map((r) => new Role(r));

    const permStrings = payload.permissions ?? (await this.resolvePermissions(user));
    const permissions = permStrings.map((p) => new Permission(p));

    // Resolve relations if callback provided
    const relations: RelationTuple[] = [];

    // Resolve tenant
    let tenant: TenantPath | undefined;
    if (payload.tenant_path !== undefined) {
      tenant = TenantPath.fromClaim(payload.tenant_path);
    } else if (payload.tenant_id !== undefined) {
      tenant = TenantPath.fromFlat(payload.tenant_id);
    }

    return new AuthContext({
      user,
      roles,
      permissions,
      relations,
      token: payload,
      tenant,
      authenticated: true,
    });
  }
}
