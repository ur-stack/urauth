/**
 * RoleRegistry — composable, role management with optional DB loading.
 */

import { RoleExpandingChecker } from "./checker";
import type { Permission } from "./primitives";

/** Protocol for loading roles from an external source (database, API, etc.). */
export interface RoleLoader {
  loadRoles(): Promise<Map<string, Set<string>>>;
  loadHierarchy(): Promise<Map<string, string[]>>;
}

/** Protocol for caching role data. */
export interface RoleCache {
  get(key: string): Promise<Record<string, unknown> | undefined>;
  set(key: string, value: Record<string, unknown>, ttl: number): Promise<void>;
  invalidate(key: string): Promise<void>;
}

/** In-memory cache with TTL tracking. */
export class MemoryRoleCache implements RoleCache {
  private store = new Map<string, { value: Record<string, unknown>; expiresAt: number }>();

  async get(key: string): Promise<Record<string, unknown> | undefined> {
    const entry = this.store.get(key);
    if (!entry) return undefined;
    if (performance.now() > entry.expiresAt) {
      this.store.delete(key);
      return undefined;
    }
    return entry.value;
  }

  async set(key: string, value: Record<string, unknown>, ttl: number): Promise<void> {
    this.store.set(key, { value, expiresAt: performance.now() + ttl * 1000 });
  }

  async invalidate(key: string): Promise<void> {
    this.store.delete(key);
  }
}

/**
 * Composable registry for role definitions.
 *
 * Supports static roles, merging via `include()`, and DB-loaded roles with caching.
 */
export class RoleRegistry {
  private static CACHE_KEY_ROLES = "role_permissions";
  private static CACHE_KEY_HIERARCHY = "role_hierarchy";

  private staticRoles = new Map<string, Set<string>>();
  private staticHierarchy = new Map<string, string[]>();
  private loadedRoles = new Map<string, Set<string>>();
  private loadedHierarchy = new Map<string, string[]>();
  private loader: RoleLoader | undefined;
  private cache: RoleCache | undefined;
  private cacheTtl = 300;

  /** Register a static role. */
  role(
    name: string,
    permissions: Array<string | Permission>,
    options?: { inherits?: string[] },
  ): void {
    this.staticRoles.set(name, new Set(permissions.map(String)));
    if (options?.inherits) {
      this.staticHierarchy.set(name, [...options.inherits]);
    }
  }

  /** Merge another registry (additive: permissions union, hierarchy merge). */
  include(other: RoleRegistry): void {
    for (const [name, perms] of other.staticRoles) {
      const existing = this.staticRoles.get(name);
      if (existing) {
        for (const p of perms) existing.add(p);
      } else {
        this.staticRoles.set(name, new Set(perms));
      }
    }
    for (const [name, children] of other.staticHierarchy) {
      const existing = this.staticHierarchy.get(name);
      if (existing) {
        const set = new Set(existing);
        for (const c of children) set.add(c);
        this.staticHierarchy.set(name, [...set]);
      } else {
        this.staticHierarchy.set(name, [...children]);
      }
    }
  }

  /** Configure DB loading with optional caching. */
  withLoader(loader: RoleLoader, options?: { cache?: RoleCache; cacheTtl?: number }): void {
    this.loader = loader;
    this.cache = options?.cache;
    this.cacheTtl = options?.cacheTtl ?? 300;
  }

  /** Load roles from the configured loader (via cache if available). */
  async load(): Promise<void> {
    if (!this.loader) return;

    let roles: Map<string, Set<string>> | undefined;
    let hierarchy: Map<string, string[]> | undefined;

    if (this.cache) {
      const cachedRoles = await this.cache.get(RoleRegistry.CACHE_KEY_ROLES);
      const cachedHierarchy = await this.cache.get(RoleRegistry.CACHE_KEY_HIERARCHY);
      if (cachedRoles && cachedHierarchy) {
        roles = new Map(
          Object.entries(cachedRoles).map(([k, v]) => [k, new Set(v as string[])]),
        );
        hierarchy = new Map(
          Object.entries(cachedHierarchy).map(([k, v]) => [k, v as string[]]),
        );
      }
    }

    if (!roles) {
      roles = await this.loader.loadRoles();
      hierarchy = await this.loader.loadHierarchy();
      if (this.cache) {
        const rolesObj: Record<string, string[]> = {};
        for (const [k, v] of roles) rolesObj[k] = [...v];
        const hierObj: Record<string, string[]> = {};
        for (const [k, v] of (hierarchy ?? new Map())) hierObj[k] = v;
        await this.cache.set(RoleRegistry.CACHE_KEY_ROLES, rolesObj, this.cacheTtl);
        await this.cache.set(RoleRegistry.CACHE_KEY_HIERARCHY, hierObj, this.cacheTtl);
      }
    }

    this.loadedRoles = roles;
    this.loadedHierarchy = hierarchy ?? new Map();
  }

  /** Invalidate cache and re-load from the loader. */
  async reload(): Promise<void> {
    if (this.cache) {
      await this.cache.invalidate(RoleRegistry.CACHE_KEY_ROLES);
      await this.cache.invalidate(RoleRegistry.CACHE_KEY_HIERARCHY);
    }
    await this.load();
  }

  private mergedRoles(): Map<string, Set<string>> {
    const merged = new Map(this.loadedRoles);
    for (const [name, perms] of this.staticRoles) {
      merged.set(name, perms); // static wins
    }
    return merged;
  }

  private mergedHierarchy(): Map<string, string[]> {
    const merged = new Map(this.loadedHierarchy);
    for (const [name, children] of this.staticHierarchy) {
      merged.set(name, children); // static wins
    }
    return merged;
  }

  /** Produce a configured RoleExpandingChecker from current state. */
  buildChecker(): RoleExpandingChecker {
    return new RoleExpandingChecker({
      rolePermissions: this.mergedRoles(),
      hierarchy: this.mergedHierarchy(),
    });
  }
}
