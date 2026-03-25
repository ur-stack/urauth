/**
 * Protocols for tenant hierarchy persistence and role provisioning.
 */

import type { TenantPath } from "./hierarchy";
import type { RoleTemplate } from "./defaults";

/** Protocol for tenant hierarchy persistence. Implement to back the hierarchy with your database. */
export interface TenantStore {
  /** Get a tenant node by ID. */
  getTenant(tenantId: string): Promise<Record<string, unknown> | undefined>;

  /** Get all ancestors of a tenant, ordered root-first. */
  getAncestors(tenantId: string): Promise<Array<Record<string, unknown>>>;

  /** Get immediate children of a tenant. */
  getChildren(tenantId: string): Promise<Array<Record<string, unknown>>>;

  /** Build a full TenantPath from root to the given tenant. */
  resolvePath(tenantId: string): Promise<TenantPath | undefined>;
}

/** Protocol for creating default roles when a tenant is created. */
export interface TenantRoleProvisioner {
  /** Create roles for a tenant from the given templates. */
  provision(tenantId: string, level: string, templates: RoleTemplate[]): Promise<void>;
}
