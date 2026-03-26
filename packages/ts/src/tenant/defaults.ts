/**
 * Default role templates for tenant levels.
 *
 * Allows defining what roles are auto-created when a new tenant is provisioned:
 *
 *     const defaults = new TenantDefaults();
 *     defaults.register("organization", [
 *       new RoleTemplate("employees", ["org:read"]),
 *       new RoleTemplate("clients", ["org:read:public"]),
 *     ]);
 *     defaults.register("group", [
 *       new RoleTemplate("group_admin", ["group:*"]),
 *       new RoleTemplate("group_member", ["group:read"]),
 *     ]);
 *
 *     await defaults.provision("org-123", "organization", provisioner);
 */

import type { TenantRoleProvisioner } from "./types";

/** Blueprint for a default role to create in a new tenant. */
export class RoleTemplate {
  readonly name: string;
  readonly permissions: string[];
  readonly description: string;

  constructor(name: string, permissions: string[] = [], description = "") {
    this.name = name;
    this.permissions = permissions;
    this.description = description;
  }
}

/** Registry mapping tenant level names to default role templates. */
export class TenantDefaults {
  private _registry = new Map<string, RoleTemplate[]>();

  /** Register default role templates for a tenant level. Replaces previous templates for this level. */
  register(level: string, templates: RoleTemplate[]): void {
    this._registry.set(level, [...templates]);
  }

  /** Get the registered templates for a level, or empty array. */
  templatesFor(level: string): RoleTemplate[] {
    return [...(this._registry.get(level) ?? [])];
  }

  /** Create default roles for a tenant using the provisioner. */
  async provision(
    tenantId: string,
    level: string,
    provisioner: TenantRoleProvisioner,
  ): Promise<void> {
    const templates = this._registry.get(level);
    if (templates) {
      await provisioner.provision(tenantId, level, templates);
    }
  }

  /** Return all registered level names. */
  get levels(): string[] {
    return [...this._registry.keys()];
  }
}
