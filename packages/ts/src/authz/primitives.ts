/**
 * Typed permission primitives — Permission, Role, Relation.
 *
 * Supports boolean composition via .and() / .or():
 *   memberOf.and(editor).or(admin)
 *   canRead.and(canWrite)
 */

import type { AuthContext } from "../context";
import type { Action, Resource } from "../actions";
import { Requirement } from "./requirement";

export type { Action, Resource } from "../actions";

/**
 * A typed permission combining a resource and an action.
 *
 * Compares equal to its string form: `new Permission("user", "read").equals("user:read")`.
 */
export class Permission extends Requirement {
  readonly resource: Resource;
  readonly action: Action;

  constructor(resource: Resource | string, action: Action | string) {
    super();
    this.resource = resource as Resource;
    this.action = action as Action;
  }

  evaluate(ctx: AuthContext): boolean {
    return ctx.hasPermission(this);
  }

  toString(): string {
    return `${this.resource}:${this.action}`;
  }

  equals(other: Permission | string): boolean {
    const otherStr = typeof other === "string" ? other : other.toString();
    return this.toString() === otherStr;
  }
}

/**
 * Static role definition with associated permissions.
 *
 * Compares equal to its name string: `new Role("admin").equals("admin")`.
 */
export class Role extends Requirement {
  readonly name: string;
  readonly permissions: Permission[];

  constructor(name: string, permissions?: Permission[]) {
    super();
    this.name = name;
    this.permissions = permissions ?? [];
  }

  evaluate(ctx: AuthContext): boolean {
    return ctx.hasRole(this);
  }

  toString(): string {
    return this.name;
  }

  equals(other: Role | string): boolean {
    const otherName = typeof other === "string" ? other : other.name;
    return this.name === otherName;
  }
}

/**
 * Zanzibar-style relation definition.
 *
 * String form: `"resource#name"` (e.g., `new Relation("owner", "post")` → `"post#owner"`).
 *
 * When used in a composite requirement (via `evaluate`), checks if the
 * relation exists for ANY resource ID in the context.
 */
export class Relation extends Requirement {
  readonly name: string;
  readonly resource: Resource;

  constructor(name: string, resource: Resource | string) {
    super();
    this.name = name;
    this.resource = resource as Resource;
  }

  evaluate(ctx: AuthContext): boolean {
    return ctx.relations.some(([r]) => r.name === this.name && r.resource === this.resource);
  }

  toString(): string {
    return `${this.resource}#${this.name}`;
  }

  equals(other: Relation | string): boolean {
    const otherStr = typeof other === "string" ? other : other.toString();
    return this.toString() === otherStr;
  }
}
