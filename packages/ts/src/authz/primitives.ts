/**
 * Typed permission primitives — Permission, Role, Relation, RelationTuple.
 *
 * Supports boolean composition via .and() / .or():
 *   memberOf.and(editor).or(admin)
 *   canRead.and(canWrite)
 *
 * Permission format is separator-agnostic — "user:read" and "user.read"
 * are semantically equal. Supported separators: @ # . : | \ / $ &
 */

import type { AuthContext } from "../context";
import type { Action, Resource } from "../actions";
import { Requirement } from "./requirement";

export type { Action, Resource } from "../actions";

// ── Separator auto-detection ──────────────────────────────────────

const SEP_RE = /[@#.:|\\/$&]/;

// ── Shared permission matching ────────────────────────────────────

/**
 * Check if a permission pattern matches a target permission.
 *
 * Performs semantic (resource, action) comparison — separator-agnostic.
 *
 * Supports:
 * - Exact match: `"user:read"` matches `"user.read"`
 * - Global wildcard: `"*"` matches everything
 * - Resource wildcard: `"user:*"` matches `"user:read"`, `"user.write"`, etc.
 */
export function matchPermission(
  pattern: Permission | string,
  target: Permission | string,
): boolean {
  const p = typeof pattern === "string" ? new Permission(pattern) : pattern;
  const t = typeof target === "string" ? new Permission(target) : target;
  if (String(p.resource) === "*") return true;
  if (String(p.resource) !== String(t.resource)) return false;
  return String(p.action) === "*" || String(p.action) === String(t.action);
}

// ── Primitives ──────────────────────────────────────────────────

export type PermissionParser = (s: string) => [string, string];

/**
 * A typed permission combining a resource and an action.
 *
 * Accepts two args, a single string (auto-detects separator), or a custom parser:
 *
 *     new Permission("user", "read")      // two-arg form
 *     new Permission("user:read")          // colon separator (auto-detected)
 *     new Permission("user.read")          // dot separator (auto-detected)
 *     new Permission("*")                  // global wildcard
 *
 * Equality is semantic: `Permission("user:read").equals("user.read")` is true.
 * Supports `&` / `|` composition with other requirements via `.and()` / `.or()`.
 */
export class Permission extends Requirement {
  readonly resource: Resource;
  readonly action: Action;
  private _sep: string;

  constructor(
    resource: Resource | string,
    action?: Action | string,
    options?: { separator?: string; parser?: PermissionParser },
  ) {
    super();
    if (action !== undefined) {
      this.resource = String(resource) as Resource;
      this.action = String(action) as Action;
      this._sep = options?.separator ?? ":";
    } else if (options?.parser) {
      const [r, a] = options.parser(String(resource));
      this.resource = r as Resource;
      this.action = a as Action;
      this._sep = options.separator ?? ":";
    } else {
      const value = String(resource);
      if (value === "*") {
        this.resource = "*" as Resource;
        this.action = "*" as Action;
        this._sep = options?.separator ?? ":";
      } else {
        const m = SEP_RE.exec(value);
        if (!m) {
          throw new Error(
            `No separator found in permission string: "${value}". ` +
              `Use one of: @ # . : | \\ / $ &`,
          );
        }
        const parts = value.split(m[0]!);
        this.resource = parts[0]! as Resource;
        this.action = parts.slice(1).join(m[0]!) as Action;
        this._sep = m[0]!;
      }
    }
  }

  evaluate(ctx: AuthContext): boolean {
    return ctx.hasPermission(this);
  }

  toString(): string {
    return `${this.resource}${this._sep}${this.action}`;
  }

  equals(other: Permission | string): boolean {
    if (typeof other === "string") {
      try {
        const p = new Permission(other);
        return (
          String(this.resource) === String(p.resource) &&
          String(this.action) === String(p.action)
        );
      } catch {
        return false;
      }
    }
    return (
      String(this.resource) === String(other.resource) &&
      String(this.action) === String(other.action)
    );
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

export type RelationParser = (s: string) => [string, string];

/**
 * Zanzibar-style relation definition.
 *
 * Resource-first ordering matches Python and the string form:
 *
 *     new Relation("doc", "owner")     // two-arg form (resource, name)
 *     new Relation("doc#owner")        // string form (auto-detects separator)
 *
 * Equality is semantic: `Relation("doc#owner").equals("doc.owner")` is true.
 * Supports `.and()` / `.or()` composition with other requirements.
 */
export class Relation extends Requirement {
  readonly resource: Resource;
  readonly name: string;
  private _sep: string;

  constructor(
    resource: Resource | string,
    name?: string,
    options?: { separator?: string; parser?: RelationParser },
  ) {
    super();
    if (name !== undefined) {
      this.resource = String(resource) as Resource;
      this.name = String(name);
      this._sep = options?.separator ?? "#";
    } else if (options?.parser) {
      const [r, n] = options.parser(String(resource));
      this.resource = r as Resource;
      this.name = n;
      this._sep = options.separator ?? "#";
    } else {
      const value = String(resource);
      const m = SEP_RE.exec(value);
      if (!m) {
        throw new Error(
          `No separator found in relation string: "${value}". ` +
            `Use one of: @ # . : | \\ / $ &`,
        );
      }
      const parts = value.split(m[0]!);
      this.resource = parts[0]! as Resource;
      this.name = parts.slice(1).join(m[0]!);
      this._sep = m[0]!;
    }
  }

  get separator(): string {
    return this._sep;
  }

  /** Create a full Zanzibar tuple from this relation definition. */
  tuple(objectId: string, subject?: string): RelationTuple {
    return new RelationTuple(this, objectId, subject);
  }

  evaluate(ctx: AuthContext): boolean {
    return ctx.relations.some(
      (rt) => rt.relation.name === this.name && String(rt.relation.resource) === String(this.resource),
    );
  }

  toString(): string {
    return `${this.resource}${this._sep}${this.name}`;
  }

  equals(other: Relation | string): boolean {
    if (typeof other === "string") {
      try {
        const r = new Relation(other);
        return this.name === r.name && String(this.resource) === String(r.resource);
      } catch {
        return false;
      }
    }
    return this.name === other.name && String(this.resource) === String(other.resource);
  }
}

/**
 * Full Zanzibar relationship tuple: `object_type:object_id#relation@subject`.
 *
 *     new RelationTuple(new Relation("doc", "owner"), "readme", "user:alice")
 *     RelationTuple.parse("doc:readme#owner@user:alice")
 */
export class RelationTuple {
  readonly relation: Relation;
  readonly objectId: string;
  readonly subject: string | undefined;

  constructor(relation: Relation, objectId: string, subject?: string) {
    this.relation = relation;
    this.objectId = objectId;
    this.subject = subject;
  }

  /** Parse `'doc:readme#owner@user:alice'` positionally by separator and `@`. */
  static parse(s: string): RelationTuple {
    let left: string;
    let subject: string | undefined;
    if (s.includes("@")) {
      const atIdx = s.indexOf("@");
      left = s.slice(0, atIdx);
      subject = s.slice(atIdx + 1);
    } else {
      left = s;
      subject = undefined;
    }
    // left = "doc:readme#owner"
    const colonPos = left.indexOf(":");
    if (colonPos === -1) {
      throw new Error(`Invalid relation tuple: "${s}"`);
    }
    const objType = left.slice(0, colonPos);
    const rest = left.slice(colonPos + 1); // "readme#owner"
    const m = SEP_RE.exec(rest);
    if (!m) {
      throw new Error(`Invalid relation tuple: "${s}"`);
    }
    const objId = rest.slice(0, m.index);
    const relName = rest.slice(m.index! + m[0]!.length);
    return new RelationTuple(
      new Relation(objType, relName),
      objId,
      subject,
    );
  }

  toString(): string {
    const sep = this.relation.separator;
    const base = `${this.relation.resource}:${this.objectId}${sep}${this.relation.name}`;
    if (this.subject !== undefined) {
      return `${base}@${this.subject}`;
    }
    return base;
  }

  equals(other: RelationTuple | string): boolean {
    if (typeof other === "string") {
      return this.toString() === other;
    }
    return (
      this.relation.equals(other.relation) &&
      this.objectId === other.objectId &&
      this.subject === other.subject
    );
  }
}
