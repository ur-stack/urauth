/**
 * Composable requirements — base class with .and() / .or() composition.
 *
 * All primitives (Permission, Role, Relation) extend Requirement.
 */

import type { AuthContext } from "../context.js";

/** Base for composable auth requirements. */
export abstract class Requirement {
  abstract evaluate(ctx: AuthContext): boolean;

  /** Combine with AND — all requirements must be satisfied. */
  and(other: Requirement): AllOf {
    const left = this instanceof AllOf ? this.requirements : [this];
    const right = other instanceof AllOf ? other.requirements : [other];
    return new AllOf([...left, ...right]);
  }

  /** Combine with OR — any requirement must be satisfied. */
  or(other: Requirement): AnyOf {
    const left = this instanceof AnyOf ? this.requirements : [this];
    const right = other instanceof AnyOf ? other.requirements : [other];
    return new AnyOf([...left, ...right]);
  }
}

/** Composite: all requirements must be satisfied (AND). */
export class AllOf extends Requirement {
  readonly requirements: Requirement[];

  constructor(requirements: Requirement[]) {
    super();
    this.requirements = requirements;
  }

  evaluate(ctx: AuthContext): boolean {
    return this.requirements.every((r) => r.evaluate(ctx));
  }
}

/** Composite: any requirement must be satisfied (OR). */
export class AnyOf extends Requirement {
  readonly requirements: Requirement[];

  constructor(requirements: Requirement[]) {
    super();
    this.requirements = requirements;
  }

  evaluate(ctx: AuthContext): boolean {
    return this.requirements.some((r) => r.evaluate(ctx));
  }
}

/** Convenience: combine requirements with AND. */
export function allOf(...reqs: Requirement[]): AllOf {
  return new AllOf(reqs);
}

/** Convenience: combine requirements with OR. */
export function anyOf(...reqs: Requirement[]): AnyOf {
  return new AnyOf(reqs);
}
