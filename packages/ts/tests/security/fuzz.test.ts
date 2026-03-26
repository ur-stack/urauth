/**
 * Property-based / fuzz tests for @urauth/ts.
 *
 * Uses fast-check to verify invariants with randomly generated inputs.
 */

import { describe, test, expect } from "bun:test";
import fc from "fast-check";
import { Permission, matchPermission, Role, Relation, RelationTuple } from "../../src/authz/primitives";
import { AuthContext } from "../../src/context";
import { AllOf, AnyOf } from "../../src/authz/requirement";

describe("Permission parsing fuzz", () => {
  test("arbitrary strings never crash Permission constructor", () => {
    fc.assert(
      fc.property(fc.string({ minLength: 0, maxLength: 200 }), (s) => {
        try {
          const p = new Permission(s);
          // If it succeeds, toString should not throw
          p.toString();
        } catch (e) {
          // Only ValueError/Error is acceptable
          expect(e).toBeInstanceOf(Error);
        }
      }),
      { numRuns: 500 },
    );
  });

  test("two-arg Permission always produces valid resource:action", () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 50 }),
        fc.string({ minLength: 1, maxLength: 50 }),
        (resource, action) => {
          const p = new Permission(resource, action);
          expect(p.resource).toBe(resource);
          expect(p.action).toBe(action);
        },
      ),
      { numRuns: 300 },
    );
  });

  test("Permission equality is reflexive", () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 30 }),
        fc.string({ minLength: 1, maxLength: 30 }),
        (resource, action) => {
          const p1 = new Permission(resource, action);
          const p2 = new Permission(resource, action);
          expect(p1.equals(p2)).toBe(true);
        },
      ),
      { numRuns: 200 },
    );
  });
});

describe("matchPermission invariants", () => {
  test("wildcard '*' always matches any permission", () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 30 }),
        fc.string({ minLength: 1, maxLength: 30 }),
        (resource, action) => {
          const wildcard = new Permission("*", "*");
          const target = new Permission(resource, action);
          expect(matchPermission(wildcard, target)).toBe(true);
        },
      ),
      { numRuns: 200 },
    );
  });

  test("exact match always succeeds", () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 30 }),
        fc.string({ minLength: 1, maxLength: 30 }),
        (resource, action) => {
          const p = new Permission(resource, action);
          expect(matchPermission(p, p)).toBe(true);
        },
      ),
      { numRuns: 200 },
    );
  });

  test("different resource never matches (unless wildcard)", () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 20 }),
        fc.string({ minLength: 1, maxLength: 20 }),
        fc.string({ minLength: 1, maxLength: 20 }),
        (r1, r2, action) => {
          fc.pre(r1 !== r2 && r1 !== "*");
          const pattern = new Permission(r1, action);
          const target = new Permission(r2, action);
          expect(matchPermission(pattern, target)).toBe(false);
        },
      ),
      { numRuns: 200 },
    );
  });
});

describe("RelationTuple parsing fuzz", () => {
  test("arbitrary strings never crash RelationTuple.parse", () => {
    fc.assert(
      fc.property(fc.string({ minLength: 0, maxLength: 200 }), (s) => {
        try {
          RelationTuple.parse(s);
        } catch (e) {
          expect(e).toBeInstanceOf(Error);
        }
      }),
      { numRuns: 500 },
    );
  });
});

describe("AuthContext property-based", () => {
  test("context with no user is never authenticated", () => {
    fc.assert(
      fc.property(
        fc.array(fc.string({ minLength: 1, maxLength: 20 }), { maxLength: 5 }),
        (roleNames) => {
          const ctx = new AuthContext({
            roles: roleNames.map((n) => new Role(n)),
          });
          expect(ctx.isAuthenticated()).toBe(false);
        },
      ),
      { numRuns: 100 },
    );
  });

  test("context with user is always authenticated unless explicitly disabled", () => {
    fc.assert(
      fc.property(fc.string({ minLength: 1, maxLength: 50 }), (userId) => {
        const ctx = new AuthContext({ user: { id: userId } });
        expect(ctx.isAuthenticated()).toBe(true);
      }),
      { numRuns: 100 },
    );
  });

  test("hasPermission is consistent with permissions array", () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 20 }),
        fc.string({ minLength: 1, maxLength: 20 }),
        fc.string({ minLength: 1, maxLength: 20 }),
        (resource, grantedAction, queriedAction) => {
          fc.pre(grantedAction !== "*" && resource !== "*");
          const granted = new Permission(resource, grantedAction);
          const ctx = new AuthContext({
            user: { id: "u1" },
            permissions: [granted],
          });
          const queried = new Permission(resource, queriedAction);
          if (grantedAction === queriedAction) {
            expect(ctx.hasPermission(queried)).toBe(true);
          }
        },
      ),
      { numRuns: 200 },
    );
  });
});

describe("Requirement composition invariants", () => {
  test("AllOf with single requirement equals that requirement", () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 20 }),
        fc.string({ minLength: 1, maxLength: 20 }),
        (resource, action) => {
          const perm = new Permission(resource, action);
          const ctx = new AuthContext({
            user: { id: "u1" },
            permissions: [perm],
          });
          expect(new AllOf([perm]).evaluate(ctx)).toBe(perm.evaluate(ctx));
        },
      ),
      { numRuns: 100 },
    );
  });

  test("AnyOf with single requirement equals that requirement", () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 20 }),
        fc.string({ minLength: 1, maxLength: 20 }),
        (resource, action) => {
          const perm = new Permission(resource, action);
          const ctx = new AuthContext({
            user: { id: "u1" },
            permissions: [perm],
          });
          expect(new AnyOf([perm]).evaluate(ctx)).toBe(perm.evaluate(ctx));
        },
      ),
      { numRuns: 100 },
    );
  });
});
