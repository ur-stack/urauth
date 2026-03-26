import { describe, test, expect } from "bun:test";
import { AuthContext } from "../../src/context";
import {
  Permission,
  Role,
  Relation,
  RelationTuple,
} from "../../src/authz/primitives";
import { AllOf, AnyOf } from "../../src/authz/requirement";

describe("AuthContext Security", () => {
  test("default constructor with no user sets authenticated=false", () => {
    const ctx = new AuthContext();
    expect(ctx.isAuthenticated()).toBe(false);
  });

  test("constructor with user sets authenticated=true by default", () => {
    const ctx = new AuthContext({ user: { id: "user-1" } });
    expect(ctx.isAuthenticated()).toBe(true);
  });

  test("anonymous context is not authenticated", () => {
    const ctx = AuthContext.anonymous();
    expect(ctx.isAuthenticated()).toBe(false);
  });

  test("anonymous context has no permissions/roles/relations", () => {
    const ctx = AuthContext.anonymous();
    expect(ctx.permissions).toEqual([]);
    expect(ctx.roles).toEqual([]);
    expect(ctx.relations).toEqual([]);
  });

  test('hasPermission with wildcard "*" pattern grants any permission', () => {
    const ctx = new AuthContext({
      user: { id: "user-1" },
      permissions: [new Permission("*")],
    });
    expect(ctx.hasPermission(new Permission("user", "read"))).toBe(true);
    expect(ctx.hasPermission(new Permission("admin", "delete"))).toBe(true);
    expect(ctx.hasPermission(new Permission("anything", "whatever"))).toBe(
      true,
    );
  });

  test('"resource:*" grants all actions on that resource', () => {
    const ctx = new AuthContext({
      user: { id: "user-1" },
      permissions: [new Permission("user", "*")],
    });
    expect(ctx.hasPermission(new Permission("user", "read"))).toBe(true);
    expect(ctx.hasPermission(new Permission("user", "write"))).toBe(true);
    expect(ctx.hasPermission(new Permission("user", "delete"))).toBe(true);
  });

  test('"resource:*" does NOT grant actions on a different resource', () => {
    const ctx = new AuthContext({
      user: { id: "user-1" },
      permissions: [new Permission("user", "*")],
    });
    expect(ctx.hasPermission(new Permission("admin", "read"))).toBe(false);
    expect(ctx.hasPermission(new Permission("billing", "write"))).toBe(false);
  });

  test('having "user:read" does NOT satisfy a wildcard pattern check (direction matters)', () => {
    // The user has a specific permission. We check if a wildcard requirement
    // is satisfied — it should NOT be, because matching direction matters.
    // matchPermission(pattern, target): pattern=user's perm, target=required
    // "user:read" (pattern) against "*" (target) — resource "user" !== "*"
    const ctx = new AuthContext({
      user: { id: "user-1" },
      permissions: [new Permission("user", "read")],
    });
    // hasPermission checks if ANY user permission (pattern) matches the target
    // Permission("*") means resource="*", action="*"
    // matchPermission(Permission("user","read"), Permission("*","*"))
    //   → pattern.resource="user", target resource="*" → pattern.resource !== "*" so no global wildcard
    //   → pattern.resource="user" !== target.resource="*" → false
    expect(ctx.hasPermission(new Permission("*"))).toBe(false);
  });

  test("empty permissions = no permission passes", () => {
    const ctx = new AuthContext({
      user: { id: "user-1" },
      permissions: [],
    });
    expect(ctx.hasPermission(new Permission("user", "read"))).toBe(false);
    expect(ctx.hasPermission(new Permission("*"))).toBe(false);
  });

  test("empty roles = no role passes", () => {
    const ctx = new AuthContext({
      user: { id: "user-1" },
      roles: [],
    });
    expect(ctx.hasRole(new Role("admin"))).toBe(false);
    expect(ctx.hasRole("viewer")).toBe(false);
  });

  test("satisfies with AllOf requires ALL requirements", () => {
    const readPerm = new Permission("user", "read");
    const writePerm = new Permission("user", "write");

    const ctx = new AuthContext({
      user: { id: "user-1" },
      permissions: [readPerm],
    });

    // Has read but not write — AllOf should fail
    const requirement = new AllOf([readPerm, writePerm]);
    expect(ctx.satisfies(requirement)).toBe(false);

    // Give both permissions
    const ctx2 = new AuthContext({
      user: { id: "user-1" },
      permissions: [readPerm, writePerm],
    });
    expect(ctx2.satisfies(requirement)).toBe(true);
  });

  test("satisfies with AnyOf requires ANY requirement", () => {
    const readPerm = new Permission("user", "read");
    const writePerm = new Permission("user", "write");

    const ctx = new AuthContext({
      user: { id: "user-1" },
      permissions: [readPerm],
    });

    // Has read — AnyOf should pass since read is present
    const requirement = new AnyOf([readPerm, writePerm]);
    expect(ctx.satisfies(requirement)).toBe(true);
  });

  test("empty AllOf evaluates to true (vacuous truth)", () => {
    const ctx = new AuthContext({ user: { id: "user-1" } });
    const requirement = new AllOf([]);
    expect(ctx.satisfies(requirement)).toBe(true);
  });

  test("empty AnyOf evaluates to false (no options)", () => {
    const ctx = new AuthContext({ user: { id: "user-1" } });
    const requirement = new AnyOf([]);
    expect(ctx.satisfies(requirement)).toBe(false);
  });

  test("matchPermission across separators: 'user:read' matches 'user.read'", () => {
    const { matchPermission } = require("../../src/authz/primitives");
    expect(matchPermission("user:read", "user.read")).toBe(true);
    expect(matchPermission("user.read", "user:read")).toBe(true);
  });

  test("matchPermission: different resource same action does not match", () => {
    const { matchPermission } = require("../../src/authz/primitives");
    expect(matchPermission("user:read", "admin:read")).toBe(false);
    expect(matchPermission("billing.write", "user.write")).toBe(false);
  });

  test("relation check: context with relation tuple finds it", () => {
    const ownerRelation = new Relation("doc", "owner");
    const tuple = ownerRelation.tuple("readme-123", "user:alice");

    const ctx = new AuthContext({
      user: { id: "alice" },
      relations: [tuple],
    });

    expect(ctx.hasRelation(ownerRelation, "readme-123")).toBe(true);
  });

  test("relation check: different relation type on same resource does not match", () => {
    const ownerRelation = new Relation("doc", "owner");
    const editorRelation = new Relation("doc", "editor");
    const tuple = ownerRelation.tuple("readme-123", "user:alice");

    const ctx = new AuthContext({
      user: { id: "alice" },
      relations: [tuple],
    });

    // Has owner but not editor
    expect(ctx.hasRelation(ownerRelation, "readme-123")).toBe(true);
    expect(ctx.hasRelation(editorRelation, "readme-123")).toBe(false);
  });

  test("relation check: empty relations means no relations pass", () => {
    const ctx = new AuthContext({
      user: { id: "alice" },
      relations: [],
    });

    const ownerRelation = new Relation("doc", "owner");
    expect(ctx.hasRelation(ownerRelation, "readme-123")).toBe(false);
  });

  test("hasAnyRole with multiple roles", () => {
    const ctx = new AuthContext({
      user: { id: "user-1" },
      roles: [new Role("editor"), new Role("viewer")],
    });

    expect(ctx.hasAnyRole("editor", "admin")).toBe(true);
    expect(ctx.hasAnyRole("admin", "superuser")).toBe(false);
    expect(ctx.hasAnyRole("viewer")).toBe(true);
    expect(ctx.hasAnyRole("editor", "viewer")).toBe(true);
  });

  test("role check with Role object (not just string)", () => {
    const adminRole = new Role("admin");
    const editorRole = new Role("editor");

    const ctx = new AuthContext({
      user: { id: "user-1" },
      roles: [adminRole],
    });

    expect(ctx.hasRole(adminRole)).toBe(true);
    expect(ctx.hasRole(editorRole)).toBe(false);
    expect(ctx.hasAnyRole(adminRole, editorRole)).toBe(true);
  });
});
