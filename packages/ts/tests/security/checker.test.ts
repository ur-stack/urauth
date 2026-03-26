import { describe, test, expect } from "bun:test";
import { AuthContext } from "../../src/context";
import {
  StringChecker,
  RoleExpandingChecker,
} from "../../src/authz/checker";
import { Permission, Role } from "../../src/authz/primitives";

describe("StringChecker Security", () => {
  test('user with "user:read" can check "user:read" -> true', async () => {
    const checker = new StringChecker();
    const ctx = new AuthContext({
      user: { id: "user-1" },
      permissions: [new Permission("user", "read")],
    });
    expect(await checker.hasPermission(ctx, "user", "read")).toBe(true);
  });

  test('user with "user:read" cannot check "user:write" -> false', async () => {
    const checker = new StringChecker();
    const ctx = new AuthContext({
      user: { id: "user-1" },
      permissions: [new Permission("user", "read")],
    });
    expect(await checker.hasPermission(ctx, "user", "write")).toBe(false);
  });

  test('wildcard "*" grants everything', async () => {
    const checker = new StringChecker();
    const ctx = new AuthContext({
      user: { id: "user-1" },
      permissions: [new Permission("*")],
    });
    expect(await checker.hasPermission(ctx, "user", "read")).toBe(true);
    expect(await checker.hasPermission(ctx, "admin", "delete")).toBe(true);
    expect(await checker.hasPermission(ctx, "billing", "write")).toBe(true);
  });

  test('"user:*" grants all user actions', async () => {
    const checker = new StringChecker();
    const ctx = new AuthContext({
      user: { id: "user-1" },
      permissions: [new Permission("user", "*")],
    });
    expect(await checker.hasPermission(ctx, "user", "read")).toBe(true);
    expect(await checker.hasPermission(ctx, "user", "write")).toBe(true);
    expect(await checker.hasPermission(ctx, "user", "delete")).toBe(true);
    // But not other resources
    expect(await checker.hasPermission(ctx, "admin", "read")).toBe(false);
  });

  test("no permissions = always false", async () => {
    const checker = new StringChecker();
    const ctx = new AuthContext({
      user: { id: "user-1" },
      permissions: [],
    });
    expect(await checker.hasPermission(ctx, "user", "read")).toBe(false);
    expect(await checker.hasPermission(ctx, "anything", "anything")).toBe(
      false,
    );
  });

  test("scoped permissions: falls back to context permissions when scope not found", async () => {
    const checker = new StringChecker();
    const ctx = new AuthContext({
      user: { id: "user-1" },
      permissions: [new Permission("user", "read")],
      scopes: new Map([
        ["tenant-a", [new Permission("billing", "read")]],
      ]),
    });

    // With a scope that exists, use scoped permissions
    expect(
      await checker.hasPermission(ctx, "billing", "read", {
        scope: "tenant-a",
      }),
    ).toBe(true);
    expect(
      await checker.hasPermission(ctx, "user", "read", {
        scope: "tenant-a",
      }),
    ).toBe(false);

    // With a scope that doesn't exist, falls back to context permissions
    expect(
      await checker.hasPermission(ctx, "user", "read", {
        scope: "nonexistent",
      }),
    ).toBe(true);
    expect(
      await checker.hasPermission(ctx, "billing", "read", {
        scope: "nonexistent",
      }),
    ).toBe(false);
  });
});

describe("RoleExpandingChecker Security", () => {
  test("role hierarchy expansion works", async () => {
    const rolePerms = new Map<string, Set<string>>([
      ["admin", new Set(["admin:manage"])],
      ["editor", new Set(["doc:edit"])],
      ["viewer", new Set(["doc:read"])],
    ]);
    const hierarchy = new Map<string, string[]>([
      ["admin", ["editor"]],
      ["editor", ["viewer"]],
    ]);

    const checker = new RoleExpandingChecker({
      rolePermissions: rolePerms,
      hierarchy,
    });

    // Admin should inherit editor and viewer permissions
    const ctx = new AuthContext({
      user: { id: "user-1" },
      roles: [new Role("admin")],
    });

    expect(await checker.hasPermission(ctx, "admin", "manage")).toBe(true);
    expect(await checker.hasPermission(ctx, "doc", "edit")).toBe(true);
    expect(await checker.hasPermission(ctx, "doc", "read")).toBe(true);
  });

  test("circular hierarchy does not crash", async () => {
    const rolePerms = new Map<string, Set<string>>([
      ["admin", new Set(["admin:manage"])],
      ["editor", new Set(["doc:edit"])],
    ]);
    const hierarchy = new Map<string, string[]>([
      ["admin", ["editor"]],
      ["editor", ["admin"]],
    ]);

    // Should not throw or infinite-loop
    const checker = new RoleExpandingChecker({
      rolePermissions: rolePerms,
      hierarchy,
    });

    const ctx = new AuthContext({
      user: { id: "user-1" },
      roles: [new Role("admin")],
    });

    // Should still resolve permissions from both roles
    expect(await checker.hasPermission(ctx, "admin", "manage")).toBe(true);
    expect(await checker.hasPermission(ctx, "doc", "edit")).toBe(true);
  });

  test("unknown role is still included (does not fail)", async () => {
    const rolePerms = new Map<string, Set<string>>([
      ["admin", new Set(["admin:manage"])],
    ]);

    const checker = new RoleExpandingChecker({
      rolePermissions: rolePerms,
    });

    // User has a role not in rolePermissions map
    const ctx = new AuthContext({
      user: { id: "user-1" },
      roles: [new Role("mysterious-role")],
    });

    // Should not throw; just returns false for permissions
    expect(
      await checker.hasPermission(ctx, "admin", "manage"),
    ).toBe(false);

    // effectiveRoles should still include the unknown role
    const effective = checker.effectiveRoles(["mysterious-role"]);
    expect(effective.has("mysterious-role")).toBe(true);
  });
});
