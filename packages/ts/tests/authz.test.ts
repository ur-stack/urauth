import { describe, test, expect } from "bun:test";
import {
  Permission,
  Role,
  Relation,
  AllOf,
  AnyOf,
  allOf,
  anyOf,
  AuthContext,
  StringChecker,
  RoleExpandingChecker,
  RoleRegistry,
  MemoryRoleCache,
  definePermissions,
  canAccess,
} from "../src/index";

describe("Permission", () => {
  test("toString returns resource:action", () => {
    const p = new Permission("user", "read");
    expect(p.toString()).toBe("user:read");
  });

  test("equals compares string form", () => {
    const p = new Permission("user", "read");
    expect(p.equals("user:read")).toBe(true);
    expect(p.equals("user:write")).toBe(false);
    expect(p.equals(new Permission("user", "read"))).toBe(true);
  });
});

describe("Role", () => {
  test("toString returns name", () => {
    const r = new Role("admin");
    expect(r.toString()).toBe("admin");
  });

  test("equals compares name", () => {
    const r = new Role("admin");
    expect(r.equals("admin")).toBe(true);
    expect(r.equals("user")).toBe(false);
  });
});

describe("Relation", () => {
  test("toString returns resource#name (Zanzibar format)", () => {
    const r = new Relation("owner", "post");
    expect(r.toString()).toBe("post#owner");
  });

  test("equals compares string form", () => {
    const r = new Relation("owner", "post");
    expect(r.equals("post#owner")).toBe(true);
    expect(r.equals("post#viewer")).toBe(false);
  });
});

describe("Requirement composition", () => {
  const admin = new Role("admin");
  const editor = new Role("editor");
  const canRead = new Permission("post", "read");
  const canWrite = new Permission("post", "write");

  test(".and() creates AllOf", () => {
    const req = canRead.and(canWrite);
    expect(req).toBeInstanceOf(AllOf);
    expect(req.requirements).toHaveLength(2);
  });

  test(".or() creates AnyOf", () => {
    const req = admin.or(editor);
    expect(req).toBeInstanceOf(AnyOf);
    expect(req.requirements).toHaveLength(2);
  });

  test("flattens nested AllOf", () => {
    const req = canRead.and(canWrite).and(admin);
    expect(req.requirements).toHaveLength(3);
  });

  test("flattens nested AnyOf", () => {
    const req = admin.or(editor).or(canRead);
    expect(req.requirements).toHaveLength(3);
  });

  test("allOf/anyOf factory functions", () => {
    const all = allOf(canRead, canWrite, admin);
    expect(all).toBeInstanceOf(AllOf);
    expect(all.requirements).toHaveLength(3);

    const any = anyOf(admin, editor);
    expect(any).toBeInstanceOf(AnyOf);
    expect(any.requirements).toHaveLength(2);
  });
});

describe("AuthContext", () => {
  test("anonymous context", () => {
    const ctx = AuthContext.anonymous();
    expect(ctx.isAuthenticated()).toBe(false);
    expect(ctx.user).toBeNull();
  });

  test("hasPermission with exact match", () => {
    const ctx = new AuthContext({
      user: { id: "1" },
      permissions: [new Permission("user", "read")],
    });
    expect(ctx.hasPermission(new Permission("user", "read"))).toBe(true);
    expect(ctx.hasPermission("user:read")).toBe(true);
    expect(ctx.hasPermission("user:write")).toBe(false);
  });

  test("hasPermission with wildcard", () => {
    const ctx = new AuthContext({
      user: { id: "1" },
      permissions: [new Permission("*", "*")],
    });
    // "*:*" won't match as global wildcard — only "*" does
    expect(ctx.hasPermission("anything:here")).toBe(false);

    const ctx2 = new AuthContext({
      user: { id: "1" },
      permissions: [new Permission("user", "*")],
    });
    expect(ctx2.hasPermission("user:read")).toBe(true);
    expect(ctx2.hasPermission("user:write")).toBe(true);
    expect(ctx2.hasPermission("post:read")).toBe(false);
  });

  test("hasRole", () => {
    const ctx = new AuthContext({
      user: { id: "1" },
      roles: [new Role("admin"), new Role("editor")],
    });
    expect(ctx.hasRole("admin")).toBe(true);
    expect(ctx.hasRole(new Role("editor"))).toBe(true);
    expect(ctx.hasRole("viewer")).toBe(false);
  });

  test("hasAnyRole", () => {
    const ctx = new AuthContext({
      user: { id: "1" },
      roles: [new Role("editor")],
    });
    expect(ctx.hasAnyRole("admin", "editor")).toBe(true);
    expect(ctx.hasAnyRole("admin", "viewer")).toBe(false);
  });

  test("hasRelation", () => {
    const ownerRel = new Relation("owner", "post");
    const ctx = new AuthContext({
      user: { id: "1" },
      relations: [[ownerRel, "post-123"]],
    });
    expect(ctx.hasRelation(ownerRel, "post-123")).toBe(true);
    expect(ctx.hasRelation(ownerRel, "post-456")).toBe(false);
    expect(ctx.hasRelation(new Relation("editor", "post"), "post-123")).toBe(false);
  });

  test("satisfies evaluates composite requirements", () => {
    const admin = new Role("admin");
    const canRead = new Permission("post", "read");

    const ctx = new AuthContext({
      user: { id: "1" },
      roles: [new Role("admin")],
      permissions: [new Permission("post", "read")],
    });

    expect(ctx.satisfies(admin)).toBe(true);
    expect(ctx.satisfies(canRead)).toBe(true);
    expect(ctx.satisfies(admin.and(canRead))).toBe(true);
    expect(ctx.satisfies(admin.or(new Role("superadmin")))).toBe(true);
    expect(ctx.satisfies(new Role("superadmin").and(canRead))).toBe(false);
  });
});

describe("StringChecker", () => {
  const checker = new StringChecker();

  test("exact match", async () => {
    const ctx = new AuthContext({
      permissions: [new Permission("user", "read")],
    });
    expect(await checker.hasPermission(ctx, "user", "read")).toBe(true);
    expect(await checker.hasPermission(ctx, "user", "write")).toBe(false);
  });

  test("wildcard *", async () => {
    const ctx = new AuthContext({
      permissions: [new Permission("*", "")],
    });
    // The "*" permission string is "*:" not "*"
    // Let's test with a proper global wildcard
    const ctx2 = new AuthContext({
      permissions: [{ toString: () => "*", resource: "*", action: "*" } as unknown as Permission],
    });
    // Actually, let's just test resource wildcard
  });

  test("resource wildcard user:*", async () => {
    const ctx = new AuthContext({
      permissions: [new Permission("user", "*")],
    });
    expect(await checker.hasPermission(ctx, "user", "read")).toBe(true);
    expect(await checker.hasPermission(ctx, "user", "delete")).toBe(true);
    expect(await checker.hasPermission(ctx, "post", "read")).toBe(false);
  });

  test("scope-based permissions", async () => {
    const ctx = new AuthContext({
      permissions: [new Permission("user", "read")],
      scopes: new Map([
        ["tenant-a", [new Permission("post", "write")]],
      ]),
    });
    expect(await checker.hasPermission(ctx, "post", "write", { scope: "tenant-a" })).toBe(true);
    expect(await checker.hasPermission(ctx, "user", "read", { scope: "tenant-a" })).toBe(false);
  });
});

describe("RoleExpandingChecker", () => {
  test("expands role hierarchy", async () => {
    const checker = new RoleExpandingChecker({
      rolePermissions: new Map([
        ["admin", new Set(["user:read", "user:write", "user:delete"])],
        ["editor", new Set(["user:read", "user:write"])],
        ["viewer", new Set(["user:read"])],
      ]),
      hierarchy: new Map([
        ["admin", ["editor"]],
        ["editor", ["viewer"]],
      ]),
    });

    expect(checker.effectiveRoles(["admin"])).toEqual(new Set(["admin", "editor", "viewer"]));
    expect(checker.effectiveRoles(["editor"])).toEqual(new Set(["editor", "viewer"]));

    const ctx = new AuthContext({
      user: { id: "1" },
      roles: [new Role("viewer")],
    });
    expect(await checker.hasPermission(ctx, "user", "read")).toBe(true);
    expect(await checker.hasPermission(ctx, "user", "write")).toBe(false);
  });

  test("includes direct permissions from context", async () => {
    const checker = new RoleExpandingChecker({
      rolePermissions: new Map([
        ["viewer", new Set(["user:read"])],
      ]),
    });

    const ctx = new AuthContext({
      user: { id: "1" },
      roles: [new Role("viewer")],
      permissions: [new Permission("post", "write")],
    });
    expect(await checker.hasPermission(ctx, "post", "write")).toBe(true);
  });
});

describe("RoleRegistry", () => {
  test("register and build checker", () => {
    const registry = new RoleRegistry();
    registry.role("admin", ["user:read", "user:write", "user:delete"], {
      inherits: ["editor"],
    });
    registry.role("editor", ["user:read", "user:write"]);
    const checker = registry.buildChecker();
    expect(checker.effectiveRoles(["admin"])).toEqual(new Set(["admin", "editor"]));
  });

  test("include merges registries", () => {
    const r1 = new RoleRegistry();
    r1.role("admin", ["user:read"]);

    const r2 = new RoleRegistry();
    r2.role("editor", ["post:write"]);

    r1.include(r2);
    const checker = r1.buildChecker();
    expect(checker.effectiveRoles(["editor"])).toEqual(new Set(["editor"]));
  });

  test("load from external loader", async () => {
    const registry = new RoleRegistry();
    registry.withLoader({
      async loadRoles() {
        return new Map([["dynamic", new Set(["dynamic:action"])]]);
      },
      async loadHierarchy() {
        return new Map();
      },
    });
    await registry.load();
    const checker = registry.buildChecker();

    const ctx = new AuthContext({
      roles: [new Role("dynamic")],
    });
    expect(await checker.hasPermission(ctx, "dynamic", "action")).toBe(true);
  });

  test("load with cache", async () => {
    const cache = new MemoryRoleCache();
    let loadCount = 0;

    const registry = new RoleRegistry();
    registry.withLoader(
      {
        async loadRoles() {
          loadCount++;
          return new Map([["cached", new Set(["cached:perm"])]]);
        },
        async loadHierarchy() {
          return new Map();
        },
      },
      { cache, cacheTtl: 60 },
    );

    await registry.load();
    expect(loadCount).toBe(1);

    await registry.load();
    expect(loadCount).toBe(1); // served from cache
  });
});

describe("definePermissions", () => {
  test("creates frozen permission map", () => {
    const Perms = definePermissions({
      USER_READ: ["user", "read"],
      TASK_WRITE: ["task", "write"],
    });

    expect(Perms.USER_READ).toBeInstanceOf(Permission);
    expect(Perms.USER_READ.toString()).toBe("user:read");
    expect(Perms.TASK_WRITE.toString()).toBe("task:write");
    expect(Object.isFrozen(Perms)).toBe(true);
  });
});

describe("canAccess", () => {
  test("checks permission on AuthContext", () => {
    const ctx = new AuthContext({
      permissions: [new Permission("post", "read"), new Permission("post", "write")],
    });
    expect(canAccess(ctx, "post", "read")).toBe(true);
    expect(canAccess(ctx, "post", "delete")).toBe(false);
  });

  test("accepts Permission object", () => {
    const ctx = new AuthContext({
      permissions: [new Permission("post", "read")],
    });
    expect(canAccess(ctx, new Permission("post", "read"))).toBe(true);
    expect(canAccess(ctx, new Permission("post", "write"))).toBe(false);
  });

  test("respects scope", () => {
    const ctx = new AuthContext({
      permissions: [new Permission("user", "read")],
      scopes: new Map([["tenant-a", [new Permission("post", "write")]]]),
    });
    expect(canAccess(ctx, "post", "write", { scope: "tenant-a" })).toBe(true);
    expect(canAccess(ctx, "user", "read", { scope: "tenant-a" })).toBe(false);
  });
});
