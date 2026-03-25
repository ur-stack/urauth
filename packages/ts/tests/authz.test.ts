import { describe, test, expect } from "bun:test";
import {
  Permission,
  Role,
  Relation,
  RelationTuple,
  matchPermission,
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
  defineRelations,
  canAccess,
} from "../src/index";

describe("Permission", () => {
  test("two-arg constructor", () => {
    const p = new Permission("user", "read");
    expect(p.toString()).toBe("user:read");
    expect(p.resource).toBe("user");
    expect(p.action).toBe("read");
  });

  test("single-string constructor with colon", () => {
    const p = new Permission("user:read");
    expect(p.resource).toBe("user");
    expect(p.action).toBe("read");
  });

  test("single-string constructor with dot", () => {
    const p = new Permission("user.read");
    expect(p.resource).toBe("user");
    expect(p.action).toBe("read");
    expect(p.toString()).toBe("user.read");
  });

  test("single-string constructor with other separators", () => {
    expect(new Permission("user|read").resource).toBe("user");
    expect(new Permission("user|read").action).toBe("read");
    expect(new Permission("user#read").resource).toBe("user");
  });

  test("global wildcard *", () => {
    const p = new Permission("*");
    expect(p.resource).toBe("*");
    expect(p.action).toBe("*");
  });

  test("throws on invalid string (no separator)", () => {
    expect(() => new Permission("invalid")).toThrow("No separator found");
  });

  test("semantic equality across separators", () => {
    const p1 = new Permission("user:read");
    const p2 = new Permission("user.read");
    expect(p1.equals(p2)).toBe(true);
    expect(p1.equals("user.read")).toBe(true);
    expect(p1.equals("user:read")).toBe(true);
  });

  test("equals returns false for different permissions", () => {
    const p = new Permission("user", "read");
    expect(p.equals("user:write")).toBe(false);
    expect(p.equals(new Permission("user", "write"))).toBe(false);
  });

  test("custom parser", () => {
    const p = new Permission("urn:service:task:read", undefined, {
      parser: (s) => {
        const parts = s.split(":");
        return [parts[parts.length - 2]!, parts[parts.length - 1]!];
      },
    });
    expect(p.resource).toBe("task");
    expect(p.action).toBe("read");
  });
});

describe("matchPermission", () => {
  test("exact match", () => {
    expect(matchPermission("user:read", "user:read")).toBe(true);
    expect(matchPermission("user:read", "user:write")).toBe(false);
  });

  test("cross-separator match", () => {
    expect(matchPermission("user:read", "user.read")).toBe(true);
    expect(matchPermission("user.read", "user:read")).toBe(true);
  });

  test("global wildcard", () => {
    expect(matchPermission("*", "user:read")).toBe(true);
    expect(matchPermission("*", "anything.here")).toBe(true);
  });

  test("resource wildcard", () => {
    expect(matchPermission("user:*", "user:read")).toBe(true);
    expect(matchPermission("user:*", "user.write")).toBe(true);
    expect(matchPermission("user:*", "post:read")).toBe(false);
  });

  test("Permission objects", () => {
    const pattern = new Permission("user", "*");
    const target = new Permission("user", "read");
    expect(matchPermission(pattern, target)).toBe(true);
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
  test("two-arg constructor (resource, name)", () => {
    const r = new Relation("post", "owner");
    expect(r.resource).toBe("post");
    expect(r.name).toBe("owner");
    expect(r.toString()).toBe("post#owner");
  });

  test("single-string constructor", () => {
    const r = new Relation("post#owner");
    expect(r.resource).toBe("post");
    expect(r.name).toBe("owner");
    expect(r.toString()).toBe("post#owner");
  });

  test("single-string with dot separator", () => {
    const r = new Relation("post.owner");
    expect(r.resource).toBe("post");
    expect(r.name).toBe("owner");
  });

  test("semantic equality across separators", () => {
    const r1 = new Relation("post#owner");
    const r2 = new Relation("post.owner");
    expect(r1.equals(r2)).toBe(true);
    expect(r1.equals("post.owner")).toBe(true);
  });

  test("equals returns false for different relations", () => {
    const r = new Relation("post", "owner");
    expect(r.equals("post#viewer")).toBe(false);
  });

  test("tuple() creates RelationTuple", () => {
    const r = new Relation("doc", "owner");
    const t = r.tuple("readme", "user:alice");
    expect(t).toBeInstanceOf(RelationTuple);
    expect(t.objectId).toBe("readme");
    expect(t.subject).toBe("user:alice");
    expect(t.relation.equals(r)).toBe(true);
  });
});

describe("RelationTuple", () => {
  test("construction", () => {
    const rel = new Relation("doc", "owner");
    const t = new RelationTuple(rel, "readme", "user:alice");
    expect(t.relation).toBe(rel);
    expect(t.objectId).toBe("readme");
    expect(t.subject).toBe("user:alice");
  });

  test("toString", () => {
    const rel = new Relation("doc", "owner");
    const t = new RelationTuple(rel, "readme", "user:alice");
    expect(t.toString()).toBe("doc:readme#owner@user:alice");
  });

  test("toString without subject", () => {
    const rel = new Relation("doc", "owner");
    const t = new RelationTuple(rel, "readme");
    expect(t.toString()).toBe("doc:readme#owner");
  });

  test("parse with subject", () => {
    const t = RelationTuple.parse("doc:readme#owner@user:alice");
    expect(t.relation.resource).toBe("doc");
    expect(t.relation.name).toBe("owner");
    expect(t.objectId).toBe("readme");
    expect(t.subject).toBe("user:alice");
  });

  test("parse without subject", () => {
    const t = RelationTuple.parse("doc:readme#owner");
    expect(t.relation.resource).toBe("doc");
    expect(t.relation.name).toBe("owner");
    expect(t.objectId).toBe("readme");
    expect(t.subject).toBeUndefined();
  });

  test("equals", () => {
    const t1 = RelationTuple.parse("doc:readme#owner@user:alice");
    const t2 = new RelationTuple(new Relation("doc", "owner"), "readme", "user:alice");
    expect(t1.equals(t2)).toBe(true);
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

  test("hasPermission cross-separator", () => {
    const ctx = new AuthContext({
      user: { id: "1" },
      permissions: [new Permission("user.read")],
    });
    expect(ctx.hasPermission("user:read")).toBe(true);
    expect(ctx.hasPermission("user.read")).toBe(true);
  });

  test("hasPermission with global wildcard", () => {
    const ctx = new AuthContext({
      user: { id: "1" },
      permissions: [new Permission("*")],
    });
    expect(ctx.hasPermission("anything:here")).toBe(true);
  });

  test("hasPermission with resource wildcard", () => {
    const ctx = new AuthContext({
      user: { id: "1" },
      permissions: [new Permission("user", "*")],
    });
    expect(ctx.hasPermission("user:read")).toBe(true);
    expect(ctx.hasPermission("user:write")).toBe(true);
    expect(ctx.hasPermission("post:read")).toBe(false);
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
    const ownerRel = new Relation("post", "owner");
    const ctx = new AuthContext({
      user: { id: "1" },
      relations: [ownerRel.tuple("post-123")],
    });
    expect(ctx.hasRelation(ownerRel, "post-123")).toBe(true);
    expect(ctx.hasRelation(ownerRel, "post-456")).toBe(false);
    expect(ctx.hasRelation(new Relation("post", "editor"), "post-123")).toBe(false);
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

  test("global wildcard", async () => {
    const ctx = new AuthContext({
      permissions: [new Permission("*")],
    });
    expect(await checker.hasPermission(ctx, "user", "read")).toBe(true);
    expect(await checker.hasPermission(ctx, "post", "delete")).toBe(true);
  });

  test("resource wildcard user:*", async () => {
    const ctx = new AuthContext({
      permissions: [new Permission("user", "*")],
    });
    expect(await checker.hasPermission(ctx, "user", "read")).toBe(true);
    expect(await checker.hasPermission(ctx, "user", "delete")).toBe(true);
    expect(await checker.hasPermission(ctx, "post", "read")).toBe(false);
  });

  test("cross-separator matching", async () => {
    const ctx = new AuthContext({
      permissions: [new Permission("user.read")],
    });
    expect(await checker.hasPermission(ctx, "user", "read")).toBe(true);
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
  test("creates frozen permission map from tuples", () => {
    const Perms = definePermissions({
      USER_READ: ["user", "read"],
      TASK_WRITE: ["task", "write"],
    });

    expect(Perms.USER_READ).toBeInstanceOf(Permission);
    expect(Perms.USER_READ.toString()).toBe("user:read");
    expect(Perms.TASK_WRITE.toString()).toBe("task:write");
    expect(Object.isFrozen(Perms)).toBe(true);
  });

  test("creates from strings", () => {
    const Perms = definePermissions({
      USER_READ: "user:read",
      TASK_WRITE: "task.write",
    });
    expect(Perms.USER_READ.resource).toBe("user");
    expect(Perms.TASK_WRITE.resource).toBe("task");
    expect(Perms.TASK_WRITE.action).toBe("write");
  });

  test("accepts Permission objects", () => {
    const Perms = definePermissions({
      ADMIN: new Permission("admin", "*"),
    });
    expect(Perms.ADMIN.action).toBe("*");
  });

  test("custom parser", () => {
    const Perms = definePermissions(
      { TASK_READ: "urn:service:task:read" },
      {
        parser: (s) => {
          const parts = s.split(":");
          return [parts[parts.length - 2]!, parts[parts.length - 1]!];
        },
      },
    );
    expect(Perms.TASK_READ.resource).toBe("task");
    expect(Perms.TASK_READ.action).toBe("read");
  });
});

describe("defineRelations", () => {
  test("creates from strings", () => {
    const Rels = defineRelations({
      DOC_OWNER: "doc#owner",
      DOC_VIEWER: "doc.viewer",
    });
    expect(Rels.DOC_OWNER).toBeInstanceOf(Relation);
    expect(Rels.DOC_OWNER.resource).toBe("doc");
    expect(Rels.DOC_OWNER.name).toBe("owner");
    expect(Object.isFrozen(Rels)).toBe(true);
  });

  test("creates from tuples", () => {
    const Rels = defineRelations({
      DOC_OWNER: ["doc", "owner"],
    });
    expect(Rels.DOC_OWNER.resource).toBe("doc");
    expect(Rels.DOC_OWNER.name).toBe("owner");
  });

  test("accepts Relation objects", () => {
    const Rels = defineRelations({
      DOC_OWNER: new Relation("doc", "owner"),
    });
    expect(Rels.DOC_OWNER.resource).toBe("doc");
  });

  test("tuple() delegation", () => {
    const Rels = defineRelations({ DOC_OWNER: "doc#owner" });
    const t = Rels.DOC_OWNER.tuple("readme", "user:alice");
    expect(t).toBeInstanceOf(RelationTuple);
    expect(t.toString()).toBe("doc:readme#owner@user:alice");
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
